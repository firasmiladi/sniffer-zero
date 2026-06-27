"""WiFi 802.11 frame dissector engine.

Full dissection of all 802.11 frame types/subtypes (management, control, data),
extraction of Information Elements from beacons/probe responses including RSN/WPA
IEs, HT/VHT/HE capabilities, supported rates, and vendor-specific elements.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import structlog
from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeResp,
    RadioTap,
    rdpcap,
    sniff,
)

from srt.core.module import AttackModule, AttackResult, ModuleContext, Risk, Status
from srt.core.registry import register

log = structlog.get_logger(__name__)

# 802.11 frame type/subtype mappings
FRAME_TYPES: dict[int, str] = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}

MGMT_SUBTYPES: dict[int, str] = {
    0: "AssocReq", 1: "AssocResp", 2: "ReassocReq", 3: "ReassocResp",
    4: "ProbeReq", 5: "ProbeResp", 6: "TimingAdv", 7: "Reserved",
    8: "Beacon", 9: "ATIM", 10: "Disassoc", 11: "Auth",
    12: "Deauth", 13: "Action", 14: "ActionNoAck", 15: "Reserved",
}

CTRL_SUBTYPES: dict[int, str] = {
    7: "CtrlWrapper", 8: "BAR", 9: "BA", 10: "PSPoll",
    11: "RTS", 12: "CTS", 13: "ACK", 14: "CFEnd", 15: "CFEndCFAck",
}

DATA_SUBTYPES: dict[int, str] = {
    0: "Data", 1: "DataCFAck", 2: "DataCFPoll", 3: "DataCFAckCFPoll",
    4: "Null", 5: "CFAck", 6: "CFPoll", 7: "CFAckCFPoll",
    8: "QoSData", 9: "QoSDataCFAck", 10: "QoSDataCFPoll",
    11: "QoSDataCFAckCFPoll", 12: "QoSNull", 13: "Reserved",
    14: "QoSCFPoll", 15: "QoSCFAckCFPoll",
}

# RSN cipher suite OUIs
CIPHER_SUITES: dict[bytes, str] = {
    b"\x00\x0f\xac\x00": "Use-Group",
    b"\x00\x0f\xac\x01": "WEP-40",
    b"\x00\x0f\xac\x02": "TKIP",
    b"\x00\x0f\xac\x04": "CCMP-128",
    b"\x00\x0f\xac\x05": "WEP-104",
    b"\x00\x0f\xac\x06": "BIP-CMAC-128",
    b"\x00\x0f\xac\x08": "GCMP-128",
    b"\x00\x0f\xac\x09": "GCMP-256",
    b"\x00\x0f\xac\x0a": "CCMP-256",
}

AKM_SUITES: dict[bytes, str] = {
    b"\x00\x0f\xac\x01": "802.1X",
    b"\x00\x0f\xac\x02": "PSK",
    b"\x00\x0f\xac\x03": "FT-802.1X",
    b"\x00\x0f\xac\x04": "FT-PSK",
    b"\x00\x0f\xac\x05": "802.1X-SHA256",
    b"\x00\x0f\xac\x06": "PSK-SHA256",
    b"\x00\x0f\xac\x08": "SAE",
    b"\x00\x0f\xac\x09": "FT-SAE",
    b"\x00\x0f\xac\x0c": "802.1X-Suite-B",
    b"\x00\x0f\xac\x0d": "802.1X-Suite-B-192",
    b"\x00\x0f\xac\x12": "OWE",
}


def _parse_rsn_ie(data: bytes) -> dict[str, Any]:
    """Parse RSN Information Element (ID 48)."""
    result: dict[str, Any] = {"raw_hex": data.hex()}
    if len(data) < 2:
        return result

    version = int.from_bytes(data[0:2], "little")
    result["version"] = version
    offset = 2

    # Group cipher suite
    if offset + 4 <= len(data):
        group_cipher = data[offset:offset + 4]
        result["group_cipher"] = CIPHER_SUITES.get(group_cipher, group_cipher.hex())
        offset += 4

    # Pairwise cipher suites
    if offset + 2 <= len(data):
        pw_count = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2
        pairwise: list[str] = []
        for _ in range(pw_count):
            if offset + 4 <= len(data):
                suite = data[offset:offset + 4]
                pairwise.append(CIPHER_SUITES.get(suite, suite.hex()))
                offset += 4
        result["pairwise_ciphers"] = pairwise

    # AKM suites
    if offset + 2 <= len(data):
        akm_count = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2
        akms: list[str] = []
        for _ in range(akm_count):
            if offset + 4 <= len(data):
                suite = data[offset:offset + 4]
                akms.append(AKM_SUITES.get(suite, suite.hex()))
                offset += 4
        result["akm_suites"] = akms

    # RSN Capabilities
    if offset + 2 <= len(data):
        cap = int.from_bytes(data[offset:offset + 2], "little")
        result["rsn_capabilities"] = cap
        result["pmf_capable"] = bool(cap & 0x0080)
        result["pmf_required"] = bool(cap & 0x0040)
        result["pre_auth"] = bool(cap & 0x0001)

    return result


def _parse_wpa_ie(data: bytes) -> dict[str, Any]:
    """Parse WPA vendor-specific IE (OUI 00:50:f2 type 1)."""
    result: dict[str, Any] = {"raw_hex": data.hex()}
    # Skip OUI + type (4 bytes already stripped by caller or present)
    offset = 4
    if offset + 2 > len(data):
        return result

    version = int.from_bytes(data[offset:offset + 2], "little")
    result["version"] = version
    offset += 2

    # Multicast cipher
    if offset + 4 <= len(data):
        result["multicast_cipher"] = data[offset:offset + 4].hex()
        offset += 4

    # Unicast ciphers
    if offset + 2 <= len(data):
        uc_count = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2
        unicast: list[str] = []
        for _ in range(uc_count):
            if offset + 4 <= len(data):
                unicast.append(data[offset:offset + 4].hex())
                offset += 4
        result["unicast_ciphers"] = unicast

    return result


def _parse_ht_capabilities(data: bytes) -> dict[str, Any]:
    """Parse HT Capabilities IE (ID 45) for 802.11n."""
    result: dict[str, Any] = {}
    if len(data) < 2:
        return result
    cap_info = int.from_bytes(data[0:2], "little")
    result["ldpc_coding"] = bool(cap_info & 0x0001)
    result["channel_width_40mhz"] = bool(cap_info & 0x0002)
    result["sm_power_save"] = (cap_info >> 2) & 0x03
    result["greenfield"] = bool(cap_info & 0x0010)
    result["short_gi_20mhz"] = bool(cap_info & 0x0020)
    result["short_gi_40mhz"] = bool(cap_info & 0x0040)
    result["tx_stbc"] = bool(cap_info & 0x0080)
    result["rx_stbc"] = (cap_info >> 8) & 0x03
    result["max_amsdu_len"] = 7935 if (cap_info & 0x0800) else 3839
    return result


def _parse_vht_capabilities(data: bytes) -> dict[str, Any]:
    """Parse VHT Capabilities IE (ID 191) for 802.11ac."""
    result: dict[str, Any] = {}
    if len(data) < 4:
        return result
    cap_info = int.from_bytes(data[0:4], "little")
    result["max_mpdu_length"] = [3895, 7991, 11454][(cap_info & 0x03)]
    result["supported_channel_width"] = (cap_info >> 2) & 0x03
    result["short_gi_80mhz"] = bool(cap_info & 0x0020)
    result["short_gi_160mhz"] = bool(cap_info & 0x0040)
    result["su_beamformer"] = bool(cap_info & 0x0800)
    result["su_beamformee"] = bool(cap_info & 0x1000)
    result["mu_beamformer"] = bool(cap_info & 0x080000)
    result["mu_beamformee"] = bool(cap_info & 0x100000)
    return result


def _extract_ies(pkt: Any) -> list[dict[str, Any]]:
    """Extract all Information Elements from a beacon/probe response."""
    ies: list[dict[str, Any]] = []
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        ie_id = elt.ID
        ie_data = bytes(elt.info) if elt.info else b""
        ie_entry: dict[str, Any] = {"id": ie_id, "len": len(ie_data)}

        if ie_id == 0:  # SSID
            try:
                ie_entry["ssid"] = ie_data.decode("utf-8", errors="replace")
            except Exception:
                ie_entry["ssid"] = ie_data.hex()
        elif ie_id == 1:  # Supported Rates
            ie_entry["rates_mbps"] = [(b & 0x7F) * 0.5 for b in ie_data]
            ie_entry["basic_rates"] = [((b & 0x7F) * 0.5) for b in ie_data if b & 0x80]
        elif ie_id == 3:  # DS Parameter Set (channel)
            ie_entry["channel"] = ie_data[0] if ie_data else None
        elif ie_id == 7:  # Country IE
            if len(ie_data) >= 3:
                ie_entry["country"] = ie_data[0:2].decode("ascii", errors="replace")
        elif ie_id == 32:  # Power Constraint
            ie_entry["power_constraint_db"] = ie_data[0] if ie_data else 0
        elif ie_id == 45:  # HT Capabilities
            ie_entry["ht_capabilities"] = _parse_ht_capabilities(ie_data)
        elif ie_id == 48:  # RSN (WPA2/WPA3)
            ie_entry["rsn"] = _parse_rsn_ie(ie_data)
        elif ie_id == 50:  # Extended Supported Rates
            ie_entry["ext_rates_mbps"] = [(b & 0x7F) * 0.5 for b in ie_data]
        elif ie_id == 191:  # VHT Capabilities
            ie_entry["vht_capabilities"] = _parse_vht_capabilities(ie_data)
        elif ie_id == 221:  # Vendor Specific
            if ie_data.startswith(b"\x00\x50\xf2\x01"):
                ie_entry["wpa"] = _parse_wpa_ie(ie_data)
                ie_entry["vendor"] = "WPA"
            elif ie_data.startswith(b"\x00\x50\xf2\x04"):
                ie_entry["vendor"] = "WPS"
                ie_entry["wps_detected"] = True
            elif ie_data.startswith(b"\x00\x17\xf2"):
                ie_entry["vendor"] = "Apple"
            elif ie_data.startswith(b"\x00\x50\xf2\x02"):
                ie_entry["vendor"] = "WMM"
            else:
                ie_entry["vendor"] = "Unknown"
                ie_entry["oui"] = ie_data[:3].hex() if len(ie_data) >= 3 else ""
        elif ie_id == 255:  # Extension element
            if ie_data and ie_data[0] == 35:
                ie_entry["he_capabilities"] = True
                ie_entry["wifi6"] = True

        ies.append(ie_entry)
        elt = elt.payload.getlayer(Dot11Elt)
    return ies


@register
class WiFiFrameDissector(AttackModule):
    """Full 802.11 frame dissection engine.

    Parses all frame types/subtypes, extracts Information Elements from
    beacons/probe responses, decodes RSN/WPA IEs for cipher suites and
    AKMs, HT/VHT/HE capabilities, supported rates, vendor-specific IEs.
    """

    name = "wifi.frame_dissector"
    protocol = "wifi"
    risk = Risk.PASSIVE
    mitre_ttp = ["T1040", "T1592.002"]
    requires = ["monitor-mode-nic"]
    description = (
        "Deep 802.11 frame dissection: parse all frame types, extract IEs, "
        "decode RSN/WPA/HT/VHT/HE capabilities from beacons and probe responses."
    )

    def __init__(self) -> None:
        self._frames: list[dict[str, Any]] = []
        self._ap_ies: dict[str, list[dict[str, Any]]] = {}

    def precheck(self, ctx: ModuleContext) -> bool:
        if not super().precheck(ctx):
            return False
        capture_file = ctx.params.get("capture_file")
        if capture_file and not Path(capture_file).exists():
            log.error("wifi.frame_dissector.file_not_found", path=capture_file)
            return False
        return True

    def _dissect_packet(self, pkt: Any) -> dict[str, Any] | None:
        """Dissect a single 802.11 frame."""
        if not pkt.haslayer(Dot11):
            return None

        dot11 = pkt.getlayer(Dot11)
        frame_type = dot11.type
        frame_subtype = dot11.subtype

        type_str = FRAME_TYPES.get(frame_type, "Unknown")
        if frame_type == 0:
            subtype_str = MGMT_SUBTYPES.get(frame_subtype, "Unknown")
        elif frame_type == 1:
            subtype_str = CTRL_SUBTYPES.get(frame_subtype, "Unknown")
        elif frame_type == 2:
            subtype_str = DATA_SUBTYPES.get(frame_subtype, "Unknown")
        else:
            subtype_str = "Unknown"

        frame_info: dict[str, Any] = {
            "type": frame_type,
            "type_str": type_str,
            "subtype": frame_subtype,
            "subtype_str": subtype_str,
            "addr1": dot11.addr1,
            "addr2": dot11.addr2,
            "addr3": dot11.addr3,
        }

        # RadioTap info
        if pkt.haslayer(RadioTap):
            rt = pkt.getlayer(RadioTap)
            frame_info["rssi"] = getattr(rt, "dBm_AntSignal", None)
            frame_info["channel_freq"] = getattr(rt, "ChannelFrequency", None)

        # Extract IEs from beacons and probe responses
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ies = _extract_ies(pkt)
            frame_info["information_elements"] = ies
            bssid = dot11.addr3
            if bssid:
                self._ap_ies[bssid] = ies

        return frame_info

    def run(self, ctx: ModuleContext) -> AttackResult:
        started = time.time()
        capture_file = ctx.params.get("capture_file")
        duration_s = int(ctx.params.get("duration_s", 30))
        iface = ctx.params.get("interface", "wlan0")

        if ctx.dry_run:
            return self._result(
                Status.OK,
                started,
                summary="[DRY-RUN] wifi.frame_dissector would dissect frames",
                metrics={"mode": "pcap" if capture_file else "live"},
            )

        self._frames = []
        self._ap_ies = {}

        try:
            if capture_file:
                packets = rdpcap(capture_file)
                for pkt in packets:
                    info = self._dissect_packet(pkt)
                    if info:
                        self._frames.append(info)
            else:
                packets = sniff(iface=iface, timeout=duration_s, store=True, monitor=True)
                for pkt in packets:
                    info = self._dissect_packet(pkt)
                    if info:
                        self._frames.append(info)
        except Exception as exc:
            log.error("wifi.frame_dissector.error", error=str(exc))
            return self._result(Status.FAIL, started, summary=f"Dissection error: {exc}")

        # Build frame type statistics
        type_stats: dict[str, int] = {}
        for frame in self._frames:
            key = f"{frame['type_str']}/{frame['subtype_str']}"
            type_stats[key] = type_stats.get(key, 0) + 1

        summary = (
            f"Dissected {len(self._frames)} frames, "
            f"{len(self._ap_ies)} APs with IE data, "
            f"{len(type_stats)} distinct frame type/subtype combinations"
        )

        return self._result(
            Status.OK,
            started,
            summary=summary,
            artifacts=[
                {"type": "frame_type_stats", "data": type_stats},
                {"type": "ap_ie_summary", "data": {
                    bssid: len(ies) for bssid, ies in self._ap_ies.items()
                }},
            ],
            metrics={
                "total_frames": len(self._frames),
                "ap_count": len(self._ap_ies),
                "frame_types": len(type_stats),
            },
        )

    def cleanup(self, ctx: ModuleContext) -> None:
        self._frames = []
        self._ap_ies = {}
