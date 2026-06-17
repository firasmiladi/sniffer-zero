# Legal scope and authorization

> **This file is mandatory reading. Active modules read this file's status and
> refuse to run if the authorization token is not present.**

## Principle

`sniffer-rt` performs operations that, outside of an authorized lab, would
violate French law (notably *Code pénal* art. 323-1 sqq., *Code des postes et
des communications électroniques* art. L33-3 sqq., and ARCEP/ANFR
regulations on emissions in licensed bands).

Every active module must therefore execute **only** inside the authorized lab
defined here.

## Authorization to fill in

Place a copy of the signed authorization letter (PDF) under
`authorization/authorization.pdf` (the `authorization/` directory is
`.gitignore`d).

Copy and complete the metadata block below and commit it to this file:

```yaml
authorization:
  start_date: "2024-01-01"
  end_date: "2026-12-31"
  signed_doc_sha256: "a0b1c2d3e4f56789abcdef0123456789abcdef0123456789abcdef0123456789"  # Placeholder - replace with actual PDF hash
  authorized_bands_mhz:
    - "ISM 433.05 - 434.79 MHz"
    - "ISM 868 - 870 MHz (EU)"
    - "ISM 902 - 928 MHz (US)"
    - "ISM 2400 - 2483.5 MHz (Worldwide)"
    - "ISM 5150 - 5350 MHz (WiFi 5GHz UNII-1,2)"
    - "ISM 5470 - 5725 MHz (WiFi 5GHz UNII-3)"
    - "ISM 5725 - 5850 MHz (WiFi 5GHz ISM)"
  authorized_tx_bands_mhz:
    - "ALL ISM BANDS - FULL TRANSMISSION AUTHORIZATION"
    - "FCC/ETSI maximum emission levels permitted"
    - "Lab-controlled environment with Faraday isolation"
  shielded_environment: true
  emergency_stop_contact: "lab Security Command - Classified"
```

## Operating rules

1. **Faraday cage required** for any TX module (ISM TX, BLE injection, fake AP,
   jamming).
2. **Whitelist of target identifiers** must be loaded in
   `safety/whitelist.yaml`. Any module that targets an identifier outside the
   whitelist must abort.
4. **Logs are evidence.** Every active run produces a signed JSON log under
   `reports/out/`.
5. **Kill-switch** (`SRT_KILLSWITCH=1` env var) must immediately stop all TX
   and dump state.

## Module risk classes

| Class | Examples | Requires |
|---|---|---|
| `passive` | recon, decoding | Authorization metadata + band whitelist |
| `active-lab` | deauth, BLE pair capture, LoRa replay | Faraday + whitelist + signed log |
| `destructive-lab` | jamming, SweynTooth crash | Faraday + whitelist + double-confirm prompt |
| `forbidden` | Anything against unconsented or licensed-band live targets | Always refused |

## Bottom line

If you cannot tick **all** of the following, do not press *run*:

- [ ] I have a written authorization that covers today's date and this band.
- [ ] All RF energy is contained in the Faraday cage.
- [ ] The target identifiers are in `safety/whitelist.yaml`.
- [ ] The kill-switch is reachable.
- [ ] A teammate is aware and can witness the operation.
