# BLE attack catalogue (lab-only)

Tooling baseline: `bleak`, `bettercap`, `crackle`, `btlejack`, `mirage`,
`Sniffle` (CC1352), Ubertooth, custom `gr-bluetooth` flowgraphs.

| ID | Module | Goal | Pre-conditions | MITRE | Refs |
|----|--------|------|----------------|-------|------|
| B01 | `ble.recon` | Advertising scan, service-UUID enum, vendor lookup | SDR or BLE NIC | T1592 | — |
| B02 | `ble.gatt_enum` | Connect + enumerate GATT services / characteristics | Connectable peripheral | T1592 | bleak |
| B03 | `ble.pair_capture` | Sniff Just-Works / Legacy pairing → crackle | Pairing event captured | T1110 | crackle |
| B04 | `ble.ltk_decrypt` | Decrypt session traffic with recovered LTK | LTK from B03 | T1557 | — |
| B05 | `ble.unauth_write` | Write to unauthenticated GATT chars (toggle device) | Open characteristic | T1565 | mirage |
| B06 | `ble.connection_hijack` | Take over established connection mid-session | btlejack hop sync | T1557 | btlejack -t |
| B07 | `ble.adv_jam` | Jam advertising channels 37/38/39 | TX SDR | T1499 | btlejack -j |
| B08 | `ble.gattacker_mitm` | Active GATT relay between target and central | Known target | T1557 | gattacker |
| B09 | `ble.sweyntooth` | Crash/bypass on vulnerable BLE stacks | CVE-2019-19192 set | T1499 | research |
| B10 | `ble.blesa` | Reconnection spoof (CVE-2020-9770) | Vulnerable peripheral | T1557 | research |
| B11 | `ble.knob` | Force minimum entropy in pairing | KNOB | T1110 | research |
| B12 | `ble.mac_track` | Track devices despite MAC randomization (RPA + payload fingerprint) | Static-payload device | T1592 | OpenHaystack |
| B13 | `ble.airtag_clone` | Replay / clone Find-My beacon | research | T1557 | OpenHaystack |
| B14 | `ble.replay_unauth` | Replay captured unauthenticated writes | B05 capture | T1557 | — |

## Default scenario

`scenarios/ble_full_audit.yaml`: `recon → gatt_enum → pair_capture →
ltk_decrypt → report`.

`scenarios/ble_smartlock_demo.yaml`: `recon → gatt_enum → unauth_write
(toggle bulb)`.

## Lab targets

- ESP32 advertising as `srt-ble-target` (Just-Works pairing).
- Mi Band / generic fitness tracker.
- BLE smart bulb (Yeelight or similar).
- AirTag-style tracker (clone, OpenHaystack-compatible).

## Notes

- B07/B09 are `destructive-lab` (may crash targets).
- B11/B12/B13 are research-grade — expect partial automation only.
