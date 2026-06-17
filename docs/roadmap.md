# Roadmap

Pitched as a 12-week academic project. Each phase ships a working demo.

| Phase | Weeks | Deliverable | Hardware | Demo |
|-------|-------|-------------|----------|------|
| 0 | 1 | Bring-up: DragonOS VM, HackRF, infra stack | HackRF | `hackrf_info`, FM demod, Grafana dashboard live |
| 1 | 2 | GNU Radio no-code basics | HackRF | Receive + decode known beacon |
| 2 | 3-4 | **WiFi recon + deauth + PMKID capture + crack** | HackRF, monitor-mode NIC | Auto-discovered devices, crack a 8-char PSK |
| 3 | 5 | **WiFi evil-twin + EAP relay** | NIC | Captive portal + cleartext creds (lab user) |
| 4 | 6 | **BLE recon + Just-Works pair capture + crackle** | HackRF / Ubertooth | LTK extracted, GATT enum |
| 5 | 7 | **BLE active MITM (mirage / btlejack hijack)** | HackRF + 2x nRF52 | Toggle a smart bulb mid-session |
| 6 | 8 | **LoRaWAN recon (gr-lora_sdr) + ABP replay** | HackRF | Replay an uplink, show on ChirpStack |
| 7 | 9 | **LoRaWAN OTAA join replay + bit-flip on FRMPayload** | HackRF | Force re-join, modify payload |
| 8 | 10 | **DB schema + flow matrix + Grafana dashboards** | - | Live cross-protocol device map |
| 9 | 11 | Pi 5 deployment, autonomous mode, encrypted captures | Pi 5 + SSD | Boot -> sniff -> upload |
| 10 | 12 | Final jury demo + report | full kit | Multi-protocol scenario |

## Stretch goals (post-12 weeks)

- RF fingerprinting (CFO, IQ imbalance) to defeat MAC randomization.
- Cross-protocol identity correlation (BLE MAC <-> WiFi MAC).
- Multi-node TDoA localization of an unauthorized emitter.
- Drone telemetry decoding (DJI OcuSync, ELRS, MAVLink-RF).

## Definition of done per phase

1. Module(s) implement the `AttackModule` interface.
2. Headers/results land in TimescaleDB.
3. Grafana panel exists.
4. `scenarios/<phase>.yaml` reproduces the demo end-to-end.
5. `docs/attacks/<protocol>.md` references the new module.
6. PR is reviewed and merged into `main`.
