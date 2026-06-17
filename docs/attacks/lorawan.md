# LoRaWAN attack catalogue (lab-only)

Tooling baseline: `gr-lora_sdr` (EPFL), `LoRaPWN`, `scapy-lorawan`,
`ChirpStack` (network server), custom Python decoders.

| ID | Module | Goal | Pre-conditions | MITRE | Refs |
|----|--------|------|----------------|-------|------|
| L01 | `lora.recon` | Listen on EU868 / 915 channels, decode PHY → LoRaWAN frames, header extract | HackRF + gr-lora_sdr | T1040 | — |
| L02 | `lora.devnonce_audit` | Detect DevNonce reuse across Join Requests | OTAA captures | T1110 | LoRaWAN spec 1.0.x |
| L03 | `lora.fcnt_audit` | Detect FCnt rollback / reset | Uplink history | T1499 | — |
| L04 | `lora.uplink_replay_abp` | Replay captured uplink against ChirpStack | ABP device, no FCnt validation | T1565.002 | — |
| L05 | `lora.join_replay` | Replay Join Request / Join Accept | OTAA target | T1110 | — |
| L06 | `lora.bitflip_frmpayload` | AES-CTR malleability on FRMPayload (no app-level MAC) | Known plaintext | T1565.002 | — |
| L07 | `lora.beacon_spoof` | Spoof Class B beacons → move RX slot | Class B device | T1557 | — |
| L08 | `lora.gateway_impersonation` | Connect to network server as fake gateway | Unauthenticated GW backhaul | T1557 | — |
| L09 | `lora.channel_jam` | Selective jamming of one of the 8 EU868 channels | TX SDR | T1499 | — |
| L10 | `lora.appkey_default_check` | Try default / vendor AppKeys → derive session keys | AppKey list | T1078 | — |
| L11 | `lora.confidentiality_abp` | Decrypt FRMPayload if AppSKey leaked | AES-CTR + key | T1040 | — |
| L12 | `lora.adr_downgrade` | Force device to lowest SF / highest power via crafted MAC commands | DL injection | T1499 | — |
| L13 | `lora.rejoin_request_abuse` | Force re-join cycle (1.1) | LoRaWAN 1.1 | T1499 | — |

## Default scenarios

- `scenarios/lora_recon_only.yaml`
- `scenarios/lora_abp_replay_demo.yaml` (full demo against ChirpStack)
- `scenarios/lora_otaa_join_replay.yaml`

## Lab targets

- ChirpStack v4 (containerized in `infra/docker-compose.yml`).
- RAK7268 or Dragino LPS8 gateway as production-style target.
- 4 disposable Heltec / TTGO LoRa nodes:
  - Two ABP, FCnt validation off (vulnerable demo).
  - One ABP, FCnt validation on.
  - One OTAA 1.0.4.

## Notes

- Always operate inside Faraday cage; HackRF TX on EU868 is licensed-band.
- L08 requires the lab's ChirpStack to be configured to accept unauthenticated
  gateways — never enable on external infra.
- Provide whitelist of allowed DevEUIs in `safety/whitelist.yaml`.
