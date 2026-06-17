# Architecture

`sniffer-rt` is a modular RF red-team platform. It treats every action — passive
scan or active attack — as an `AttackModule` that exposes the same lifecycle and
emits structured results to a shared bus + database.

## High-level diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                           sniffer-rt                                 │
├────────────────────────┬─────────────────────────────────────────────┤
│  ISM (HackRF + ALFA)   │  POST / SHARED                             │
│  - WiFi  2.4 / 5 GHz   │  - TimescaleDB                             │
│  - BLE   2.4 GHz       │  - Grafana                                 │
│  - LoRa  433/868/915   │  - Reporter (PDF)                          │
│  - Zigbee (bonus)      │  - MITRE mapping                           │
└──────────┬─────────────┴─────────────────────────────────┬───────────┘
           │                                               │
           ▼                                               ▼
     GNU Radio /                                     MQTT (events)
     gr-* OOTs                                       PostgreSQL/TS
           │                                               │
           └──────────────────┬────────────────────────────┘
                              ▼
                     ┌────────────────┐
                     │  Orchestrator  │
                     │   (src/srt)    │
                     └────────┬───────┘
                              ▼
                      CLI  (`srt ...`)  +  YAML scenarios  +  TUI (later)
```

## Layers

### 1. Capture & decode (recon)

Located under `src/srt/recon/`.
- `wifi/`, `ble/`, `lora/` use SDR or commodity NICs.
- All recon modules emit normalized **header records** (no payloads) onto the
  internal MQTT bus and the `events.headers` Timescale hypertable.

### 2. Storage & dashboards

- TimescaleDB: time-series headers, sessions, hashes (PMKID/EAPOL), captures
  index.
- Grafana: pre-provisioned dashboards (`infra/grafana/provisioning/`).
- MQTT (Mosquitto): real-time event bus for live UI / chained modules.

### 3. Active attack modules (exploit)

Located under `src/srt/exploit/`. Each module:
- Inherits `srt.core.module.AttackModule`.
- Declares `protocol`, `mitre_ttp`, `cve`, `requires`, `risk`.
- Implements `precheck → run → cleanup → report`.
- Refuses to run unless `safety.lab_only=True` and an authorization token is
  present (see `docs/legal-scope.md`).

### 4. Orchestrator & reporting

`src/srt/core/orchestrator.py` loads YAML scenarios from `scenarios/`, runs
modules in sequence, and aggregates results into a session.
`src/srt/core/reporter.py` produces JSON + Markdown + PDF reports with MITRE
ATT&CK coverage.

## Data flow

```
SDR ─▶ flowgraph ─▶ decoder ─▶ recon module ─┬─▶ MQTT topic   srt/headers/<proto>
                                              ├─▶ TimescaleDB events.headers
                                              └─▶ pcap/cfile  data/captures/...

scenario.yaml ─▶ orchestrator ─▶ module.run() ─▶ AttackResult ─▶ reporter
                                              └─▶ MQTT topic   srt/results/<id>
```

## Why this architecture

- **Uniform module API** → easy to teach, easy to grade, easy to extend.
- **Clear split passive/active** → maps directly to the Cyber Kill Chain and
  MITRE ATT&CK Recon → Initial Access phases.
- **Headers-only storage** → privacy-preserving by design (relevant for
  defense/RGPD audits).
- **Containerized infra** → reproducible lab; identical on the analyst's laptop
  and on the deployable Pi 5.
