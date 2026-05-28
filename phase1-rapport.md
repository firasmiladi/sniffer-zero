# test_phase1_recon

Date: 2026-05-28 06:30 UTC

| Module | Status | Résumé |
|--------|--------|--------|
| wifi.recon | ok | wifi.recon completed: 4 APs discovered, 2 clients seen, 1033 frames captured over 60s on channels 1-13 |
| wifi.security_assessor | ok | Assessed 4 APs: A=0 B=0 C=3 D=0 E=1 F=0, 1 total issues found |
| wifi.signal_analyzer | ok | Signal analysis: 73 frames, 4 channels active, 6 sources with distance estimates |
| wifi.timing_analyzer | ok | Timing analysis: 22 beacons (4 suspicious), 0 deauths (0 floods), 51 probes from 2 clients |
| wifi.frame_dissector | ok | Dissected 163 frames, 1 APs with IE data, 3 distinct frame type/subtype combinations |
| wifi.probe_fingerprinter | ok | Fingerprinted 2 devices (0 randomized MACs), 1 multi-MAC clusters, 2 SSIDs in PNLs |

---
## wifi.recon

**Status:** ok  
**Durée:** 60.4s  
**MITRE:** T1040, T1592  

wifi.recon completed: 4 APs discovered, 2 clients seen, 1033 frames captured over 60s on channels 1-13

### APs détectés
| BSSID | SSID | Channel | Encryption |
|-------|------|---------|-----------|
| 98:a9:42:1d:44:be | Ooredoo _S20_44BE | 1 | WPA2 |
| 34:e8:94:b8:d6:d8 | TT_D6D8 | 2 | WPA |
| 28:d1:27:4e:81:54 | Xiaomi_288C | 4 | WPA2 |
| a0:9f:7a:73:46:dd | Tunisie_Telecom-2.4G-46DD | 7 | WPA2 |

---
## wifi.security_assessor

**Status:** ok  
**Durée:** 0.0s  
**MITRE:** T1592.002, T1590  

Assessed 4 APs: A=0 B=0 C=3 D=0 E=1 F=0, 1 total issues found

### Évaluation sécurité
| SSID | Encryption | Grade | Problèmes |
|------|-----------|-------|-----------|
| Xiaomi_288C | WPA2 | C | — |
| TT_D6D8 | WPA | E | WPA is cryptographically broken |
| Ooredoo _S20_44BE | WPA2 | C | — |
| Tunisie_Telecom-2.4G-46DD | WPA2 | C | — |

**Grades:** C=3 / E=1

---
## wifi.signal_analyzer

**Status:** ok  
**Durée:** 0.0s  
**MITRE:** T1592  

Signal analysis: 73 frames, 4 channels active, 6 sources with distance estimates

### Congestion canaux
| Canal | Frames | % |
|-------|--------|---|
| 1 | 3 | 13.6% |
| 2 | 5 | 22.7% |
| 4 | 5 | 22.7% |
| 7 | 9 | 40.9% |

### Distances estimées
| Source | RSSI moyen | Distance | Samples |
|--------|-----------|----------|---------|
| 68:3a:48:44:ad:9c | -38.1 dBm | 4.64 m | 48 |
| 98:a9:42:1d:44:be | -73.7 dBm | 91.83 m | 3 |
| 34:e8:94:b8:d6:d8 | -66.6 dBm | 50.55 m | 5 |
| 28:d1:27:4e:81:54 | -75.0 dBm | 108.9 m | 5 |
| 3c:71:bf:2e:b0:2e | -77.0 dBm | 129.15 m | 3 |
| a0:9f:7a:73:46:dd | -30.8 dBm | 2.35 m | 9 |

---
## wifi.timing_analyzer

**Status:** ok  
**Durée:** 0.0s  
**MITRE:** T1557.004, T1498  

Timing analysis: 22 beacons (4 suspicious), 0 deauths (0 floods), 51 probes from 2 clients

### Analyse jitter beacons
| BSSID | Interval moy | Jitter ratio | Alerte |
|-------|-------------|-------------|--------|
| 98:a9:42:1d:44:be | 7987 ms | 0.923 | possible_rogue_ap |
| 34:e8:94:b8:d6:d8 | 11853 ms | 1.669 | possible_rogue_ap |
| 28:d1:27:4e:81:54 | 11827 ms | 1.572 | possible_rogue_ap |
| a0:9f:7a:73:46:dd | 5926 ms | 1.661 | possible_rogue_ap |

### Profils timing probes
| Client | Probes | Interval moy | Durée |
|--------|--------|-------------|-------|
| 68:3a:48:44:ad:9c | 48 | 1.19s | 55.8s |
| 3c:71:bf:2e:b0:2e | 3 | 19.42s | 38.8s |

---
## wifi.frame_dissector

**Status:** ok  
**Durée:** 30.2s  
**MITRE:** T1040, T1592.002  

Dissected 163 frames, 1 APs with IE data, 3 distinct frame type/subtype combinations

### Types de frames
| Type | Count |
|------|-------|
| Management/ProbeReq | 130 |
| Control/ACK | 32 |
| Management/Beacon | 1 |

---
## wifi.probe_fingerprinter

**Status:** ok  
**Durée:** 0.0s  
**MITRE:** T1592.002, T1018  

Fingerprinted 2 devices (0 randomized MACs), 1 multi-MAC clusters, 2 SSIDs in PNLs

### Devices identifiés
| MAC | Type | Fingerprint | Random |
|-----|------|------------|--------|
| 68:3a:48:44:ad:9c | iot_device | 26556e2639858107 | False |
| 3c:71:bf:2e:b0:2e | iot_device | 26556e2639858107 | False |

### PNL (réseaux cherchés par les devices)
- 68:3a:48:44:ad:9c: poupou
- 3c:71:bf:2e:b0:2e: TOPNET7616AB70

