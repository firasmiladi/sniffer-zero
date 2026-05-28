# Rapport: test_phase5_defense_zeroday
_2026-05-28 07:47 UTC_

**Modules exécutés:** 5 (4 OK)

| Module | Status | Résultat |
|--------|--------|----------|
| defense.rogue_ap_detector | ok | defense.rogue_ap_detector: 0 APs monitored, 0 alerts raised in 60s |
| defense.alerting | ok | defense.alerting: 0 alerts raised, 0 APs, 0 clients monitored in 60s |
| intel.mac_dehide | ok | intel.mac_dehide: 0 MACs seen, 0 random, 0 multi-MAC clusters (same device with ... |
| zero_day.airsnitch | ok | zero_day.airsnitch bssid=a0:9f:7a:73:46:dd: 3 vectors tested, 3 successful |
| zero_day.cve_2024_30078 | fail | Injection error: While building field 'len': Incorrect type of value for field l... |

---

## defense.rogue_ap_detector

defense.rogue_ap_detector: 0 APs monitored, 0 alerts raised in 60s

---

## defense.alerting

defense.alerting: 0 alerts raised, 0 APs, 0 clients monitored in 60s

---

## intel.mac_dehide

intel.mac_dehide: 0 MACs seen, 0 random, 0 multi-MAC clusters (same device with different MACs)

---

## zero_day.airsnitch

zero_day.airsnitch bssid=a0:9f:7a:73:46:dd: 3 vectors tested, 3 successful

---

## zero_day.cve_2024_30078

Injection error: While building field 'len': Incorrect type of value for field len:
struct.error(''B' format requires 0 <= number <= 255')
To inject bytes into the field regardless of the type, use RawVal. See help(RawVal)

