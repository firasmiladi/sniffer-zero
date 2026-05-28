# test_phase2_active

Date: 2026-05-28 07:09 UTC

| Module | Status | Résumé |
|--------|--------|--------|
| wifi.deauth | ok | wifi.deauth sent 200 deauth frames to a0:9f:7a:73:46:dd (client=FF:FF:FF:FF:FF:FF, channel=7, reason=7) |
| wifi.karma | ok | wifi.karma rogue_bssid=02:00:00:00:00:01: 120 probe responses sent to 3 unique clients in 30s |
| wifi.beacon_flood | ok | wifi.beacon_flood: 296 beacon frames sent (100 fake APs) on channel 7 over 20s |
| wifi.fragattack | ok | wifi.fragattack AP=a0:9f:7a:73:46:dd: 3/3 tests completed, 5 frames sent |
| wifi.dragonblood | ok | wifi.dragonblood AP=a0:9f:7a:73:46:dd: tests=['timing', 'downgrade'], timing_responses=0, downgrade_vulnerable=False |
| wifi.macstealer | ok | wifi.macstealer AP=a0:9f:7a:73:46:dd: impersonated 68:3a:48:44:ad:9c, intercepted 70 queued frames |
| wifi.eap_relay | ok | wifi.eap_relay SSID=Tunisie_Telecom-2.4G-46DD: captured 0 EAP identities over 60s |

---
## wifi.deauth

**Status:** ok  
**Durée:** 23.7s  
**MITRE:** T1499.004  

wifi.deauth sent 200 deauth frames to a0:9f:7a:73:46:dd (client=FF:FF:FF:FF:FF:FF, channel=7, reason=7)

---
## wifi.karma

**Status:** ok  
**Durée:** 30.1s  
**MITRE:** T1557.002, T1583.001  

wifi.karma rogue_bssid=02:00:00:00:00:01: 120 probe responses sent to 3 unique clients in 30s

---
## wifi.beacon_flood

**Status:** ok  
**Durée:** 20.3s  
**MITRE:** T1499.002  

wifi.beacon_flood: 296 beacon frames sent (100 fake APs) on channel 7 over 20s

---
## wifi.fragattack

**Status:** ok  
**Durée:** 1.1s  
**MITRE:** T1557  
**CVE:** CVE-2020-24586, CVE-2020-24587, CVE-2020-24588  

wifi.fragattack AP=a0:9f:7a:73:46:dd: 3/3 tests completed, 5 frames sent

---
## wifi.dragonblood

**Status:** ok  
**Durée:** 54.1s  
**MITRE:** T1557, T1110  
**CVE:** CVE-2019-9494, CVE-2019-9495, CVE-2019-9496  

wifi.dragonblood AP=a0:9f:7a:73:46:dd: tests=['timing', 'downgrade'], timing_responses=0, downgrade_vulnerable=False

---
## wifi.macstealer

**Status:** ok  
**Durée:** 6.9s  
**MITRE:** T1557.002  
**CVE:** CVE-2022-47522  

wifi.macstealer AP=a0:9f:7a:73:46:dd: impersonated 68:3a:48:44:ad:9c, intercepted 70 queued frames

---
## wifi.eap_relay

**Status:** ok  
**Durée:** 66.5s  
**MITRE:** T1557, T1556.005  
**CVE:** CVE-2023-52160  

wifi.eap_relay SSID=Tunisie_Telecom-2.4G-46DD: captured 0 EAP identities over 60s

