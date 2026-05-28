# test_phase4_external

Date: 2026-05-28 07:26 UTC

| Module | Status | Résumé |
|--------|--------|--------|
| wifi.mdk4_dos | ok | wifi.mdk4_dos attack=d (deauth) bssid=a0:9f:7a:73:46:dd: ran 30.0s |
| wifi.eap_capture | fail | eaphammer not found. Install: git clone https://github.com/s0lst1c3/eaphammer ~/sniffer/third_party/eaphammer && cd ~/sniffer/third_party/eaphammer && sudo ./kali-setup |

---
## wifi.mdk4_dos

**Status:** ok  
**Durée:** 30.0s  
**MITRE:** T1499.002, T1499.004  

wifi.mdk4_dos attack=d (deauth) bssid=a0:9f:7a:73:46:dd: ran 30.0s

---
## wifi.eap_capture

**Status:** fail  
**Durée:** 0.0s  
**MITRE:** T1557, T1556.005  
**CVE:** CVE-2023-52160  

eaphammer not found. Install: git clone https://github.com/s0lst1c3/eaphammer ~/sniffer/third_party/eaphammer && cd ~/sniffer/third_party/eaphammer && sudo ./kali-setup

