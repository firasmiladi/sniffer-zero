# WiFi attack catalogue (lab-only)

Tooling baseline: `aircrack-ng`, `hcxdumptool`/`hcxtools`, `hashcat`, `mdk4`,
`hostapd-mana`, `eaphammer`, optional `bettercap`.

| ID | Module | Goal | Pre-conditions | MITRE | CVE / Refs |
|----|--------|------|----------------|-------|------------|
| W01 | `wifi.recon` | Channel hopping survey, AP+client inventory, OUI lookup | Monitor-mode NIC | T1040, T1592 | — |
| W02 | `wifi.deauth` | Force client to disconnect → re-auth handshake | Target AP+client | T1499.004 | 802.11 mgmt frames |
| W03 | `wifi.handshake_capture` | Capture WPA2 4-way handshake | Re-auth event (W02) | T1040 | — |
| W04 | `wifi.pmkid` | Capture PMKID from beacon-less AP | RSN IE present | T1110.002 | hashcat 16800 |
| W05 | `wifi.psk_crack` | Offline brute-force / dict / mask | hash from W03/W04 | T1110.002 | hashcat 22000 |
| W06 | `wifi.evil_twin` | Spawn rogue AP with same SSID, captive portal | SSID known | T1557 | hostapd-mana |
| W07 | `wifi.karma` | Respond to probe requests, lure clients | Clients with saved nets | T1557 | mana / eaphammer |
| W08 | `wifi.wps_pixie` | Recover WPS PIN → derive PSK | WPS enabled AP | T1110 | reaver, bully |
| W09 | `wifi.eap_relay` | Capture NTLMv2 / cleartext on enterprise WiFi | WPA2-Enterprise | T1557 | eaphammer |
| W10 | `wifi.krack` | Key-reinstallation against unpatched client | CVE-2017-13077 family | T1557 | KRACK |
| W11 | `wifi.fragattacks` | Frame aggregation/injection bugs | unpatched stack | T1557 | CVE-2020-24588... |
| W12 | `wifi.beacon_flood` | Flood with fake SSIDs | — | T1499 | mdk4 -b |
| W13 | `wifi.mgmt_dos` | Auth/assoc flood | — | T1499 | mdk4 -a |
| W14 | `wifi.rogue_ap_dns` | Evil twin + DNS spoofing for downstream attacks | W06 | T1557.002 | dnsmasq |
| W15 | `wifi.mac_fingerprint` | Defeat MAC randomization via PHY-layer fingerprint | SDR capture | T1592 | research |

## Default scenario

`scenarios/wifi_full_audit.yaml` chains: `recon → deauth → handshake_capture →
pmkid → psk_crack → report`.

## Lab targets

Disposable OpenWrt AP under `lab/openwrt-ap/`:
- WPA2-PSK SSID `srt-lab-psk` (pwd `Pasteur123!`)
- WPA2-Enterprise SSID `srt-lab-eap` (PEAP-MSCHAPv2)
- Legacy WPS-enabled SSID `srt-lab-wps`
- Open SSID `srt-lab-open` (for evil-twin tests)

## Notes

- All TX modules require `safety.lab_only=true` and a band whitelist hit on
  2.4 GHz / 5 GHz.
- `wifi.fragattacks` is `destructive-lab` (may crash target stacks).
