# Hardware BOM

| # | Item | Purpose | Approx. EUR |
|---|------|---------|-------------|
| 1 | HackRF One | ISM TX/RX up to 6 GHz, half-duplex | 320 |
| 2 | Nooelec SAWbird+ Flex / generic LNA | Front-end gain | 50 |
| 3 | SAW filters: 433 / 868 / 915 / 2.4 GHz | Out-of-band rejection | 4x15 |
| 4 | RF antennas (433/868/915/2.4/5) | Reception | 60 |
| 5 | Raspberry Pi 5, 8 GB | Sniffer host | 90 |
| 6 | NVMe SSD 256 GB + Pi 5 NVMe HAT | Capture storage (LUKS) | 70 |
| 7 | Pi 5 active cooler + PSU | Stability | 25 |
| 8 | USB-C hub (powered) | HackRF + ALFA + storage | 25 |
| 9 | ALFA AWUS036ACH (RTL8812AU) | WiFi monitor mode + injection | 60 |
| 10 | Faraday cage / shielded tent | Legal RF containment | 150-500 |
| 11 | ESP32 / nRF52 dev boards | BLE / LoRa targets | 30 |
| 12 | OpenWrt-capable AP (e.g. GL.iNet) | WiFi target | 60 |
| 13 | LoRaWAN gateway (RAK / Dragino) | LoRa uplink target | 150 |
| 14 | Spectrum analyzer (TinySA Ultra) | Sanity / EMC checks | 130 |
| 15 | Variable bench PSU + RF cables | Power, plumbing | 100 |

**Optional**

- LimeSDR-Mini 2.0 - additional SDR for dual-radio experiments (~250 EUR).
- Ubertooth One - known-good BLE sniffer for cross-validation (~120 EUR).
- Sniffle (TI CC1352) - modern BLE 5 sniffer (~50 EUR).
- HackRF Portapack - field UI / recon (~250 EUR).

**Total minimum (ISM-only):** ~700 EUR
**Total recommended (full lab):** ~1500 EUR
