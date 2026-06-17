#!/bin/bash
# Install all military WiFi arsenal tools
# Project: DEF-RF-2024-001
# Usage: sudo bash scripts/install_arsenal.sh

set -e

echo "╔════════════════════════════════════════════════╗"
echo "║  ISM-SNIFFER ARSENAL INSTALLER                  ║"
echo "║  Project: DEF-RF-2024-001                       ║"
echo "╚════════════════════════════════════════════════╝"

# System tools
echo "[*] Installing system tools..."
sudo apt update
sudo apt install -y \
    mdk4 macchanger reaver bully \
    hostapd dnsmasq \
    hashcat hcxdumptool hcxtools \
    kismet \
    aircrack-ng \
    python3-pip python3-dev libssl-dev libffi-dev

# Python tools
echo "[*] Installing Python tools..."
pip3 install --break-system-packages \
    impacket bloodhound-python lsassy pycryptodome \
    wifiphisher requests scapy 2>/dev/null || \
pip3 install \
    impacket bloodhound-python lsassy pycryptodome \
    wifiphisher requests scapy

# Third party repos
echo "[*] Cloning third-party tools..."
THIRD_PARTY="$(dirname "$(readlink -f "$0")")/../third_party"
mkdir -p "$THIRD_PARTY"
cd "$THIRD_PARTY"

[ ! -d "eaphammer" ] && git clone --depth=1 https://github.com/s0lst1c3/eaphammer
[ ! -d "Responder" ] && git clone --depth=1 https://github.com/lgandx/Responder
[ ! -d "SecLists" ] && git clone --depth=1 https://github.com/danielmiessler/SecLists
[ ! -d "impacket" ] && git clone --depth=1 https://github.com/fortra/impacket
[ ! -d "RuView" ] && git clone --depth=1 https://github.com/ruvnet/RuView

# Setup eaphammer
if [ -d "eaphammer" ] && [ -f "eaphammer/kali-setup" ]; then
    echo "[*] Setting up eaphammer..."
    cd eaphammer && sudo ./kali-setup 2>/dev/null || true
    cd "$THIRD_PARTY"
fi

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║  ARSENAL INSTALLED SUCCESSFULLY                 ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "Verify with:"
echo "  which mdk4 && which hashcat && which reaver && which kismet"
echo "  srt list | grep -E 'phishing|eap_capture|mdk4|responder|bettercap|airsnitch'"
