#!/bin/bash
set -euo pipefail

# sniffer-rt Raspberry Pi 5 Automated Setup Script
# Run as root on a fresh Raspberry Pi OS (Bookworm 64-bit) installation.

INSTALL_DIR="/opt/sniffer"
SRT_USER="srt"
REPO_URL="https://github.com/your-org/sniffer.git"
SSH_PORT=2222

echo "============================================"
echo "  sniffer-rt Pi 5 Setup"
echo "============================================"

# --- Check root ---
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

# --- Install required packages ---
echo "[1/9] Installing required packages..."
apt-get update
apt-get install -y \
    python3 python3-venv python3-pip \
    git docker.io docker-compose-plugin \
    hackrf libhackrf-dev \
    gpsd gpsd-clients \
    cryptsetup \
    ufw \
    bluez \
    aircrack-ng \
    tshark \
    jq \
    shred \
    dkms \
    "linux-headers-$(uname -r)" \
    build-essential \
    bc

# --- Install ALFA adapter driver (RTL8812AU/RTL8814AU) ---
echo "[1b/9] Installing ALFA WiFi adapter driver..."
# Try the packaged DKMS driver first
if apt-get install -y realtek-rtl88xxau-dkms 2>/dev/null; then
    echo "  ALFA driver installed via dkms package"
else
    # If the dkms package is not available, build from source
    echo "  DKMS package unavailable, building rtl8812au from source..."
    RTL_SRC="/usr/src/rtl8812au"
    if [ ! -d "$RTL_SRC" ]; then
        git clone https://github.com/aircrack-ng/rtl8812au.git "$RTL_SRC" || true
    fi
    if [ -d "$RTL_SRC" ]; then
        (cd "$RTL_SRC" && make && make install) || echo "  WARNING: rtl8812au build failed - install manually"
    fi
fi

# --- Install HackRF udev rules ---
echo "[1c/9] Installing HackRF udev rules..."
cat > /etc/udev/rules.d/52-hackrf.rules <<'UDEV_EOF'
# HackRF One
ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", MODE="0660", GROUP="plugdev", SYMLINK+="hackrf-%k"
# HackRF Jawbreaker
ATTR{idVendor}=="1d50", ATTR{idProduct}=="604b", MODE="0660", GROUP="plugdev", SYMLINK+="hackrf-jb-%k"
UDEV_EOF

# Ensure srt user is in plugdev group for HackRF access
usermod -aG plugdev "$SRT_USER" 2>/dev/null || true

# Enable Docker
systemctl enable --now docker

# --- Create srt user ---
echo "[2/9] Creating $SRT_USER user..."
if ! id "$SRT_USER" &>/dev/null; then
    useradd -r -m -s /bin/bash -d /home/srt "$SRT_USER"
    usermod -aG docker "$SRT_USER"
fi

# --- Clone/copy repository ---
echo "[3/9] Setting up repository at $INSTALL_DIR..."
if [ -d "$INSTALL_DIR" ]; then
    echo "  $INSTALL_DIR already exists, pulling latest..."
    git -C "$INSTALL_DIR" pull || true
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
chown -R "$SRT_USER:$SRT_USER" "$INSTALL_DIR"

# --- Set up Python virtual environment ---
echo "[4/9] Setting up Python virtual environment..."
sudo -u "$SRT_USER" python3 -m venv "$INSTALL_DIR/.venv"
sudo -u "$SRT_USER" "$INSTALL_DIR/.venv/bin/pip" install -e "$INSTALL_DIR"

# --- Copy systemd units ---
echo "[5/9] Installing systemd service files..."
cp "$INSTALL_DIR/deploy/systemd/srt-infra.service" /etc/systemd/system/
cp "$INSTALL_DIR/deploy/systemd/srt-probe.service" /etc/systemd/system/
cp "$INSTALL_DIR/deploy/systemd/srt-watchdog.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable srt-infra.service
systemctl enable srt-probe.service
systemctl enable srt-watchdog.service

# --- Copy udev rules ---
echo "[6/9] Installing udev rules..."
cp "$INSTALL_DIR/deploy/udev/99-srt-export.rules" /etc/udev/rules.d/
udevadm control --reload-rules
udevadm trigger

# --- Configure firewall ---
echo "[7/9] Configuring firewall (ufw)..."
ufw default deny incoming
ufw default allow outgoing
# Allow local network access for Grafana dashboard
ufw allow from 192.168.0.0/16 to any port 3000 proto tcp comment "Grafana"
# Allow SSH on custom port
ufw allow "$SSH_PORT/tcp" comment "SSH"
# Allow MQTT local only
ufw allow from 127.0.0.1 to any port 1883 proto tcp comment "MQTT local"
ufw --force enable

# --- Harden SSH ---
echo "[8/9] Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
# Backup original
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

# Apply hardening
sed -i "s/^#\?Port .*/Port $SSH_PORT/" "$SSHD_CONFIG"
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' "$SSHD_CONFIG"
sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
sed -i 's/^#\?X11Forwarding .*/X11Forwarding no/' "$SSHD_CONFIG"

systemctl restart sshd

# --- Set up GPS ---
echo "[9/9] Configuring GPS daemon..."
# Enable gpsd for USB GPS receiver
systemctl enable gpsd
systemctl start gpsd || true

# Create data directories
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/reports/out"
chown -R "$SRT_USER:$SRT_USER" "$INSTALL_DIR/data" "$INSTALL_DIR/reports"

# Make scripts executable
chmod +x "$INSTALL_DIR/scripts/"*.sh

echo ""
echo "============================================"
echo "  Setup Complete"
echo "============================================"
echo ""
echo "  Install directory:  $INSTALL_DIR"
echo "  Service user:       $SRT_USER"
echo "  SSH port:           $SSH_PORT"
echo "  Grafana:            http://localhost:3000"
echo ""
echo "  Services installed:"
echo "    - srt-infra.service   (Docker infrastructure)"
echo "    - srt-probe.service   (Autonomous probe)"
echo "    - srt-watchdog.service (Hardware watchdog)"
echo ""
echo "  Next steps:"
echo "    1. Set up LUKS encryption (see deploy/luks/README.md)"
echo "    2. Add SSH public keys to /home/srt/.ssh/authorized_keys"
echo "    3. Configure GPS receiver (check gpsd status)"
echo "    4. Start services: systemctl start srt-infra"
echo "    5. Verify with: srt selftest"
echo ""
