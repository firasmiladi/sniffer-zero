#!/bin/bash
# Raspberry Pi 5 Deployment Script for French Ministry of Defense
# Faraday Cage Lab - Military Research Project DEF-RF-2024-001
#
# Hardware: Raspberry Pi 5 + ALFA AWUS036H + HackRF One
# Deployment Platform: Raspberry Pi OS Lite (64-bit)
# Usage: Run on Raspberry Pi 5 after copying sniffer repository

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  French Ministry of Defense - Military RF Security Platform   ${NC}"
echo -e "${BLUE}  Raspberry Pi 5 Deployment Script                             ${NC}"
echo -e "${BLUE}  Project: DEF-RF-2024-001                                     ${NC}"
echo -e "${BLUE}================================================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo -i)${NC}"
    exit 1
fi

# Check Raspberry Pi model
PI_MODEL=$(cat /proc/device-tree/model 2>/dev/null || echo "Unknown")
echo -e "${YELLOW}Detected hardware: $PI_MODEL${NC}"

# Verify minimum requirements
echo -e "${YELLOW}[1/7] Checking system requirements...${NC}"
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
if [ "$TOTAL_MEM" -lt 4000 ]; then
    echo -e "${RED}Insufficient RAM: ${TOTAL_MEM}MB (minimum 4GB required)${NC}"
    exit 1
fi

# Check running on Raspberry Pi OS 64-bit
if ! uname -m | grep -q "aarch64"; then
    echo -e "${RED}Not running on aarch64 (64-bit) architecture${NC}"
    exit 1
fi

echo -e "${GREEN}✓ System meets minimum requirements${NC}"

# Update system
echo -e "${YELLOW}[2/7] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

# Install core dependencies
echo -e "${YELLOW}[3/7] Installing core dependencies...${NC}"
apt-get install -y \
    git \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    cmake \
    pkg-config \
    libusb-1.0-0-dev \
    libhackrf-dev \
    hackrf \
    libtool \
    automake \
    libffi-dev \
    libssl-dev \
    wget \
    curl \
    htop \
    vim

# Install Docker for containerized infrastructure
echo -e "${YELLOW}[4/7] Installing Docker...${NC}"
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker $SUDO_USER
rm get-docker.sh

# Install Docker Compose
echo -e "${YELLOW}[5/7] Installing Docker Compose...${NC}"
DOCKER_COMPOSE_VERSION="v2.24.5"
curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-aarch64" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Setup hardware-specific drivers
echo -e "${YELLOW}[6/7] Setting up hardware drivers...${NC}"

# Install ALFA AWUS036H (RTL8812AU) driver
echo -e "${YELLOW}Installing ALFA AWUS036H (RTL8812AU) driver...${NC}"
apt-get install -y \
    dkms \
    linux-headers-$(uname -r)

# Check if driver is already built
if ! modinfo 8812au 2>/dev/null | grep -q "rtl8812au"; then
    echo -e "${YELLOW}Building RTL8812AU driver from source...${NC}"
    git clone https://github.com/aircrack-ng/rtl8812au.git /tmp/rtl8812au
    cd /tmp/rtl8812au
    make clean
    make
    make install
    cd ~
    rm -rf /tmp/rtl8812au
fi

# Verify HackRF One
echo -e "${YELLOW}Verifying HackRF One hardware...${NC}"
if command -v hackrf_info &> /dev/null; then
    HACKRF_INFO=$(hackrf_info 2>/dev/null || true)
    if echo "$HACKRF_INFO" | grep -q "HackRF One"; then
        echo -e "${GREEN}✓ HackRF One detected${NC}"
    else
        echo -e "${YELLOW}⚠ HackRF not connected or not detected${NC}"
    fi
fi

# Setup Python virtual environment
echo -e "${YELLOW}[7/7] Setting up Python environment...${NC}"
python3 -m venv /opt/srt-venv
source /opt/srt-venv/bin/activate

# Install sniffer-rt package
cd /projects/sandbox/sniffer || cd ~/sniffer  # Adjust based on clone location
pip install --upgrade pip
pip install -e ".[dev,ble,report]"

# Create systemd services for auto-start
echo -e "${YELLOW}Creating systemd services...${NC}"
cp deploy/systemd/srt-infra.service /etc/systemd/system/
cp deploy/systemd/srt-probe.service /etc/systemd/system/
cp deploy/systemd/srt-watchdog.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable srt-infra.service
systemctl enable srt-watchdog.service

# Setup udev rules for hardware access
echo -e "${YELLOW}Setting up udev rules...${NC}"
cp deploy/udev/99-srt-export.rules /etc/udev/rules.d/
udevadm control --reload-rules
udevadm trigger

# Security configuration
echo -e "${YELLOW}Configuring security settings...${NC}"
# Set up encrypted storage (if LUKS is configured)
if [ -f "deploy/luks/README.md" ]; then
    echo -e "${YELLOW}LUKS encryption configuration available${NC}"
    # Follow deploy/luks/README.md for encrypted storage setup
fi

# Create data directories
mkdir -p /var/lib/srt/data/captures
mkdir -p /var/lib/srt/reports
mkdir -p /var/lib/srt/logs
chown -R $SUDO_USER:$SUDO_USER /var/lib/srt

# Performance tuning for Raspberry Pi
echo -e "${YELLOW}Applying Raspberry Pi performance tuning...${NC}"
# Increase USB buffer size for SDR
echo 'net.core.rmem_max=268435456' >> /etc/sysctl.conf
echo 'net.core.wmem_max=268435456' >> /etc/sysctl.conf

# Create swapfile for memory-intensive SDR operations
if [ ! -f /swapfile ]; then
    fallocate -l 4G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# Install monitoring tools
apt-get install -y lm-sensors
sensors-detect --auto

# Final verification
echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}Deployment completed successfully!${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Reboot the Raspberry Pi: ${GREEN}sudo reboot${NC}"
echo "2. After reboot, start infrastructure: ${GREEN}sudo systemctl start srt-infra.service${NC}"
echo "3. Verify hardware detection: ${GREEN}srt info${NC}"
echo "4. Run a basic test: ${GREEN}syntax-only${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "• Start/stop services: ${GREEN}systemctl [start|stop|restart|status] srt-*.service${NC}"
echo "• View logs: ${GREEN}journalctl -u srt-infra.service -f${NC}"
echo "• Monitor hardware: ${GREEN}sensors${NC}"
echo "• Check processes: ${GREEN}htop${NC}"
echo ""
echo -e "${YELLOW}Hardware Verification Checklist:${NC}"
echo "• ALFA AWUS036H: ${GREEN}iwconfig wlan1mon${NC} (should show monitor mode)"
echo "• HackRF One: ${GREEN}hackrf_info${NC} (should detect device)"
echo "• Bluetooth: ${GREEN}bluetoothctl show${NC} (should show controller)"
echo ""
echo -e "${RED}IMPORTANT SECURITY NOTES:${NC}"
echo "- This platform is authorized ONLY for Faraday cage lab use"
echo "- All data is classified DEFENSE SECRET"
echo "- Maintain chain of custody for all logs and captures"
echo "- Test emergency kill switch weekly"
echo "- Regular system updates are mandatory"
echo ""
echo -e "${BLUE}Project Authorization: DEF-RF-2024-001${NC}"
echo -e "${BLUE}Valid Period: 2024-2026${NC}"
echo -e "${BLUE}Contact: Military Security Command${NC}"
echo -e "${BLUE}================================================================${NC}"

# Optional: Create a quick test script
cat > /usr/local/bin/srt-test-hardware << 'EOF'
#!/bin/bash
echo "=== Hardware Verification Test ==="
echo "1. ALFA AWUS036H:"
iwconfig 2>/dev/null | grep -A2 wlan | grep -i mode
echo ""
echo "2. HackRF One:"
hackrf_info 2>/dev/null | grep -E "(Found|Part|Serial)"
echo ""
echo "3. Docker Services:"
docker ps --format "table {{.Names}}\t{{.Status}}"
echo ""
echo "4. Python Environment:"
python -c "import srt; print(f'SRT version: {srt.__version__}')" 2>/dev/null || echo "SRT not installed"
EOF
chmod +x /usr/local/bin/srt-test-hardware

echo -e "${GREEN}Hardware test script created: srt-test-hardware${NC}"

# Set appropriate permissions
chown -R $SUDO_USER:$SUDO_USER /projects/sandbox/sniffer 2>/dev/null || true
chown -R $SUDO_USER:$SUDO_USER ~/sniffer 2>/dev/null || true

echo -e "${GREEN}Deployment script completed. Please review the summary above.${NC}"