#!/usr/bin/env bash
# Deploy sniffer-rt to Raspberry Pi
# Usage: ./deploy_to_pi.sh <pi-host> <pi-user> [ssh-key-path]
#        ./deploy_to_pi.sh --dry-run <pi-host> <pi-user>
#        ./deploy_to_pi.sh --help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Defaults ---
DRY_RUN=false
PI_HOST=""
PI_USER=""
SSH_KEY=""
SSH_PORT=2222
REMOTE_DIR="/opt/sniffer"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <pi-host> <pi-user> [ssh-key-path]

Deploy sniffer-rt to a Raspberry Pi over SSH.

Arguments:
  pi-host          Hostname or IP of the Raspberry Pi
  pi-user          SSH username on the Pi (e.g., srt, pi)
  ssh-key-path     Optional path to SSH private key

Options:
  --dry-run        Show commands without executing them
  --port PORT      SSH port (default: 2222)
  --remote-dir DIR Remote install directory (default: /opt/sniffer)
  --help           Show this help message

Examples:
  $(basename "$0") 192.168.1.100 srt ~/.ssh/id_ed25519
  $(basename "$0") --dry-run pi-host.local pi
  $(basename "$0") --port 22 192.168.1.100 root

Steps performed:
  1. Run local syntax validation (run_all_tests.py --syntax-only)
  2. rsync project to Pi (excluding .git, __pycache__, .venv, data/)
  3. SSH to Pi: run deploy/setup.sh
  4. SSH to Pi: install Python package in venv
  5. SSH to Pi: copy udev rules, reload
  6. SSH to Pi: enable systemd services
  7. SSH to Pi: run srt selftest for verification
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info() {
    echo -e "${GREEN}[+]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    else
        "$@"
    fi
}

ssh_cmd() {
    local ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p "$SSH_PORT")
    if [ -n "$SSH_KEY" ]; then
        ssh_opts+=(-i "$SSH_KEY")
    fi
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} ssh ${ssh_opts[*]} ${PI_USER}@${PI_HOST} $*"
    else
        ssh "${ssh_opts[@]}" "${PI_USER}@${PI_HOST}" "$@"
    fi
}

rsync_cmd() {
    local ssh_opts="-o StrictHostKeyChecking=accept-new -p $SSH_PORT"
    if [ -n "$SSH_KEY" ]; then
        ssh_opts="$ssh_opts -i $SSH_KEY"
    fi
    local rsync_args=(
        -avz --delete
        --exclude='.git'
        --exclude='__pycache__'
        --exclude='.venv'
        --exclude='data/'
        --exclude='*.pyc'
        --exclude='.mypy_cache'
        --exclude='.pytest_cache'
        -e "ssh $ssh_opts"
        "$SCRIPT_DIR/"
        "${PI_USER}@${PI_HOST}:${REMOTE_DIR}/"
    )
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} rsync ${rsync_args[*]}"
    else
        rsync "${rsync_args[@]}"
    fi
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

parse_args() {
    local positional=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --port)
                SSH_PORT="$2"
                shift 2
                ;;
            --remote-dir)
                REMOTE_DIR="$2"
                shift 2
                ;;
            --help|-h)
                usage
                ;;
            -*)
                error "Unknown option: $1"
                usage
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    if [ ${#positional[@]} -lt 2 ]; then
        error "Missing required arguments: <pi-host> <pi-user>"
        echo
        usage
    fi

    PI_HOST="${positional[0]}"
    PI_USER="${positional[1]}"
    if [ ${#positional[@]} -ge 3 ]; then
        SSH_KEY="${positional[2]}"
    fi
}

# ---------------------------------------------------------------------------
# Deployment steps
# ---------------------------------------------------------------------------

step_local_validation() {
    info "Step 1: Running local syntax validation..."
    if [ -f "$SCRIPT_DIR/run_all_tests.py" ]; then
        run_cmd python3 "$SCRIPT_DIR/run_all_tests.py" --syntax-only
        if [ $? -ne 0 ] && [ "$DRY_RUN" = false ]; then
            error "Local validation failed. Fix errors before deploying."
            exit 1
        fi
    else
        warn "run_all_tests.py not found, skipping local validation"
    fi
}

step_rsync() {
    info "Step 2: Syncing project to Pi ($PI_HOST:$REMOTE_DIR)..."
    # WARNING: SSH is configured with StrictHostKeyChecking=accept-new which will
    # auto-accept the Pi's host key on first connection without verification.
    # If deploying over an untrusted network, manually verify the host fingerprint
    # by running: ssh-keyscan -p $SSH_PORT $PI_HOST
    warn "SSH will auto-accept the Pi's host key on first connection. Verify the host fingerprint if deploying over an untrusted network."
    rsync_cmd
}

step_setup() {
    info "Step 3: Running deploy/setup.sh on Pi..."
    ssh_cmd "sudo bash $REMOTE_DIR/deploy/setup.sh"
}

step_install_package() {
    info "Step 4: Installing Python package in venv on Pi..."
    ssh_cmd "$REMOTE_DIR/.venv/bin/pip install -e $REMOTE_DIR"
}

step_udev_rules() {
    info "Step 5: Copying udev rules and reloading..."
    ssh_cmd "sudo cp $REMOTE_DIR/deploy/udev/99-srt-export.rules /etc/udev/rules.d/ && sudo udevadm control --reload-rules && sudo udevadm trigger"
}

step_systemd() {
    info "Step 6: Enabling systemd services..."
    ssh_cmd "sudo systemctl daemon-reload && sudo systemctl enable srt-infra.service srt-probe.service srt-watchdog.service"
}

step_selftest() {
    info "Step 7: Running remote selftest..."
    ssh_cmd "$REMOTE_DIR/.venv/bin/srt selftest"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    if [ $# -eq 0 ]; then
        usage
    fi

    parse_args "$@"

    echo "================================================"
    echo "  sniffer-rt Deployment to Raspberry Pi"
    echo "================================================"
    echo
    info "Target: ${PI_USER}@${PI_HOST}:${SSH_PORT}"
    info "Remote directory: $REMOTE_DIR"
    if [ -n "$SSH_KEY" ]; then
        info "SSH key: $SSH_KEY"
    fi
    if [ "$DRY_RUN" = true ]; then
        warn "DRY-RUN mode: commands will be shown but not executed"
    fi
    echo

    step_local_validation
    echo
    step_rsync
    echo
    step_setup
    echo
    step_install_package
    echo
    step_udev_rules
    echo
    step_systemd
    echo
    step_selftest
    echo

    echo "================================================"
    if [ "$DRY_RUN" = true ]; then
        info "Dry-run complete. No changes were made."
    else
        info "Deployment complete!"
        info "Services can be started with: ssh ${PI_USER}@${PI_HOST} -p ${SSH_PORT} 'sudo systemctl start srt-infra srt-probe'"
    fi
    echo "================================================"
}

main "$@"
