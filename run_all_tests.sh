#!/usr/bin/env bash
# sniffer-rt test runner wrapper
# Handles venv activation, root check, and delegates to Python
#
# Usage:
#   ./run_all_tests.sh              # Full test
#   ./run_all_tests.sh --syntax-only  # Syntax/config only
#   ./run_all_tests.sh --dry-run      # No live hardware
#   ./run_all_tests.sh --help         # Show help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/run_all_tests.py"

# --- Check Python 3.10+ ---
check_python() {
    local py=""
    for candidate in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$candidate" &>/dev/null; then
            py="$candidate"
            break
        fi
    done

    if [ -z "$py" ]; then
        echo "ERROR: Python 3.10+ not found" >&2
        exit 1
    fi

    local version
    version=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 10 ]; }; then
        echo "ERROR: Python 3.10+ required, found $version" >&2
        exit 1
    fi

    echo "$py"
}

# --- Activate venv if available ---
activate_venv() {
    local venv_paths=(
        "$SCRIPT_DIR/.venv/bin/activate"
        "/opt/sniffer/.venv/bin/activate"
    )
    for venv in "${venv_paths[@]}"; do
        if [ -f "$venv" ]; then
            echo "[*] Activating virtual environment: $venv"
            # shellcheck disable=SC1090
            source "$venv"
            return 0
        fi
    done
    echo "[*] No virtual environment found, using system Python"
    return 0
}

# --- Main ---
main() {
    echo "================================================"
    echo "  sniffer-rt Test Runner"
    echo "================================================"
    echo

    # Check Python version
    PYTHON=$(check_python)
    echo "[*] Using Python: $PYTHON ($($PYTHON --version 2>&1))"

    # Activate venv
    activate_venv

    # Set PYTHONPATH
    export PYTHONPATH="${SCRIPT_DIR}/src:${PYTHONPATH:-}"
    echo "[*] PYTHONPATH=$PYTHONPATH"

    # Root check warning
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] WARNING: Not running as root. Live hardware tests (monitor mode) will be skipped."
        echo "[!] Run with sudo for full hardware testing."
        echo
    fi

    # Check test script exists
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo "ERROR: $PYTHON_SCRIPT not found" >&2
        exit 1
    fi

    # Run the Python test script, passing all arguments through
    echo "[*] Running: $PYTHON $PYTHON_SCRIPT $*"
    echo
    exec "$PYTHON" "$PYTHON_SCRIPT" "$@"
}

main "$@"
