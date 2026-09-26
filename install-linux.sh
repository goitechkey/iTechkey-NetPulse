#!/usr/bin/env bash
# ============================================================================
#  iTechkey NetPulse — Linux/macOS Installer & Launcher
#  Version : 1.0.0
#  Author  : iTechkey
#  Contact : admin@itechkey.com
# ============================================================================
#
#  Usage:
#    chmod +x install-linux.sh
#    ./install-linux.sh
#
# ============================================================================

set -e

# ---- Config ----
APP_NAME="iTechkey NetPulse"
APP_VERSION="1.0.0"
VENV_DIR="venv"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=9
PORT=5000

# ---- Colors ----
if [ -t 1 ]; then
    G="\033[92m"   # green
    Y="\033[93m"   # yellow
    R="\033[91m"   # red
    B="\033[94m"   # blue
    C="\033[96m"   # cyan
    D="\033[0m"    # reset
    BOLD="\033[1m"
else
    G=""; Y=""; R=""; B=""; C=""; D=""; BOLD=""
fi

ok()    { printf "  ${G}✓${D} %s\n" "$1"; }
warn()  { printf "  ${Y}!${D} %s\n" "$1"; }
err()   { printf "  ${R}✗${D} %s\n" "$1"; }
info()  { printf "  ${C}→${D} %s\n" "$1"; }
head()  {
    printf "\n${B}%s\n  %s\n%s${D}\n\n" \
           "$(printf '=%.0s' {1..68})" "$1" \
           "$(printf '=%.0s' {1..68})"
}

# ---- Banner ----
clear 2>/dev/null || true
printf "\n"
printf "${B}  +----------------------------------------------------------------+${D}\n"
printf "${B}  |                                                                |${D}\n"
printf "${B}  |      ${APP_NAME}  —  Linux/macOS Installer        |${D}\n"
printf "${B}  |                    Version %s                               |${D}\n" "$APP_VERSION"
printf "${B}  |                                                                |${D}\n"
printf "${B}  +----------------------------------------------------------------+${D}\n"
printf "\n"

# ---- Step 0: Working directory ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
info "Working directory: $SCRIPT_DIR"

# Required files check
REQUIRED_FILES=(
    "itechkey_monitor.py"
    "itechkey_snmp.py"
    "itechkey_setup.py"
    "requirements.txt"
)

head "Checking required files"
MISSING=()
for f in "${REQUIRED_FILES[@]}"; do
    if [ -f "$f" ]; then
        ok "Found: $f"
    else
        err "Missing: $f"
        MISSING+=("$f")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo ""
    err "Required files missing. Please extract the ZIP properly."
    echo ""
    read -rp "Press Enter to exit... " _
    exit 1
fi

# Logo check
if [ -f "static/itechkey-logo.png" ]; then
    ok "Found: static/itechkey-logo.png"
else
    warn "Logo missing: static/itechkey-logo.png"
    warn "App will run without logo. Add it later and restart."
    mkdir -p static
fi

# ---- Step 1: Python check ----
head "Checking Python installation"

PYTHON_CMD=""
for cmd in python3 python python3.12 python3.11 python3.10 python3.9; do
    if command -v "$cmd" >/dev/null 2>&1; then
        if "$cmd" --version >/dev/null 2>&1; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    err "Python not found!"
    echo ""
    echo "  Please install Python 3.9 or higher:"
    echo ""
    echo "    ${C}Debian/Ubuntu:${D}  sudo apt update && sudo apt install python3 python3-pip python3-venv"
    echo "    ${C}RHEL/CentOS:${D}    sudo yum install python3 python3-pip"
    echo "    ${C}Fedora:${D}         sudo dnf install python3 python3-pip"
    echo "    ${C}Arch:${D}           sudo pacman -S python python-pip"
    echo "    ${C}macOS:${D}          brew install python3"
    echo ""
    read -rp "Press Enter to exit... " _
    exit 1
fi

PY_VER=$("$PYTHON_CMD" --version 2>&1 | awk '{print $2}')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

ok "$PYTHON_CMD detected: $PY_VER"

if [ "$PY_MAJOR" -lt "$MIN_PYTHON_MAJOR" ] || \
   { [ "$PY_MAJOR" -eq "$MIN_PYTHON_MAJOR" ] && [ "$PY_MINOR" -lt "$MIN_PYTHON_MINOR" ]; }; then
    err "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ required, found $PY_VER"
    read -rp "Press Enter to exit... " _
    exit 1
fi
ok "Python version OK"

# ---- Step 2: Check python3-venv availability ----
head "Verifying venv module"

if ! "$PYTHON_CMD" -c "import venv" >/dev/null 2>&1; then
    err "Python venv module not available"
    echo ""
    echo "  Install it:"
    echo "    ${C}Ubuntu/Debian:${D}  sudo apt install python3-venv"
    echo "    ${C}RHEL/CentOS:${D}    sudo yum install python3-venv"
    echo ""
    read -rp "Press Enter to exit... " _
    exit 1
fi
ok "venv module available"

# ---- Step 3: Virtual environment ----
head "Setting up virtual environment"

if [ -f "$VENV_DIR/bin/python" ]; then
    ok "Virtual environment already exists: $VENV_DIR"
else
    info "Creating virtual environment: $VENV_DIR"
    "$PYTHON_CMD" -m venv "$VENV_DIR"
    ok "Virtual environment created"
fi

VENV_PYTHON="$SCRIPT_DIR/$VENV_DIR/bin/python"
VENV_PIP="$SCRIPT_DIR/$VENV_DIR/bin/pip"

if [ ! -f "$VENV_PYTHON" ]; then
    err "Virtual environment python not found: $VENV_PYTHON"
    read -rp "Press Enter to exit... " _
    exit 1
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Virtual environment activated"

# ---- Step 4: Install dependencies ----
head "Installing Python dependencies"

info "Upgrading pip..."
"$VENV_PYTHON" -m pip install --upgrade pip --quiet

info "Installing from requirements.txt (may take a minute)..."
"$VENV_PIP" install -r requirements.txt --quiet
ok "All dependencies installed"

# ---- Step 4b: System package for ping ----
head "Checking system ping utility"

if command -v ping >/dev/null 2>&1; then
    ok "System ping available"
else
    warn "System ping not found (fallback will use Python ping3 library)"
fi

# ---- Step 5: Setup wizard ----
head "Running first-time setup wizard"

if [ -f ".env" ]; then
    ok "Config already exists (.env)"
    info "Skipping setup wizard. Delete .env to reconfigure."
else
    info "Launching setup wizard..."
    echo ""
    "$VENV_PYTHON" itechkey_setup.py
    ok "Setup complete"
fi

# ---- Step 6: Firewall (Linux only) ----
head "Firewall configuration (optional)"

if [[ "$(uname -s)" == "Linux" ]]; then
    if command -v ufw >/dev/null 2>&1; then
        if sudo -n true 2>/dev/null; then
            if sudo ufw status 2>/dev/null | grep -q "$PORT"; then
                ok "ufw rule already exists for port $PORT"
            else
                info "Adding ufw rule for port $PORT..."
                sudo ufw allow "$PORT/tcp" >/dev/null 2>&1 && \
                    ok "ufw rule added" || warn "Could not add ufw rule"
            fi
        else
            info "Skipping ufw (sudo required). Manual command:"
            echo "     ${C}sudo ufw allow $PORT/tcp${D}"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        info "firewalld detected. Manual command (if needed):"
        echo "     ${C}sudo firewall-cmd --permanent --add-port=$PORT/tcp${D}"
        echo "     ${C}sudo firewall-cmd --reload${D}"
    else
        info "No ufw or firewalld detected — skipping firewall config"
    fi
else
    info "macOS — firewall handled by System Preferences"
fi

# ---- Step 7: Launch app ----
head "Starting ${APP_NAME}"

# Get LAN IP
LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || \
         ipconfig getifaddr en0 2>/dev/null || \
         ipconfig getifaddr en1 2>/dev/null || \
         echo "localhost")
[ -z "$LAN_IP" ] && LAN_IP="localhost"

echo ""
printf "${G}  +----------------------------------------------------------------+${D}\n"
printf "${G}  |                    Setup Complete!                             |${D}\n"
printf "${G}  +----------------------------------------------------------------+${D}\n"
echo ""
printf "    Local URL      : ${C}http://localhost:%s${D}\n" "$PORT"
printf "    Network URL    : ${C}http://%s:%s${D}\n" "$LAN_IP" "$PORT"
printf "    Login          : ${Y}admin / admin${D}\n"
echo ""
printf "    ${Y}IMPORTANT: Change password immediately in Settings!${D}\n"
echo ""
printf "    Press ${BOLD}Ctrl+C${D} to stop the monitor.\n"
echo ""

sleep 2

# Handle Ctrl+C gracefully
cleanup() {
    echo ""
    ok "Shutting down..."
    exit 0
}
trap cleanup SIGINT SIGTERM

"$VENV_PYTHON" itechkey_monitor.py

ok "Monitor stopped."