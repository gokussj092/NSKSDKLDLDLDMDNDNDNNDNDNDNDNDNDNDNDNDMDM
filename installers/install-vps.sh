#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git"
BOT_BRANCH="feat/telegram-cloud-decoder-parity"
SERVICE_NAME="spdecode-telegram"
CALLER_USER="$(id -un)"
CALLER_HOME="$(getent passwd "$CALLER_USER" 2>/dev/null | cut -d: -f6)"
CALLER_HOME="${CALLER_HOME:-$HOME}"
TARGET_DIR="${SPDECODE_HOME:-$CALLER_HOME/spdecode-telegram}"
MANAGER_PATH="/usr/local/bin/spdecode-telegram"

if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    echo "ERROR: do not run the whole installer with sudo."
    echo "Run: bash installers/install-vps.sh"
    echo "The installer requests sudo only for system package/service operations."
    exit 2
fi

run_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

echo "============================================================"
echo " SP-DECODE TELEGRAM BOT - VPS INSTALLER"
echo "============================================================"

echo "[1/9] Installing system packages..."
if command -v apt-get >/dev/null 2>&1; then
    run_root apt-get update
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        git curl ca-certificates util-linux \
        python3 python3-venv python3-pip \
        php-cli \
        build-essential pkg-config libffi-dev libssl-dev
elif command -v dnf >/dev/null 2>&1; then
    run_root dnf install -y \
        git curl ca-certificates util-linux \
        python3 python3-pip \
        php-cli \
        gcc gcc-c++ make pkgconf-pkg-config libffi-devel openssl-devel
elif command -v yum >/dev/null 2>&1; then
    run_root yum install -y \
        git curl ca-certificates util-linux \
        python3 python3-pip \
        php-cli \
        gcc gcc-c++ make pkgconfig libffi-devel openssl-devel
else
    echo "ERROR: unsupported package manager. Debian/Ubuntu, Fedora/RHEL and compatible systems are supported."
    exit 1
fi

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "Node.js/npm not detected; installing distribution packages..."
    if command -v apt-get >/dev/null 2>&1; then
        run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs npm
    elif command -v dnf >/dev/null 2>&1; then
        run_root dnf install -y nodejs npm
    else
        run_root yum install -y nodejs npm
    fi
else
    echo "Node.js $(node --version) and npm $(npm --version) already available."
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "ERROR: systemd/systemctl is required by the VPS activator."
    exit 1
fi

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PULL_CHECKOUT=0
if [[ -f "$SOURCE_ROOT/main.py" && -f "$SOURCE_ROOT/installers/configure.py" ]]; then
    PROJECT_DIR="$SOURCE_ROOT"
    echo "[2/9] Using current repository: $PROJECT_DIR"
else
    PROJECT_DIR="$TARGET_DIR"
    if [[ ! -d "$PROJECT_DIR/.git" ]]; then
        echo "[2/9] Cloning SP-DECODE into $PROJECT_DIR..."
        git clone --single-branch --branch "$BOT_BRANCH" "$REPO_URL" "$PROJECT_DIR"
    else
        echo "[2/9] Existing repository found at $PROJECT_DIR."
        PULL_CHECKOUT=1
    fi
fi

cd "$PROJECT_DIR"
PROJECT_DIR="$(pwd -P)"
if [[ -e "$MANAGER_PATH" || -L "$MANAGER_PATH" ]]; then
    if [[ "$(readlink -f "$MANAGER_PATH")" != "$PROJECT_DIR/scripts/spdecode-vps.sh" ]]; then
        echo "ERROR: $MANAGER_PATH already points to a different installation." >&2
        exit 1
    fi
    exec "$MANAGER_PATH" update
fi
exec 9>"$(git rev-parse --absolute-git-dir)/spdecode-telegram.lock"
if ! flock -n 9; then
    echo "ERROR: another bot maintenance command is running." >&2
    exit 1
fi
if (( PULL_CHECKOUT )); then
    git pull --ff-only
fi

echo "[3/9] Creating Python virtual environment..."
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel

echo "[4/9] Installing Python dependencies..."
.venv/bin/python -m pip install -r requirements.txt

echo "[5/9] Installing Node.js decoder dependencies..."
npm ci --omit=dev

echo "[6/9] Configuring Telegram access..."
if [[ ! -f config.json ]]; then
    (umask 077; .venv/bin/python installers/configure.py </dev/tty)
fi
chmod 600 config.json

echo "[7/9] Checking bot startup..."
.venv/bin/python -c 'import main; main.validate_startup()'

echo "[8/9] Installing systemd service..."
chmod +x scripts/spdecode-vps.sh

SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
run_root tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=SP-DECODE Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CALLER_USER
WorkingDirectory=$PROJECT_DIR
ExecStart="$PROJECT_DIR/.venv/bin/python" "$PROJECT_DIR/main.py"
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

run_root ln -sfn "$PROJECT_DIR/scripts/spdecode-vps.sh" "$MANAGER_PATH"
run_root systemctl daemon-reload
run_root systemctl enable "$SERVICE_NAME"

echo "[9/9] Starting SP-DECODE..."
run_root systemctl restart "$SERVICE_NAME"

echo
echo "Installation complete."
echo "Project: $PROJECT_DIR"
echo "Service: $SERVICE_NAME"
echo
echo "Management commands:"
echo "  spdecode-telegram status"
echo "  spdecode-telegram start"
echo "  spdecode-telegram stop"
echo "  spdecode-telegram restart"
echo "  spdecode-telegram logs"
echo "  spdecode-telegram config"
echo "  spdecode-telegram update"
echo "  spdecode-telegram validate"
echo
run_root systemctl --no-pager --full status "$SERVICE_NAME" || true
