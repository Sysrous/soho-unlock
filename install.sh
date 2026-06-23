#!/bin/bash
set -euo pipefail

REPO="Sysrous/soho-unlock"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/soho-unlock"
CONFIG_FILE="$CONFIG_DIR/config.toml"
BIN_NAME="soho-unlock"
SERVICE_FILE="/etc/systemd/system/soho-unlock.service"

# --- uninstall ---
if [[ "${1:-}" == "uninstall" ]]; then
    echo "Uninstalling soho-unlock..."
    systemctl stop soho-unlock 2>/dev/null || true
    systemctl disable soho-unlock 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -f "$INSTALL_DIR/$BIN_NAME"
    systemctl daemon-reload
    echo "Removed binary and service."
    echo "Config preserved at $CONFIG_DIR (delete manually if not needed)"
    exit 0
fi

# --- upgrade ---
if [[ "${1:-}" == "upgrade" ]]; then
    VERSION="${2:-latest}"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)   BINARY="soho-unlock-linux-amd64" ;;
        aarch64|arm64)  BINARY="soho-unlock-linux-arm64" ;;
        *)              echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    if [[ "$VERSION" == "latest" ]]; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    fi
    echo "Upgrading to $VERSION ..."
    OLD_VER=$("$INSTALL_DIR/$BIN_NAME" --version 2>/dev/null || echo "unknown")
    TMP=$(mktemp)
    curl -fSL -o "$TMP" "https://github.com/$REPO/releases/download/$VERSION/$BINARY"
    chmod +x "$TMP"
    systemctl stop soho-unlock 2>/dev/null || true
    mv "$TMP" "$INSTALL_DIR/$BIN_NAME"
    systemctl start soho-unlock
    NEW_VER=$("$INSTALL_DIR/$BIN_NAME" --version 2>/dev/null || echo "$VERSION")
    echo "Upgraded: $OLD_VER -> $NEW_VER (config preserved)"
    exit 0
fi

# --- parse args ---
PANEL_URL=""
GRPC_ADDR=""
NODE_ID=""
TOKEN=""
NODE_TYPE="dns"
VERSION="latest"
UNLOCK_TARGET=""

usage() {
    echo "Usage:"
    echo "  Install:   bash <(curl -sL URL) --panel URL --node-id N --token T [--grpc URL] [--type dns|transit] [--target IP] [--version vX.Y.Z]"
    echo "  Upgrade:   bash <(curl -sL URL) upgrade [vX.Y.Z]"
    echo "  Uninstall: bash <(curl -sL URL) uninstall"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --panel)    PANEL_URL="$2"; shift 2 ;;
        --grpc)     GRPC_ADDR="$2"; shift 2 ;;
        --node-id)  NODE_ID="$2"; shift 2 ;;
        --token)    TOKEN="$2"; shift 2 ;;
        --type)     NODE_TYPE="$2"; shift 2 ;;
        --target)   UNLOCK_TARGET="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        *)          echo "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$PANEL_URL" || -z "$NODE_ID" || -z "$TOKEN" ]]; then
    echo "Error: --panel, --node-id, --token are required"
    usage
fi

# --- detect arch ---
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   BINARY="soho-unlock-linux-amd64" ;;
    aarch64|arm64)   BINARY="soho-unlock-linux-arm64" ;;
    *)               echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# --- resolve version ---
if [[ "$VERSION" == "latest" ]]; then
    echo "Fetching latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    if [[ -z "$VERSION" ]]; then
        echo "Failed to fetch latest version, falling back to v0.1.1"
        VERSION="v0.1.1"
    fi
fi
echo "Version: $VERSION"

# --- download ---
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY"
echo "Downloading $DOWNLOAD_URL ..."
TMP=$(mktemp)
if ! curl -fSL -o "$TMP" "$DOWNLOAD_URL"; then
    echo "Download failed. Check version and network."
    rm -f "$TMP"
    exit 1
fi
chmod +x "$TMP"

# --- stop existing service ---
if systemctl is-active --quiet soho-unlock 2>/dev/null; then
    echo "Stopping existing soho-unlock service..."
    systemctl stop soho-unlock
fi

# --- install binary ---
mkdir -p "$INSTALL_DIR"
mv "$TMP" "$INSTALL_DIR/$BIN_NAME"
echo "Installed $INSTALL_DIR/$BIN_NAME"

# --- generate config ---
mkdir -p "$CONFIG_DIR"
if [[ -f "$CONFIG_FILE" ]]; then
    echo "Config already exists at $CONFIG_FILE, backing up..."
    cp "$CONFIG_FILE" "$CONFIG_FILE.bak.$(date +%s)"
fi

# default unlock target placeholder
if [[ -z "$UNLOCK_TARGET" ]]; then
    UNLOCK_TARGET="0.0.0.0"
fi

cat > "$CONFIG_FILE" <<TOML
[server]
dns_listen = "0.0.0.0:53"
sni_listen = "0.0.0.0:443"
panel_listen = "127.0.0.1:9190"

[auth]
token = "change-me"

[upstream]
dns = ["1.1.1.1", "8.8.8.8"]

[unlock]
target = "$UNLOCK_TARGET"

[firewall]
enabled = false

[panel]
url = "$PANEL_URL"
grpc_addr = "$GRPC_ADDR"
node_id = $NODE_ID
token = "$TOKEN"
heartbeat_secs = 30
TOML

echo "Config written to $CONFIG_FILE"

# --- install systemd service ---
"$INSTALL_DIR/$BIN_NAME" --install
systemctl daemon-reload
systemctl enable --now soho-unlock

echo ""
echo "=== soho-unlock installed ==="
echo "Binary:  $INSTALL_DIR/$BIN_NAME"
echo "Config:  $CONFIG_FILE"
echo "Service: systemctl status soho-unlock"
echo ""
echo "Edit $CONFIG_FILE to set [unlock] target and [firewall] if needed, then:"
echo "  systemctl restart soho-unlock"
