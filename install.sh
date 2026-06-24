#!/bin/bash
set -euo pipefail

REPO="Sysrous/soho-unlock"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/soho-unlock"
CONFIG_FILE="$CONFIG_DIR/config.toml"
BIN_NAME="soho-unlock"
SERVICE_FILE="/etc/systemd/system/soho-unlock.service"

# The box may point resolv.conf at 127.0.0.1 (our own DNS), which is down while we
# restart, and some hosts block outbound UDP/53. If GitHub can't be resolved, drop
# in a public TCP-capable resolver so the download works. The agent re-applies its
# own DNS on the next start.
ensure_dns() {
    if getent hosts raw.githubusercontent.com >/dev/null 2>&1; then
        return 0
    fi
    echo "Name resolution is down — setting temporary resolver 1.1.1.1 ..."
    chattr -i /etc/resolv.conf 2>/dev/null || true
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions use-vc\n' > /etc/resolv.conf
}

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
    ensure_dns
    if [[ "$VERSION" == "latest" ]]; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    fi
    echo "Upgrading to $VERSION ..."
    OLD_VER=$("$INSTALL_DIR/$BIN_NAME" --version 2>/dev/null || echo "unknown")
    TMP=$(mktemp)
    curl -fSL -o "$TMP" "https://github.com/$REPO/releases/download/$VERSION/$BINARY"
    chmod +x "$TMP"
    systemctl stop soho-unlock 2>/dev/null || rc-service soho-unlock stop 2>/dev/null || true
    mv "$TMP" "$INSTALL_DIR/$BIN_NAME"
    # Also update ut
    UT_ARCH="amd64"; [[ "$ARCH" == aarch64 || "$ARCH" == arm64 ]] && UT_ARCH="arm64"
    curl -fSL -o "$INSTALL_DIR/ut" "https://github.com/oneclickvirt/UnlockTests/releases/latest/download/ut-linux-${UT_ARCH}" && chmod +x "$INSTALL_DIR/ut" && echo "ut updated" || echo "ut update failed (non-fatal)"
    # A file swap alone leaves the old process resident in memory (still holding
    # :53), so the new binary never actually takes over. Kill any straggler, then
    # start fresh so the upgrade really applies.
    pkill -x soho-unlock 2>/dev/null || true
    sleep 1
    systemctl start soho-unlock 2>/dev/null || rc-service soho-unlock start 2>/dev/null || true
    sleep 1
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
    x86_64|amd64)   BINARY="soho-unlock-linux-amd64"; UT_BINARY="ut-linux-amd64" ;;
    aarch64|arm64)   BINARY="soho-unlock-linux-arm64"; UT_BINARY="ut-linux-arm64" ;;
    *)               echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# --- resolve version ---
ensure_dns
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

# --- install ut (unlock test tool) ---
UT_URL="https://github.com/oneclickvirt/UnlockTests/releases/latest/download/$UT_BINARY"
echo "Downloading ut ($UT_BINARY) ..."
if curl -fSL -o "$INSTALL_DIR/ut" "$UT_URL"; then
    chmod +x "$INSTALL_DIR/ut"
    echo "Installed $INSTALL_DIR/ut"
else
    echo "Warning: ut download failed (non-fatal, unlock test won't work)"
fi

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

# Map install --type to config node_type
case "$NODE_TYPE" in
    dns|unlock) CFG_NODE_TYPE="unlock" ;;
    transit)    CFG_NODE_TYPE="transit" ;;
    *)          CFG_NODE_TYPE="$NODE_TYPE" ;;
esac

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
node_type = "$CFG_NODE_TYPE"
heartbeat_secs = 30
TOML

echo "Config written to $CONFIG_FILE"

# --- free ports 53/443 from legacy unlock stacks ---
# soho-unlock replaces dnsmasq + sniproxy (+ smartdns). If any are still running
# they hold :53/:443 and soho-unlock's DNS/SNI bind fails (silently), so unlock
# never works. Stop, disable, and kill stragglers so soho-unlock can own the
# ports. (For full package removal, run your dnsmasq_sniproxy uninstaller.)
echo "Freeing ports 53/443 from legacy DNS/SNI services if present..."
for svc in dnsmasq sniproxy smartdns mosdns; do
    systemctl stop "$svc" 2>/dev/null && echo "  stopped $svc" || true
    systemctl disable "$svc" 2>/dev/null || true
    pkill -x "$svc" 2>/dev/null || true
done

# --- open firewall ports 53 (DNS) and 443 (SNI) ---
# The agent serves DNS on :53 and the SNI relay on :443. If a host firewall is
# active it must allow them inbound or the node is unreachable (cloud security
# groups are separate — open 53/tcp+udp and 443/tcp there too if you use them).
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    ufw allow 53 >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    echo "ufw: allowed 53 and 443"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=53/tcp --add-port=53/udp --add-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "firewalld: allowed 53 and 443"
fi

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
