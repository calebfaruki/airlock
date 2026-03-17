#!/bin/sh
set -e

# Configurable
INSTALL_DIR="${AIRLOCK_INSTALL_DIR:-$HOME/.local/bin}"
REPO="calebfaruki/airlock"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)  OS_NAME="linux" ;;
    darwin) OS_NAME="darwin" ;;
    *)      echo "airlock: unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64)   ARCH_NAME="amd64" ;;
    aarch64|arm64)   ARCH_NAME="arm64" ;;
    *)               echo "airlock: unsupported architecture: $ARCH"; exit 1 ;;
esac

ARTIFACT="airlock-daemon-${OS_NAME}-${ARCH_NAME}"

# Get latest release tag
if command -v curl >/dev/null 2>&1; then
    LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    DOWNLOAD="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    DOWNLOAD="wget -qO"
else
    echo "airlock: curl or wget required"
    exit 1
fi

if [ -z "$LATEST" ]; then
    echo "airlock: could not determine latest release"
    exit 1
fi

URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARTIFACT}"

# Download
echo "airlock: downloading ${ARTIFACT} (${LATEST})..."
mkdir -p "$INSTALL_DIR"
$DOWNLOAD "$INSTALL_DIR/airlock-daemon" "$URL"
chmod +x "$INSTALL_DIR/airlock-daemon"

# Verify
if ! "$INSTALL_DIR/airlock-daemon" version >/dev/null 2>&1; then
    echo "airlock: download failed or binary is incompatible"
    exit 1
fi

echo "airlock: installed to $INSTALL_DIR/airlock-daemon"

# Check PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "airlock: warning — $INSTALL_DIR is not in your PATH"
        echo "airlock: add this to your shell profile:"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
esac

# Run init
echo ""
"$INSTALL_DIR/airlock-daemon" init
