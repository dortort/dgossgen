#!/bin/sh
# Usage: curl -fsSL https://raw.githubusercontent.com/dortort/dgossgen/main/install.sh | sh
set -e

REPO="dortort/dgossgen"
BINARY="dgossgen"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux)  os="unknown-linux" ;;
  Darwin) os="apple-darwin" ;;
  *)      echo "error: unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  arch="x86_64" ;;
  aarch64|arm64)  arch="aarch64" ;;
  *)              echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Pick target triple
if [ "$os" = "unknown-linux" ] && [ "$arch" = "x86_64" ]; then
  TARGET="${arch}-${os}-musl"
else
  TARGET="${arch}-${os}"
  if [ "$os" = "unknown-linux" ]; then
    TARGET="${arch}-${os}-gnu"
  fi
fi

# Get latest version tag
if command -v curl >/dev/null 2>&1; then
  fetch="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  fetch="wget -qO-"
else
  echo "error: curl or wget required" >&2; exit 1
fi

VERSION=$($fetch "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')

if [ -z "$VERSION" ]; then
  echo "error: could not determine latest version" >&2; exit 1
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}-${TARGET}.tar.gz"
SHA_URL="${URL}.sha256"

echo "Installing ${BINARY} ${VERSION} (${TARGET})..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

ARCHIVE="${TMPDIR}/${BINARY}-${TARGET}.tar.gz"
CHECKSUM_FILE="${ARCHIVE}.sha256"

$fetch "$URL" > "$ARCHIVE"
$fetch "$SHA_URL" > "$CHECKSUM_FILE"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha=$(sha256sum "$ARCHIVE" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual_sha=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
else
  echo "error: sha256sum or shasum is required for checksum verification" >&2
  exit 1
fi

expected_sha=$(awk '{print $1}' "$CHECKSUM_FILE" | head -1)
if [ -z "$expected_sha" ]; then
  echo "error: release checksum file is empty or invalid" >&2
  exit 1
fi

if [ "$actual_sha" != "$expected_sha" ]; then
  echo "error: checksum verification failed for downloaded archive" >&2
  exit 1
fi

tar xz -f "$ARCHIVE" -C "$TMPDIR"

if [ ! -f "${TMPDIR}/${BINARY}" ]; then
  echo "error: binary not found in archive" >&2; exit 1
fi

chmod +x "${TMPDIR}/${BINARY}"

if [ -w "$INSTALL_DIR" ]; then
  mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
${INSTALL_DIR}/${BINARY} --version
