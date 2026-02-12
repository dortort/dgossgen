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

echo "Installing ${BINARY} ${VERSION} (${TARGET})..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

$fetch "$URL" | tar xz -C "$TMPDIR"

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
