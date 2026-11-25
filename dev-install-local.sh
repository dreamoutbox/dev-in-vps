#!/bin/sh
set -eu

# Resolve project directory relative to script path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

INSTALL_DIR="${HOME}/.local/bin"
BINARY_NAME="dev-vps"

# Build latest binary via build script wrapper
./build.sh "${BINARY_NAME}"

# Ensure destination directory exists
mkdir -p "${INSTALL_DIR}"

# Install binary with executable permissions (0755)
install -m 0755 "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

echo "Successfully installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
