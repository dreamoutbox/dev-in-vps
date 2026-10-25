#!/bin/sh
set -eu

REPO="dreamoutbox/dev-in-vps"
INSTALL_DIR="${HOME}/.local/bin"
TARGET_NAME="dev-vps"

# Detect Operating System
RAW_OS="$(uname -s)"
case "${RAW_OS}" in
	Linux*)  OS="linux" ;;
	Darwin*) OS="darwin" ;;
	*)
		echo "Error: unsupported operating system ${RAW_OS}"
		exit 1
		;;
esac

# Detect Architecture
RAW_ARCH="$(uname -m)"
case "${RAW_ARCH}" in
	x86_64|amd64)   ARCH="amd64" ;;
	arm64|aarch64) ARCH="arm64" ;;
	*)
		echo "Error: unsupported architecture ${RAW_ARCH}"
		exit 1
		;;
esac

BINARY_NAME="dev-vps-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}"

echo "Downloading ${BINARY_NAME} from GitHub release..."
mkdir -p "${INSTALL_DIR}"
TEMP_FILE="$(mktemp "${INSTALL_DIR}/dev-vps.tmp.XXXXXX")"

if command -v curl >/dev/null 2>&1; then
	curl -fsSL "${DOWNLOAD_URL}" -o "${TEMP_FILE}"
elif command -v wget >/dev/null 2>&1; then
	wget -qO "${TEMP_FILE}" "${DOWNLOAD_URL}"
else
	echo "Error: neither curl nor wget found."
	exit 1
fi

chmod +x "${TEMP_FILE}"
mv "${TEMP_FILE}" "${INSTALL_DIR}/${TARGET_NAME}"

echo "Successfully installed dev-vps to ${INSTALL_DIR}/${TARGET_NAME}"

# Verify PATH
case ":${PATH}:" in
	*:"${INSTALL_DIR}":*) ;;
	*)
		echo "Note: ${INSTALL_DIR} is not in your PATH."
		echo "Add it with: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
		;;
esac
