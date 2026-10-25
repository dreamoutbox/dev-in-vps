#!/bin/sh
set -eu

# Resolve project root relative to script location
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

DIST_DIR="${PROJECT_ROOT}/dist"
rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

VERSION="$(tr -d 'v \t\r\n' < VERSION 2>/dev/null || echo "0.1.0")"
LDFLAGS="-s -w -X github.com/dreamoutbox/dev-in-vps/pkg/version.Version=${VERSION}"

TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"

for target in $TARGETS; do
	TARGET_OS="$(echo "$target" | cut -d/ -f1)"
	TARGET_ARCH="$(echo "$target" | cut -d/ -f2)"
	OUTPUT_NAME="dev-vps-${TARGET_OS}-${TARGET_ARCH}"

	echo "Building ${OUTPUT_NAME}..."
	CGO_ENABLED=0 GOOS="${TARGET_OS}" GOARCH="${TARGET_ARCH}" go build -trimpath -ldflags="${LDFLAGS}" -o "${DIST_DIR}/${OUTPUT_NAME}" ./cmd/dev-vps
done

# Generate SHA256 checksums
cd "${DIST_DIR}"
sha256sum dev-vps-* > checksums.txt
cd "${PROJECT_ROOT}"

echo "Release artifacts built successfully in ${DIST_DIR}"
