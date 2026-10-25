#!/bin/sh
set -eu

# Resolve project directory relative to script path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

OUTPUT_BINARY="${1:-dev-vps}"
VERSION="$(cat VERSION 2>/dev/null || echo "0.1.0")"

echo "Building dev-vps (v${VERSION}) -> ${OUTPUT_BINARY}..."
go build -trimpath -ldflags="-s -w -X github.com/dreamoutbox/dev-in-vps/pkg/version.Version=${VERSION}" -o "${OUTPUT_BINARY}" ./cmd/dev-vps

echo "Build successful: ${OUTPUT_BINARY}"
