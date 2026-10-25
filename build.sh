#!/bin/sh
set -eu

# Resolve project directory relative to script path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

OUTPUT_BINARY="${1:-dev-vps}"

echo "Building dev-vps -> ${OUTPUT_BINARY}..."
go build -trimpath -ldflags="-s -w" -o "${OUTPUT_BINARY}" ./cmd/dev-vps

echo "Build successful: ${OUTPUT_BINARY}"
