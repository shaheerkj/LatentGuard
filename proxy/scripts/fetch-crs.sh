#!/usr/bin/env bash
# fetch-crs.sh — pull the latest OWASP Core Rule Set into proxy/rules/90-crs.
# Safe to re-run; existing 90-crs is replaced.

set -euo pipefail

CRS_VERSION="${CRS_VERSION:-v4.7.0}"
DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/rules/90-crs"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "fetching OWASP CRS ${CRS_VERSION}..."
curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
    | tar -xz -C "$TMP_DIR"

SRC_DIR="$TMP_DIR/coreruleset-${CRS_VERSION#v}"

rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"

# crs-setup.conf.example becomes crs-setup.conf — required by CRS.
cp "$SRC_DIR/crs-setup.conf.example" "$DEST_DIR/crs-setup.conf"
cp -r "$SRC_DIR/rules" "$DEST_DIR/rules"

echo "OWASP CRS ${CRS_VERSION} installed at $DEST_DIR"
echo "Files:"
find "$DEST_DIR" -name '*.conf' | head -20
