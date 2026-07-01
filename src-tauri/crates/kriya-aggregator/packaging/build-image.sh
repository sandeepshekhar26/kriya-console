#!/usr/bin/env bash
# build-image.sh — build the minimal distroless kriyad OCI image (SHIP-IMG) from the static musl binary
# produced by build/build-static.sh. No in-image compile: COPY the prebuilt static binary → distroless.
#
#   ARCH=x86_64  bash build-image.sh    # linux/amd64 (default)
#   ARCH=aarch64 bash build-image.sh    # linux/arm64
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # …/kriya-aggregator/packaging
AGG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"                          # …/kriya-aggregator
VERSION="$(grep -m1 '^version' "$AGG_DIR/Cargo.toml" | cut -d'"' -f2)"
ARCH="${ARCH:-x86_64}"
case "$ARCH" in
  x86_64)  TARGET=x86_64-unknown-linux-musl;  PLATFORM=linux/amd64 ;;
  aarch64) TARGET=aarch64-unknown-linux-musl; PLATFORM=linux/arm64 ;;
  *) echo "unknown ARCH=$ARCH (use x86_64|aarch64)" >&2; exit 1 ;;
esac

BIN="$AGG_DIR/build/dist/$TARGET/kriyad"
[ -f "$BIN" ] || { echo "ERROR: static binary missing: $BIN — run build/build-static.sh first." >&2; exit 1; }

CTX="$(mktemp -d)"; trap 'rm -rf "$CTX"' EXIT
cp "$BIN" "$CTX/kriyad"
cp "$SCRIPT_DIR/Dockerfile" "$CTX/Dockerfile"

echo "==> Building kriyad:$VERSION ($PLATFORM) from $BIN"
docker build --platform "$PLATFORM" -t "kriyad:$VERSION" -t "kriyad:latest" "$CTX"
echo "==> Image:"
docker images "kriyad:$VERSION" --format '  {{.Repository}}:{{.Tag}}  {{.Size}}'
