#!/usr/bin/env bash
# make-box.sh — assemble the BOX skin tarball (SHIP-BOX): the Vault/Consul model — one static binary +
# a hardened systemd unit + the mTLS CA bootstrap + the auditor + a README. Requires the static musl
# binaries from ../../build/build-static.sh.
#
#   ARCH=x86_64  bash make-box.sh    # default
#   ARCH=aarch64 bash make-box.sh
set -euo pipefail

BOX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # …/packaging/box
AGG_DIR="$(cd "$BOX_DIR/../.." && pwd)"                          # …/kriya-aggregator
VERSION="$(grep -m1 '^version' "$AGG_DIR/Cargo.toml" | cut -d'"' -f2)"
ARCH="${ARCH:-x86_64}"
case "$ARCH" in
  x86_64)  TARGET=x86_64-unknown-linux-musl ;;
  aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "unknown ARCH=$ARCH (use x86_64|aarch64)" >&2; exit 1 ;;
esac
DIST="$AGG_DIR/build/dist/$TARGET"
[ -f "$DIST/kriyad" ] || { echo "ERROR: $DIST/kriyad missing — run build/build-static.sh first." >&2; exit 1; }

OUT="$AGG_DIR/build/dist"
NAME="kriyad-$VERSION-box-$ARCH"
STAGE="$(mktemp -d)/$NAME"; mkdir -p "$STAGE"
trap 'rm -rf "$(dirname "$STAGE")"' EXIT

install -m 0755 "$DIST/kriyad"                 "$STAGE/kriyad"
install -m 0755 "$DIST/kriya-audit"            "$STAGE/kriya-audit"
install -m 0644 "$BOX_DIR/kriyad.service"      "$STAGE/kriyad.service"
install -m 0644 "$BOX_DIR/kriyad.env.example"  "$STAGE/kriyad.env.example"
install -m 0755 "$BOX_DIR/install.sh"          "$STAGE/install.sh"
install -m 0644 "$BOX_DIR/README.md"           "$STAGE/README.md"
install -m 0755 "$AGG_DIR/scripts/kriyd-ca.sh" "$STAGE/kriyd-ca.sh"

TARBALL="$OUT/$NAME.tar.gz"
tar -C "$(dirname "$STAGE")" -czf "$TARBALL" "$NAME"
( cd "$OUT" && shasum -a 256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
echo "==> BOX tarball: $TARBALL"
tar -tzf "$TARBALL" | sed 's/^/    /'
cat "$OUT/$NAME.tar.gz.sha256"
