#!/usr/bin/env bash
# verify-bundle.sh — verify the air-gap bundle on a DISCONNECTED machine. No network: the signature is
# checked against a pinned public key with the transparency log ignored (--insecure-ignore-tlog), then
# the extracted contents are checked against SHA256SUMS. Exits non-zero on any tamper.
#
#   bash verify-bundle.sh <bundle.tar.zst> <bundle.tar.zst.cosign.bundle> <kriya-release.pub>
set -euo pipefail

BUNDLE="${1:?usage: verify-bundle.sh <bundle.tar.zst> <bundle.tar.zst.cosign.bundle> <kriya-release.pub>}"
SIGBUNDLE="${2:?missing <bundle.tar.zst.cosign.bundle>}"
PUB="${3:?missing <kriya-release.pub>}"

echo "==> 1/2 cosign signature (offline, tlog ignored)"
cosign verify-blob --key "$PUB" --bundle "$SIGBUNDLE" --insecure-ignore-tlog=true "$BUNDLE"

echo "==> 2/2 extract + content checksums"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
zstd -dc "$BUNDLE" | tar -C "$TMP" -xf -
DIR="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
( cd "$DIR" && shasum -a 256 -c SHA256SUMS )

echo "✓ bundle authentic + intact — safe to install (see INSTALL-AIRGAP.md)"
