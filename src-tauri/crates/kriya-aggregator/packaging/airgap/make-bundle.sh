#!/usr/bin/env bash
# make-bundle.sh — assemble the AIR-GAPPED skin (SHIP-AIR): a cosign KEY-signed `.tar.zst` that a
# disconnected site can carry across the gap and re-verify FULLY OFFLINE against a pinned public key.
#
# Why key-based, not keyless: keyless cosign needs an OIDC identity + a Rekor transparency-log round-trip
# — i.e. outbound calls — which defeats the whole air-gap premise. We sign with a long-lived key and pass
# --tlog-upload=false so nothing touches the network; verify-bundle.sh mirrors that with --insecure-ignore-tlog.
#
#   COSIGN_KEY=/path/kriya-release.key COSIGN_PASSWORD=… ARCH=x86_64 bash make-bundle.sh
#
# Generate the release keypair ONCE (keep the .key secret, publish the .pub):
#   COSIGN_PASSWORD=… cosign generate-key-pair    # → cosign.key (SECRET) + cosign.pub
set -euo pipefail

AIR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # …/packaging/airgap
AGG_DIR="$(cd "$AIR_DIR/../.." && pwd)"                          # …/kriya-aggregator
VERSION="$(grep -m1 '^version' "$AGG_DIR/Cargo.toml" | cut -d'"' -f2)"
ARCH="${ARCH:-x86_64}"
case "$ARCH" in
  x86_64)  TARGET=x86_64-unknown-linux-musl ;;
  aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "unknown ARCH=$ARCH (use x86_64|aarch64)" >&2; exit 1 ;;
esac
: "${COSIGN_KEY:?set COSIGN_KEY to your cosign private key (see header for how to generate one)}"

DIST="$AGG_DIR/build/dist/$TARGET"
[ -f "$DIST/kriyad" ] || { echo "ERROR: $DIST/kriyad missing — run build/build-static.sh first." >&2; exit 1; }
OUT="$AGG_DIR/build/dist"
NAME="kriyad-$VERSION-airgap-$ARCH"
STAGE="$(mktemp -d)/$NAME"; mkdir -p "$STAGE/binaries" "$STAGE/image"
trap 'rm -rf "$(dirname "$STAGE")"' EXIT

# 1) binaries + CA bootstrap + docs + a license SLOT (the operator drops their real license here).
install -m 0755 "$DIST/kriyad"                 "$STAGE/binaries/kriyad"
install -m 0755 "$DIST/kriya-audit"            "$STAGE/binaries/kriya-audit"
install -m 0755 "$AGG_DIR/scripts/kriyd-ca.sh" "$STAGE/kriyd-ca.sh"
install -m 0644 "$AIR_DIR/INSTALL-AIRGAP.md"   "$STAGE/INSTALL-AIRGAP.md"
install -m 0755 "$AIR_DIR/verify-bundle.sh"    "$STAGE/verify-bundle.sh"
install -m 0644 "$AGG_DIR/fixtures/dev-control-plane-license.json" "$STAGE/kriyad-license.example.json"

# 2) the saved OCI image, IF it's been built locally (packaging/build-image.sh). Optional.
if docker image inspect "kriyad:$VERSION" >/dev/null 2>&1; then
  docker save "kriyad:$VERSION" -o "$STAGE/image/kriyad-$VERSION.image.tar"
  echo "==> bundled docker image kriyad:$VERSION"
else
  echo "==> (skipping docker image — kriyad:$VERSION not built locally; run packaging/build-image.sh to include it)"
  rmdir "$STAGE/image"
fi

# 3) content checksums (excludes SHA256SUMS itself).
( cd "$STAGE" && find . -type f ! -name SHA256SUMS | sort | xargs shasum -a 256 > SHA256SUMS )

# 4) compress → .tar.zst
BUNDLE="$OUT/$NAME.tar.zst"
tar -C "$(dirname "$STAGE")" -cf - "$NAME" | zstd -19 -q -o "$BUNDLE" -f
echo "==> bundle: $BUNDLE"

# 5) cosign KEY-sign the blob into a Sigstore bundle, tlog OFF (fully offline), + emit the pinnable
#    public key alongside. cosign v3 replaced the detached --output-signature with the --bundle format.
COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign sign-blob --yes \
  --use-signing-config=false --tlog-upload=false \
  --key "$COSIGN_KEY" --bundle "$BUNDLE.cosign.bundle" "$BUNDLE"
COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign public-key --key "$COSIGN_KEY" > "$OUT/kriya-release.pub"

( cd "$OUT" && shasum -a 256 "$NAME.tar.zst" > "$NAME.tar.zst.sha256" )
echo "==> signed:   $BUNDLE.cosign.bundle"
echo "==> pin this: $OUT/kriya-release.pub"
echo "Verify offline:  bash verify-bundle.sh $BUNDLE $BUNDLE.cosign.bundle $OUT/kriya-release.pub"
