#!/usr/bin/env bash
#
# bundle-gateway.sh — build the public `kriya-gateway` and stage it as the Console's Tauri sidecar.
#
# The control-plane app ships the gateway INSIDE its bundle (D-018): one download installs + wires
# the gateway. Tauri's `externalBin` expects the binary at
#   src-tauri/binaries/kriya-gateway-<target-triple>
# This script builds the gateway from the PUBLIC repo (open-core: the gateway is public, the Console
# is private) with the macOS fronts enabled, then copies it into place. Run before `tauri build`
# (and once before `tauri dev`, since externalBin must exist).
#
# Override the gateway repo path with KRIYA_REPO=/path/to/experiment1.
# Set KRIYA_UNIVERSAL=1 to build a UNIVERSAL sidecar (aarch64 + x86_64 lipo'd into one binary named
# kriya-gateway-universal-apple-darwin) — required by `tauri build --target universal-apple-darwin`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KRIYA_REPO="${KRIYA_REPO:-/Volumes/WORKSSD/software_for_agents/experiment1}"
CRATE_DIR="$KRIYA_REPO/crates/kriya"

if [ ! -d "$CRATE_DIR" ]; then
  echo "ERROR: kriya crate not found at $CRATE_DIR (set KRIYA_REPO)." >&2
  exit 1
fi

[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
PROFILE="${1:-release}"
DEST_DIR="$CONSOLE_DIR/src-tauri/binaries"
mkdir -p "$DEST_DIR"

# mcp-http adds the broker's remote (HTTP/SSE) upstream transport (W2-2) so the shipped Console can
# govern hosted MCP servers, not just local stdio ones. Pulls in the same ureq client the runtime
# already uses; no macOS FFI.
BUILD_FLAGS=(--no-default-features --features mcp-client,mcp-http,reach-in,computer-use,router --bin kriya-gateway)
if [ "$PROFILE" = "release" ]; then BUILD_FLAGS+=(--release); fi

# Build the gateway for one target triple; echo the resulting binary path on stdout (progress → stderr).
build_for() {
  echo "==> Building kriya-gateway ($PROFILE, all macOS fronts) for $1" >&2
  cargo build --manifest-path "$CRATE_DIR/Cargo.toml" --target "$1" "${BUILD_FLAGS[@]}" >&2
  echo "$CRATE_DIR/target/$1/$PROFILE/kriya-gateway"
}

if [ "${KRIYA_UNIVERSAL:-0}" = "1" ]; then
  # `tauri build --target universal-apple-darwin` needs BOTH: the two per-arch sidecars
  # (kriya-gateway-<arch>-apple-darwin, resolved during each per-arch app compile) AND a lipo'd
  # kriya-gateway-universal-apple-darwin (copied into the app at the final bundle step). Stage all three.
  for T in aarch64-apple-darwin x86_64-apple-darwin; do
    SRC="$(build_for "$T")"
    cp "$SRC" "$DEST_DIR/kriya-gateway-$T"
    chmod +x "$DEST_DIR/kriya-gateway-$T"
    echo "==> Staged sidecar: kriya-gateway-$T"
  done
  lipo -create "$DEST_DIR/kriya-gateway-aarch64-apple-darwin" "$DEST_DIR/kriya-gateway-x86_64-apple-darwin" \
    -output "$DEST_DIR/kriya-gateway-universal-apple-darwin"
  chmod +x "$DEST_DIR/kriya-gateway-universal-apple-darwin"
  echo "==> Staged UNIVERSAL sidecar: kriya-gateway-universal-apple-darwin ($(lipo -info "$DEST_DIR/kriya-gateway-universal-apple-darwin" | sed 's/.*are: *//'))"
else
  TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
  SRC="$(build_for "$TRIPLE")"
  DEST="$DEST_DIR/kriya-gateway-$TRIPLE"
  cp "$SRC" "$DEST"
  chmod +x "$DEST"
  echo "==> Staged sidecar: $DEST"
fi
