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
TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
PROFILE="${1:-release}"

echo "==> Building kriya-gateway ($PROFILE, all macOS fronts) for $TRIPLE"
BUILD_FLAGS=(--no-default-features --features mcp-client,reach-in,computer-use,router --bin kriya-gateway)
if [ "$PROFILE" = "release" ]; then BUILD_FLAGS+=(--release); fi
cargo build --manifest-path "$CRATE_DIR/Cargo.toml" "${BUILD_FLAGS[@]}"

SRC="$CRATE_DIR/target/$PROFILE/kriya-gateway"
DEST_DIR="$CONSOLE_DIR/src-tauri/binaries"
DEST="$DEST_DIR/kriya-gateway-$TRIPLE"
mkdir -p "$DEST_DIR"
cp "$SRC" "$DEST"
chmod +x "$DEST"
echo "==> Staged sidecar: $DEST"
