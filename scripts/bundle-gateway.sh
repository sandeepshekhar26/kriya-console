#!/usr/bin/env bash
#
# bundle-gateway.sh — build the public kriya sidecars and stage them as the Console's Tauri sidecars.
#
# The control-plane app ships the runtime binaries INSIDE its bundle (D-018): one download installs +
# wires them. Two sidecars are staged (both declared as Tauri `externalBin`):
#   • kriya-gateway — the stdio governance proxy + reach-in/computer-use fronts.
#   • kriya-hook    — the Claude Code hooks adapter govern-all installs (GA-0, doc 21 Part C).
# Tauri's `externalBin` expects each at src-tauri/binaries/<bin>-<target-triple>.
#
# This builds both from the PUBLIC repo (open-core: the runtime is public, the Console is private) with
# the macOS features each needs, then copies them into place. Run before `tauri build` (and once before
# `tauri dev`, since externalBin must exist).
#
# Override the runtime repo path with KRIYA_REPO=/path/to/experiment1.
# Set KRIYA_UNIVERSAL=1 to build UNIVERSAL sidecars (aarch64 + x86_64 lipo'd into one <bin>-universal-
# apple-darwin each) — required by `tauri build --target universal-apple-darwin`.

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

# The sidecars to stage, as "bin:features" specs (bash 3.2-safe — no associative arrays).
#  • gateway: mcp-http adds the broker's remote (HTTP/SSE) upstream transport (W2-2) so the shipped
#    Console can govern hosted MCP servers, not just local stdio; reach-in/computer-use/router are the
#    desktop fronts. Same ureq client the runtime already uses; no extra FFI.
#  • hook / hermes-hook: mcp-client alone (both reuse Policy/ApprovalGate/Signer; the macOS
#    GuiApproval needs no extra feature). std-only, tiny.
SIDECAR_SPECS=(
  "kriya-gateway:mcp-client,mcp-http,reach-in,computer-use,router"
  "kriya-hook:mcp-client"
  "kriya-hermes-hook:mcp-client"
)

# Build one binary for one target triple; echo the resulting binary path on stdout (progress → stderr).
build_bin() {  # $1=bin  $2=features  $3=target
  local bin="$1" feats="$2" target="$3"
  echo "==> Building $bin ($PROFILE, features: $feats) for $target" >&2
  local flags=(--no-default-features --features "$feats" --bin "$bin")
  [ "$PROFILE" = "release" ] && flags+=(--release)
  cargo build --manifest-path "$CRATE_DIR/Cargo.toml" --target "$target" "${flags[@]}" >&2
  echo "$CRATE_DIR/target/$target/$PROFILE/$bin"
}

# Build + stage one binary's per-arch sidecar under binaries/<bin>-<target>.
stage_for() {  # $1=bin  $2=features  $3=target
  local bin="$1" feats="$2" target="$3" src
  src="$(build_bin "$bin" "$feats" "$target")"
  cp "$src" "$DEST_DIR/$bin-$target"
  chmod +x "$DEST_DIR/$bin-$target"
  echo "==> Staged sidecar: $bin-$target" >&2
}

if [ "${KRIYA_UNIVERSAL:-0}" = "1" ]; then
  # `tauri build --target universal-apple-darwin` needs, per sidecar, BOTH the two per-arch staged
  # binaries (resolved during each per-arch app compile) AND a lipo'd <bin>-universal-apple-darwin
  # (copied into the app at the final bundle step). Stage all three for each sidecar.
  for spec in "${SIDECAR_SPECS[@]}"; do
    bin="${spec%%:*}"; feats="${spec#*:}"
    for T in aarch64-apple-darwin x86_64-apple-darwin; do
      stage_for "$bin" "$feats" "$T"
    done
    lipo -create "$DEST_DIR/$bin-aarch64-apple-darwin" "$DEST_DIR/$bin-x86_64-apple-darwin" \
      -output "$DEST_DIR/$bin-universal-apple-darwin"
    chmod +x "$DEST_DIR/$bin-universal-apple-darwin"
    echo "==> Staged UNIVERSAL sidecar: $bin-universal-apple-darwin ($(lipo -info "$DEST_DIR/$bin-universal-apple-darwin" | sed 's/.*are: *//'))" >&2
  done
else
  TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
  for spec in "${SIDECAR_SPECS[@]}"; do
    bin="${spec%%:*}"; feats="${spec#*:}"
    stage_for "$bin" "$feats" "$TRIPLE"
  done
fi

echo "==> All sidecars staged under $DEST_DIR"
