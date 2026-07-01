#!/usr/bin/env bash
# build-static.sh — reproducible STATIC-musl build of kriyad + kriya-audit (SHIP-0), the single source
# of every kriyaD shipping skin (BOX / OCI image / air-gap bundle).
#
# Why cargo-zigbuild: two deps need a C cross-toolchain — `rusqlite` (bundled SQLite C) and `rustls`
# (aws-lc-rs crypto provider). Plain `cargo build --target …musl` on macOS has no such toolchain and
# fails. cargo-zigbuild uses `zig cc` as the cross C compiler/linker, which cross-compiles both to musl
# cleanly. Runs in Docker so the host toolchain is irrelevant.
#
#   bash build-static.sh                                   # both x86_64 + aarch64 musl
#   TARGETS=x86_64-unknown-linux-musl bash build-static.sh # a single target
#
# Output: build/dist/<target>/{kriyad,kriya-audit} + build/dist/SHA256SUMS (fully static ELF binaries).
#
# FALLBACK (documented in SHIP-ROADMAP SHIP-0): if aws-lc-rs refuses to cross-build to musl, add a `ring`
# Cargo feature that swaps `rustls::crypto::aws_lc_rs`→`ring` in src/tls.rs and pass it here. Try aws-lc-rs
# first — it is FIPS-capable, which the air-gap/defense buyer may require.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # …/kriya-aggregator/build
WORKSPACE="$(cd "$SCRIPT_DIR/../../.." && pwd)"              # src-tauri (the cargo workspace root)
IMAGE="${IMAGE:-messense/cargo-zigbuild:latest}"
TARGETS="${TARGETS:-x86_64-unknown-linux-musl aarch64-unknown-linux-musl}"
OUT="$SCRIPT_DIR/dist"
CACHE="$SCRIPT_DIR/.cargo-registry"                          # persisted crate cache (faster re-runs)

mkdir -p "$OUT" "$CACHE"
TARGET_FLAGS=(); for t in $TARGETS; do TARGET_FLAGS+=(--target "$t"); done

echo "==> Static-musl build of kriyad + kriya-audit for: $TARGETS"
echo "    image=$IMAGE  workspace=$WORKSPACE"
# Build ONLY the two headless crates (-p …): their graph pulls kriya-verify but never the Tauri app crate,
# so no macOS-only deps are compiled. CARGO_TARGET_DIR is a build-local dir so musl artifacts never mix
# with the host macOS target/.
docker run --rm --platform linux/amd64 \
  -v "$WORKSPACE":/io -w /io \
  -v "$CACHE":/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/io/crates/kriya-aggregator/build/target \
  -e CARGO_PROFILE_RELEASE_STRIP=true \
  "$IMAGE" \
  cargo zigbuild --release -p kriya-aggregator -p kriya-audit-cli "${TARGET_FLAGS[@]}"

# Collect the binaries + checksums.
: > "$OUT/SHA256SUMS"
for t in $TARGETS; do
  mkdir -p "$OUT/$t"
  cp "$SCRIPT_DIR/target/$t/release/kriyad"      "$OUT/$t/kriyad"
  cp "$SCRIPT_DIR/target/$t/release/kriya-audit" "$OUT/$t/kriya-audit"
  ( cd "$OUT" && shasum -a 256 "$t/kriyad" "$t/kriya-audit" >> SHA256SUMS )
  echo "==> $t"
  file "$OUT/$t/kriyad" | sed 's/^/    /'
done
echo "==> Artifacts in $OUT"
cat "$OUT/SHA256SUMS"
echo "✓ static build done"
