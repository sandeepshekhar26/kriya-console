#!/usr/bin/env bash
# release-audit-cli.sh — build, sign, notarize + publish the FREE `kriya-audit` auditor CLI (PROD-3).
#
#   ./scripts/release-audit-cli.sh                 # macOS universal: build + Developer ID sign + notarize
#   ./scripts/release-audit-cli.sh --linux         # + static-musl Linux binaries (Docker, via build-static.sh)
#   ./scripts/release-audit-cli.sh --gh-release    # + publish to the PUBLIC runtime repo (tag audit-v<ver>)
#
# Needs the same Apple env as scripts/macos/release.sh: APPLE_SIGNING_IDENTITY plus notarization creds
# (App Store Connect API key: APPLE_API_KEY / APPLE_API_ISSUER / APPLE_API_KEY_PATH — or Apple ID trio).
# A bare CLI cannot be stapled, so the ZIP is notarized: Gatekeeper fetches the ticket online the first
# time a quarantined (browser-downloaded) copy runs. curl downloads carry no quarantine at all.
set -euo pipefail

LINUX=0; GH_RELEASE=0
for arg in "$@"; do
  case "$arg" in
    --linux)      LINUX=1 ;;
    --gh-release) GH_RELEASE=1 ;;
    -h|--help)    sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg (try --help)" >&2; exit 1 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' src-tauri/crates/kriya-audit-cli/Cargo.toml | head -1)"
[ -n "$VERSION" ] || { echo "ERROR: could not read the crate version" >&2; exit 1; }
OUT="dist-audit"; rm -rf "$OUT"; mkdir -p "$OUT"
AGG="src-tauri/crates/kriya-aggregator"

: "${APPLE_SIGNING_IDENTITY:?set APPLE_SIGNING_IDENTITY to 'Developer ID Application: NAME (TEAMID)'}"
if [ -n "${APPLE_API_KEY:-}" ] && [ -n "${APPLE_API_ISSUER:-}" ] && [ -n "${APPLE_API_KEY_PATH:-}" ]; then
  NOTARY_ARGS=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER")
elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ]; then
  NOTARY_ARGS=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
else
  echo "ERROR: no notarization creds (API key trio or Apple ID trio)." >&2; exit 1
fi

echo "==> kriya-audit $VERSION — macOS universal (aarch64 + x86_64)"
for T in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --manifest-path src-tauri/Cargo.toml --release -p kriya-audit-cli --target "$T"
done
lipo -create -output "$OUT/kriya-audit" \
  src-tauri/target/aarch64-apple-darwin/release/kriya-audit \
  src-tauri/target/x86_64-apple-darwin/release/kriya-audit
lipo -archs "$OUT/kriya-audit" | grep -q 'x86_64 arm64\|arm64 x86_64' || { echo "ERROR: not universal" >&2; exit 1; }

echo "==> Signing (Developer ID, hardened runtime)"
codesign --force --timestamp --options runtime --sign "$APPLE_SIGNING_IDENTITY" "$OUT/kriya-audit"
codesign --verify --strict --verbose=2 "$OUT/kriya-audit"

ZIP="kriya-audit-$VERSION-macos-universal.zip"
( cd "$OUT" && zip -q "$ZIP" kriya-audit )

echo "==> Notarizing $ZIP (this can take a few minutes)…"
xcrun notarytool submit "$OUT/$ZIP" "${NOTARY_ARGS[@]}" --wait | tee "$OUT/notary.log"
grep -q 'status: Accepted' "$OUT/notary.log" || { echo "ERROR: notarization not Accepted" >&2; exit 1; }

# Stage the copy-paste sample evidence (all three modes) from the committed fixtures.
echo "==> Staging sample evidence"
cp src/sample/sample-audit.jsonl            "$OUT/sample-receipts.jsonl"
cp "$AGG/test-fixtures/pilot-outbox.ndjson" "$OUT/sample-envelopes.ndjson"
jq -n \
  --argjson envs "$(jq -Rs 'split("\n")|map(select(length>0))' "$AGG/test-fixtures/pilot-outbox.ndjson")" \
  --arg hb "$(cat "$AGG/test-fixtures/pilot-heartbeat.json")" \
  '{envelopes:$envs,heartbeat:$hb}' > "$OUT/sample-readback.json"

# Self-check: the exact binary we ship verifies all three samples, and FAILS a 1-byte tamper.
echo "==> Self-check (verify + tamper)"
"$OUT/kriya-audit" "$OUT/sample-receipts.jsonl"
"$OUT/kriya-audit" --envelopes "$OUT/sample-envelopes.ndjson"
"$OUT/kriya-audit" --readback  "$OUT/sample-readback.json"
sed '1s/list_transactions/list_transactionsX/' "$OUT/sample-receipts.jsonl" > "$OUT/.tampered.jsonl"
if "$OUT/kriya-audit" "$OUT/.tampered.jsonl" >/dev/null 2>&1; then
  echo "ERROR: tampered sample did NOT fail" >&2; exit 1
fi
rm -f "$OUT/.tampered.jsonl"
echo "    tamper correctly rejected (exit 1)"

ASSETS=("$OUT/$ZIP" "$OUT/sample-receipts.jsonl" "$OUT/sample-envelopes.ndjson" "$OUT/sample-readback.json")

if [ "$LINUX" -eq 1 ]; then
  echo "==> Static-musl Linux binaries (Docker)"
  docker info >/dev/null 2>&1 || { echo "ERROR: Docker not running (needed for --linux)" >&2; exit 1; }
  bash "$AGG/build/build-static.sh"
  for T in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    SRC="$AGG/build/dist/$T/kriya-audit"
    [ -f "$SRC" ] || { echo "ERROR: missing $SRC" >&2; exit 1; }
    DEST="$OUT/kriya-audit-$VERSION-linux-${T%%-*}-musl"
    cp "$SRC" "$DEST"; chmod +x "$DEST"
    ASSETS+=("$DEST")
  done
fi

echo "==> SHA256SUMS"
( cd "$OUT" && shasum -a 256 $(for a in "${ASSETS[@]}"; do basename "$a"; done) | tee SHA256SUMS )
ASSETS+=("$OUT/SHA256SUMS")

if [ "$GH_RELEASE" -eq 1 ]; then
  # PUBLIC runtime repo (not this private one): free download, publicly fetchable, download-metered.
  GH_RELEASE_REPO="${GH_RELEASE_REPO:-sandeepshekhar26/kriya}"
  TAG="audit-v$VERSION"
  echo "==> Publishing $TAG to $GH_RELEASE_REPO"
  gh release create "$TAG" "${ASSETS[@]}" -R "$GH_RELEASE_REPO" \
      --title "kriya-audit $VERSION — offline auditor re-prover" \
      --notes-file src-tauri/crates/kriya-audit-cli/README.md \
    || gh release upload "$TAG" "${ASSETS[@]}" --clobber -R "$GH_RELEASE_REPO"
fi
echo "✓ done — artifacts in $OUT/"
