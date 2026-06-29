#!/usr/bin/env bash
# Keep the Console version in lockstep across all three manifests, since the .dmg filename + release
# name derive from src-tauri/tauri.conf.json. Without this they drift (package.json was 0.0.0 while
# Cargo/tauri were 0.1.0) and the published artifact/checksum/tag end up mislabeled.
#
#   ./scripts/bump-version.sh 0.2.0            # sync package.json + Cargo.toml + tauri.conf.json (safe)
#   ./scripts/bump-version.sh 0.2.0 --release  # …then commit on a release branch + annotated tag v0.2.0
#
# Default is sync-only (no git side effects). Pass --release to cut the release commit + tag — do that
# only when you actually intend to publish, not mid-feature.
set -euo pipefail

NEW="${1:-}"
MODE="${2:-}"
if [[ -z "$NEW" ]]; then
  echo "usage: $0 <semver> [--release]" >&2
  exit 1
fi
if [[ ! "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+.][0-9A-Za-z.]+)?$ ]]; then
  echo "error: '$NEW' is not a semver (expected e.g. 0.2.0)" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "→ package.json → $NEW"
node -e 'const fs=require("fs");const f="package.json";const p=JSON.parse(fs.readFileSync(f,"utf8"));p.version=process.argv[1];fs.writeFileSync(f,JSON.stringify(p,null,2)+"\n");' "$NEW"

echo "→ src-tauri/tauri.conf.json → $NEW"
node -e 'const fs=require("fs");const f="src-tauri/tauri.conf.json";const p=JSON.parse(fs.readFileSync(f,"utf8"));p.version=process.argv[1];fs.writeFileSync(f,JSON.stringify(p,null,2)+"\n");' "$NEW"

echo "→ src-tauri/Cargo.toml [package].version → $NEW"
# Replace only the version line inside the [package] table (the first table), never a dependency version.
NEW="$NEW" perl -0pi -e 'my $v=$ENV{NEW}; s/(\[package\][^\[]*?\nversion\s*=\s*")[^"]*(")/${1}$v${2}/s' src-tauri/Cargo.toml

echo "→ refreshing Cargo.lock"
cargo update --manifest-path src-tauri/Cargo.toml -p kriya-console --offline >/dev/null 2>&1 \
  || cargo update --manifest-path src-tauri/Cargo.toml --workspace >/dev/null 2>&1 \
  || echo "  (lockfile will sync on the next cargo build)"

echo "✓ versions synced to $NEW:"
grep -m1 '"version"' package.json
grep -m1 '"version"' src-tauri/tauri.conf.json
grep -m1 '^version' src-tauri/Cargo.toml

if [[ "$MODE" == "--release" ]]; then
  BRANCH="release/v$NEW"
  echo "→ --release: committing on $BRANCH + tagging v$NEW"
  git checkout -b "$BRANCH"
  git add package.json src-tauri/tauri.conf.json src-tauri/Cargo.toml src-tauri/Cargo.lock
  git commit -m "chore(release): v$NEW"
  git tag -a "v$NEW" -m "Kriya Console v$NEW"
  echo "✓ tagged v$NEW on $BRANCH — push with: git push origin $BRANCH --tags"
else
  echo "ℹ sync-only (no git changes). Re-run with --release to cut the release commit + tag."
fi
