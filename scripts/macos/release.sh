#!/usr/bin/env bash
# release.sh — build a distributable macOS Console .dmg (+ checksum), signed and (by default) notarized.
#
#   ./scripts/macos/release.sh                 # PROPER: Developer ID sign + Apple notarize + staple
#   ./scripts/macos/release.sh --self-signed   # INTERIM: self-signed, NOT notarized (Gatekeeper WILL warn)
#   ./scripts/macos/release.sh --gh-release     # also publish the .dmg + .sha256 to a GitHub Release (tag vX.Y.Z)
#   (flags combine, e.g. --self-signed --gh-release)
#
# PROPER mode needs (once your Apple Developer enrollment completes):
#   APPLE_SIGNING_IDENTITY="Developer ID Application: NAME (TEAMID)"
#   plus notarization creds — EITHER an App Store Connect API key:
#     APPLE_API_KEY=<KeyID>  APPLE_API_ISSUER=<IssuerID>  APPLE_API_KEY_PATH=/path/AuthKey_XXXX.p8
#   OR an Apple ID + app-specific password:
#     APPLE_ID=you@example.com  APPLE_PASSWORD=<app-specific-pw>  APPLE_TEAM_ID=<TEAMID>
# Tauri v2 signs with APPLE_SIGNING_IDENTITY and auto-notarizes when those creds are present.
#
# SELF-SIGNED mode uses the local self-signed identity from scripts/macos/sign-stable-identity.sh
# (default name "Kriya Dev"; override with IDENTITY=...). It produces a runnable .dmg, but because it is
# NOT notarized, a browser-downloaded copy trips Gatekeeper — see the note printed at the end. Use it
# only as a stopgap; replace the download with the notarized build once your Developer ID is active.
set -euo pipefail

SELF_SIGNED=0
GH_RELEASE=0
for arg in "$@"; do
  case "$arg" in
    --self-signed) SELF_SIGNED=1 ;;
    --gh-release)  GH_RELEASE=1 ;;
    -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg (try --help)" >&2; exit 1 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
ARCH="${TRIPLE%%-*}"                                  # aarch64 | x86_64
VERSION="$(node -e 'console.log(require("./src-tauri/tauri.conf.json").version)')"
SIDECAR="src-tauri/binaries/kriya-gateway-$TRIPLE"
SELF_IDENTITY="${IDENTITY:-Kriya Dev}"

if [ "$SELF_SIGNED" -eq 1 ]; then
  echo "==> Kriya Console $VERSION ($ARCH) — SELF-SIGNED (interim, not notarized)"
else
  echo "==> Kriya Console $VERSION ($ARCH) — Developer ID + notarized"
fi

# 1) Build + stage the gateway sidecar (externalBin Tauri embeds).
scripts/bundle-gateway.sh release
[ -f "$SIDECAR" ] || { echo "ERROR: staged sidecar not found: $SIDECAR" >&2; exit 1; }

# 2) Resolve the signing identity + verify creds.
if [ "$SELF_SIGNED" -eq 1 ]; then
  if ! security find-certificate -c "$SELF_IDENTITY" >/dev/null 2>&1; then
    echo "ERROR: self-signed identity '$SELF_IDENTITY' not in the keychain." >&2
    echo "       Run scripts/macos/sign-stable-identity.sh once to create it." >&2
    exit 1
  fi
  SIGN_ID="$SELF_IDENTITY"
else
  : "${APPLE_SIGNING_IDENTITY:?set APPLE_SIGNING_IDENTITY to 'Developer ID Application: NAME (TEAMID)' (or use --self-signed)}"
  SIGN_ID="$APPLE_SIGNING_IDENTITY"
  if [ -n "${APPLE_API_KEY:-}" ] && [ -n "${APPLE_API_ISSUER:-}" ] && [ -n "${APPLE_API_KEY_PATH:-}" ]; then
    echo "    notarization: App Store Connect API key"
  elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ]; then
    echo "    notarization: Apple ID + app-specific password"
  else
    echo "ERROR: no notarization creds. Set APPLE_API_KEY+APPLE_API_ISSUER+APPLE_API_KEY_PATH," >&2
    echo "       or APPLE_ID+APPLE_PASSWORD+APPLE_TEAM_ID (or use --self-signed for an interim build)." >&2
    exit 1
  fi
fi

# 3) Sign the staged sidecar with hardened runtime BEFORE tauri build. This is the documented mitigation
#    for the v2 sidecar-notarization invalidation (tauri-apps/tauri#11992); harmless for self-signed.
echo "==> Signing sidecar with '$SIGN_ID'"
codesign --force --timestamp --options runtime \
  --entitlements src-tauri/entitlements.plist --sign "$SIGN_ID" "$SIDECAR"

# 4) Build app + dmg. Exporting APPLE_SIGNING_IDENTITY makes Tauri sign the bundle; in PROPER mode the
#    notarization env (present from step 2) also triggers Apple notarization during the build.
export APPLE_SIGNING_IDENTITY="$SIGN_ID"
npm run tauri build -- --bundles app,dmg

# 5) Locate the produced dmg (newest under the bundle dir).
DMG="$(ls -t "src-tauri/target/release/bundle/dmg/"*.dmg 2>/dev/null | head -1 || true)"
[ -n "$DMG" ] || { echo "ERROR: no .dmg produced under src-tauri/target/release/bundle/dmg/" >&2; exit 1; }
echo "==> Built: $DMG"

# 6) Staple + verify (proper mode only; a self-signed dmg has no notarization ticket to staple).
if [ "$SELF_SIGNED" -eq 0 ]; then
  echo "==> Stapling + verifying notarization"
  xcrun stapler staple "$DMG"
  spctl -a -vvv -t open --context context:primary-signature "$DMG"
  xcrun stapler validate "$DMG"
  hdiutil verify "$DMG" >/dev/null && echo "    hdiutil verify: ok"
fi

# 7) Versioned name + SHA-256 (what the website /download page verifies against).
OUT="dist-macos"
mkdir -p "$OUT"
FINAL="$OUT/KriyaConsole-$VERSION-$ARCH.dmg"
cp "$DMG" "$FINAL"
( cd "$OUT" && shasum -a 256 "KriyaConsole-$VERSION-$ARCH.dmg" | tee "KriyaConsole-$VERSION-$ARCH.dmg.sha256" )
echo "==> Artifact: $FINAL (+ .sha256)"

# 8) Optional: publish to a GitHub Release.
if [ "$GH_RELEASE" -eq 1 ]; then
  TAG="v$VERSION"
  echo "==> Publishing $TAG to GitHub Releases"
  gh release create "$TAG" "$FINAL" "$FINAL.sha256" \
      --title "Kriya Console $VERSION" --notes "Kriya Console $VERSION ($ARCH)" \
    || gh release upload "$TAG" "$FINAL" "$FINAL.sha256" --clobber
fi

if [ "$SELF_SIGNED" -eq 1 ]; then
  cat <<'NOTE'

⚠ This .dmg is SELF-SIGNED and NOT notarized. A browser download will hit Gatekeeper:
  "Apple cannot check it for malicious software." To open it, the user must either:
   • System Settings → Privacy & Security → "Open Anyway" (macOS 15 removed right-click→Open), or
   • run:  xattr -d com.apple.quarantine "/Applications/Kriya Console.app"
  Replace this with the notarized build — ./scripts/macos/release.sh — once your Developer ID enrolls.
NOTE
fi
echo "✓ done"
