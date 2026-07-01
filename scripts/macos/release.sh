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

# Create the one-time stable self-signed code-signing identity in the login keychain (only used by
# --self-signed). Imports with -A/-T codesign so subsequent codesign runs don't re-prompt. This touches
# YOUR keychain, so it only runs when YOU invoke --self-signed (it may pop one keychain 'allow' dialog).
create_self_identity() {
  echo "==> Creating one-time self-signed identity '$SELF_IDENTITY' (approve the keychain prompt if it appears)."
  local TMP; TMP="$(mktemp -d)"
  cat > "$TMP/openssl.cnf" <<CNF
[ req ]
distinguished_name = dn
x509_extensions = v3
prompt = no
[ dn ]
CN = $SELF_IDENTITY
[ v3 ]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
basicConstraints = critical, CA:false
CNF
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 3650 -config "$TMP/openssl.cnf" >/dev/null 2>&1
  openssl pkcs12 -export -inkey "$TMP/key.pem" -in "$TMP/cert.pem" -name "$SELF_IDENTITY" -out "$TMP/identity.p12" -passout pass: >/dev/null 2>&1
  security import "$TMP/identity.p12" -k "$HOME/Library/Keychains/login.keychain-db" -P "" -T /usr/bin/codesign -A
  rm -rf "$TMP"
}

# Build a compressed, drag-to-Applications dmg from a .app via hdiutil — no Finder/AppleScript, so it
# works headless and won't fail the way Tauri's bundle_dmg.sh does.
make_dmg() {  # $1 = .app path, $2 = output .dmg path
  local app="$1" out="$2" stage
  stage="$(mktemp -d)"
  cp -R "$app" "$stage/"
  ln -s /Applications "$stage/Applications"
  rm -f "$out"
  hdiutil create -volname "Kriya Console" -srcfolder "$stage" -ov -format UDZO "$out" >/dev/null
  rm -rf "$stage"
}

# 1) Build + stage the gateway sidecar (externalBin Tauri embeds).
scripts/bundle-gateway.sh release
[ -f "$SIDECAR" ] || { echo "ERROR: staged sidecar not found: $SIDECAR" >&2; exit 1; }

# 2) Resolve the signing identity + verify creds.
if [ "$SELF_SIGNED" -eq 1 ]; then
  if ! security find-certificate -c "$SELF_IDENTITY" >/dev/null 2>&1; then
    create_self_identity
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

# 4) Build the .app ONLY. We package the dmg ourselves with hdiutil (step 5) — Tauri's bundle_dmg.sh
#    drives Finder/AppleScript to lay out the dmg window and is flaky / headless-hostile.
export APPLE_SIGNING_IDENTITY="$SIGN_ID"
npm run tauri build -- --bundles app
APP="src-tauri/target/release/bundle/macos/Kriya Console.app"
[ -d "$APP" ] || { echo "ERROR: .app not produced at $APP" >&2; exit 1; }

# 5) Package a clean drag-to-Applications dmg from the signed .app (no Finder automation).
OUT="dist-macos"; mkdir -p "$OUT"
FINAL="$OUT/KriyaConsole-$VERSION-$ARCH.dmg"
echo "==> Packaging dmg via hdiutil"
make_dmg "$APP" "$FINAL"
echo "==> Built: $FINAL"

# 6) Sign + notarize + staple (proper mode only). The dmg is code-signed with the Developer ID FIRST
#    (Apple's recommended flow — an unsigned-but-notarized dmg staples fine but `spctl --assess` reports
#    "no usable signature"), THEN notarytool notarizes its contents, THEN staple pins the ticket so
#    Gatekeeper passes offline. Self-signed builds skip this (no ticket to staple).
if [ "$SELF_SIGNED" -eq 0 ]; then
  echo "==> Signing dmg with '$SIGN_ID'"
  codesign --force --timestamp --sign "$SIGN_ID" "$FINAL"
  echo "==> Notarizing $FINAL (this can take a few minutes)…"
  if [ -n "${APPLE_API_KEY:-}" ]; then
    xcrun notarytool submit "$FINAL" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER" --wait
  else
    xcrun notarytool submit "$FINAL" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait
  fi
  xcrun stapler staple "$FINAL"
  spctl -a -vvv -t open --context context:primary-signature "$FINAL" || true
  xcrun stapler validate "$FINAL"
fi

# 7) SHA-256 (what the website /download page verifies against).
( cd "$OUT" && shasum -a 256 "KriyaConsole-$VERSION-$ARCH.dmg" | tee "KriyaConsole-$VERSION-$ARCH.dmg.sha256" )
echo "==> Artifact: $FINAL (+ .sha256)"

# 8) Optional: publish to a GitHub Release.
#    IMPORTANT: publish to the PUBLIC runtime repo, NOT this private Console repo — so the free-tier
#    download is publicly fetchable (no auth) AND GitHub meters every fetch (asset.downloadCount = the
#    traction number; see docs/ideas/SHIP-ROADMAP.md HOST-1). `gh` defaults to the current repo's origin
#    (private kriya-console), so we pass -R explicitly. Console releases are namespaced `console-v*` so
#    they never collide with the runtime's own tags in the shared repo.
if [ "$GH_RELEASE" -eq 1 ]; then
  GH_RELEASE_REPO="${GH_RELEASE_REPO:-sandeepshekhar26/kriya}"
  TAG="console-v$VERSION"
  NOTES="Kriya Console $VERSION ($ARCH) — free tier. Signed with our Apple Developer ID, notarized + stapled by Apple, so it opens with no Gatekeeper prompt. The Console app is closed-source; the kriya runtime in this repo is MIT. Verify with the .sha256 asset."
  echo "==> Publishing $TAG to GitHub Releases on $GH_RELEASE_REPO"
  gh release create "$TAG" "$FINAL" "$FINAL.sha256" -R "$GH_RELEASE_REPO" \
      --title "Kriya Console $VERSION" --notes "$NOTES" \
    || gh release upload "$TAG" "$FINAL" "$FINAL.sha256" --clobber -R "$GH_RELEASE_REPO"
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
