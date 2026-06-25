#!/usr/bin/env bash
#
# sign-stable-identity.sh — give the Kriya Console bundle (and its embedded gateway sidecar) a
# STABLE self-signed code-signing identity so the macOS Accessibility (TCC) grant survives rebuilds.
#
# The problem (hit live this session): an ad-hoc-signed binary's cdhash changes on every rebuild, so
# the Accessibility grant you gave "Kriya Console.app" is invalidated and you must re-grant after each
# `tauri build`. A stable signing identity keeps the designated requirement constant, so the grant
# sticks across rebuilds.
#
# ── IMPORTANT: this touches your login keychain, so RUN IT YOURSELF (the planner) ──────────────────
# Creating the cert may prompt for your login-keychain password / an "always allow" dialog the first
# time codesign uses the key. That's why this isn't run autonomously by the agent. It is a ONE-TIME
# setup; after the cert exists, only the codesign step at the bottom needs re-running per build (and it
# won't prompt once you click "Always Allow").
#
# Usage:
#   scripts/macos/sign-stable-identity.sh            # creates the cert if missing, signs the built .app
#   IDENTITY="Kriya Dev" scripts/macos/sign-stable-identity.sh

set -euo pipefail

IDENTITY="${IDENTITY:-Kriya Dev}"
APP="${APP:-src-tauri/target/release/bundle/macos/Kriya Console.app}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$CONSOLE_DIR"

# 1. Create the self-signed CODE SIGNING cert in the login keychain if it isn't there yet.
if security find-certificate -c "$IDENTITY" >/dev/null 2>&1; then
  echo "==> Signing identity '$IDENTITY' already exists in the keychain."
else
  echo "==> Creating self-signed code-signing identity '$IDENTITY' in the login keychain."
  echo "    (If a password/allow dialog appears, approve it — this is the one-time setup.)"
  # Build a minimal self-signed cert with the codeSigning extended key usage, then import it with the
  # private key pre-authorized for /usr/bin/codesign so signing doesn't prompt every run.
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  cat > "$TMP/openssl.cnf" <<CNF
[ req ]
distinguished_name = dn
x509_extensions = v3
prompt = no
[ dn ]
CN = $IDENTITY
[ v3 ]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
basicConstraints = critical, CA:false
CNF
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 3650 -config "$TMP/openssl.cnf"
  openssl pkcs12 -export -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
    -name "$IDENTITY" -out "$TMP/identity.p12" -passout pass:
  security import "$TMP/identity.p12" \
    -k "$HOME/Library/Keychains/login.keychain-db" \
    -P "" -T /usr/bin/codesign -A
  echo "==> Imported '$IDENTITY'. (You may need to set it to 'Always Trust' in Keychain Access for"
  echo "    a clean codesign --verify, but signing works regardless.)"
fi

# 2. Sign the bundle: embedded gateway first (inside-out), then the .app.
if [ ! -d "$APP" ]; then
  echo "ERROR: built app not found at: $APP (run 'npm run tauri build' first)." >&2
  exit 1
fi
GATEWAY="$APP/Contents/MacOS/kriya-gateway"
if [ -f "$GATEWAY" ]; then
  echo "==> Signing embedded gateway sidecar"
  codesign --force --options runtime --sign "$IDENTITY" "$GATEWAY"
fi
echo "==> Signing $APP"
codesign --force --deep --options runtime --sign "$IDENTITY" "$APP"
echo "==> Verifying"
codesign --verify --verbose "$APP" || true
codesign -dvv "$APP" 2>&1 | grep -E "Authority|Identifier|TeamIdentifier|flags" || true
echo "==> Done. Grant Accessibility to this bundle ONCE; the grant now survives rebuilds (same identity)."
