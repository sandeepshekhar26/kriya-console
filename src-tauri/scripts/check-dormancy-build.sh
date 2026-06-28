#!/usr/bin/env bash
# Dormancy build-half (roadmap 1.4): assert a DEFAULT (free) build links NONE of the control-plane-only
# dependencies, so the shipped free tier stays byte-for-byte unchanged. Run from src-tauri/.
# Exit 1 if any control-plane dep leaks into the free dependency graph.
set -euo pipefail

# Only deps that are CONTROL-PLANE-EXCLUSIVE (getrandom is already a transitive dep of the app, so it
# is not a leak signal). reqwest/rustls arrive with push.rs (2.7).
leaked="$(cargo tree -e normal 2>/dev/null | grep -iE '[│├└].*\b(hmac|reqwest|rustls)\b' || true)"
if [ -n "$leaked" ]; then
  echo "DORMANCY VIOLATION — control-plane deps found in the FREE build graph:" >&2
  echo "$leaked" >&2
  exit 1
fi
echo "OK: the free build links none of hmac / reqwest / rustls"
