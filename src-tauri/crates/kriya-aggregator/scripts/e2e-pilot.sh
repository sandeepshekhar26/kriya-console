#!/usr/bin/env bash
# e2e-pilot.sh — the ⭐ pilot demo over the REAL shipped binaries (roadmap 2.11), now over mTLS with
# P6 ROLE-STAMPED certs (doc 22 §11-B2):
#   device emits a signed envelope + heartbeat (committed fixtures)
#     → kriyad AIR-GAP side-loads + re-verifies offline   (`kriyad ingest-file`)
#     → kriyad serves the same store over mTLS             (`kriyad`, role-gated)
#     → the DEVICE cert posts its own heartbeat            (device role, bound to its device_pub)
#     → the OPERATOR cert reads the fleet back             (operator role: /v1/verify + /v1/coverage)
#     → auditor RE-PROVES the read-back fully offline      (`kriya-audit --readback`)
#     → coverage reads `current`.
#   Then the P6 denials, proven live: a DEVICE cert is 403'd on a fleet read, and an OPERATOR cert is
#   403'd on an evidence POST.
# Run from anywhere: bash crates/kriya-aggregator/scripts/e2e-pilot.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd) # -> src-tauri
FIX="$ROOT/crates/kriya-aggregator/test-fixtures"
WORK=$(mktemp -d)
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== build the real binaries =="
( cd "$ROOT" && cargo build -q -p kriya-aggregator -p kriya-audit-cli )
KRIYAD="$ROOT/target/debug/kriyad"
AUDIT="$ROOT/target/debug/kriya-audit"

DEVICE=$(tr -d '[:space:]' < "$FIX/pilot-device-pub.txt")

echo "== 0. bootstrap role-stamped mTLS certs (operator + a device bound to the pilot device_pub) =="
CA="$WORK/ca"
bash "$ROOT/crates/kriya-aggregator/scripts/kriyd-ca.sh" "$CA" --operator --device "$DEVICE" >/dev/null
OP="--cacert $CA/ca.pem --cert $CA/operator.pem --key $CA/operator.key"
DEV="--cacert $CA/ca.pem --cert $CA/device.pem   --key $CA/device.key"

export KRIYAD_DB="$WORK/kriyad.sqlite"
export KRIYAD_LICENSE="$ROOT/crates/kriya-aggregator/fixtures/dev-control-plane-license.json"
export KRIYAD_BIND="127.0.0.1:8455"
export KRIYAD_CA_DIR="$CA" # present → mTLS + P6 role gating on
BASE="https://localhost:8455"

echo "== 1. device → kriyad (AIR-GAP side-load): offline re-verify + ingest =="
"$KRIYAD" ingest-file "$FIX/pilot-outbox.ndjson"

echo "== 2. kriyad serves the same append-only store over mTLS (role-gated) =="
"$KRIYAD" & SRV=$!
# shellcheck disable=SC2086
for _ in $(seq 1 50); do curl -fsS $OP "$BASE/healthz" >/dev/null 2>&1 && break || sleep 0.1; done

echo "== 3. device heartbeat over mTLS (DEVICE role, bound to its own device_pub) =="
# shellcheck disable=SC2086
curl -fsS $DEV -X POST --data-binary @"$FIX/pilot-heartbeat.json" "$BASE/v1/heartbeat"; echo

echo "== 4. auditor → /v1/verify over mTLS (OPERATOR role) — trustless read-back of the EXACT bytes =="
# shellcheck disable=SC2086
curl -fsS $OP "$BASE/v1/verify?device_pub=$DEVICE" > "$WORK/readback.json"

echo "== 5. coverage (OPERATOR role) =="
# shellcheck disable=SC2086
curl -fsS $OP "$BASE/v1/coverage"; echo

echo "== 6. OFFLINE re-prove the read-back (sig + chain + merkle + tail anchor) =="
"$AUDIT" --readback "$WORK/readback.json"

echo "== 7. P6 role denials, proven live =="
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
# shellcheck disable=SC2086
C=$(code $DEV "$BASE/v1/coverage"); echo "  device cert → GET /v1/coverage  : HTTP $C"; [ "$C" = "403" ] || { echo "EXPECTED 403"; exit 1; }
# shellcheck disable=SC2086
C=$(code $OP -X POST --data-binary @"$FIX/pilot-heartbeat.json" "$BASE/v1/heartbeat"); echo "  operator cert → POST /v1/heartbeat: HTTP $C"; [ "$C" = "403" ] || { echo "EXPECTED 403"; exit 1; }

echo "✅ e2e pilot demo passed end-to-end over the real binaries (mTLS + P6 role separation enforced)"
