#!/usr/bin/env bash
# e2e-pilot.sh — the ⭐ pilot demo over the REAL shipped binaries (roadmap 2.11):
#   device emits a signed envelope + heartbeat (committed fixtures)
#     → kriyad AIR-GAP side-loads + re-verifies offline   (`kriyad ingest-file`)
#     → kriyad serves the same store                        (`kriyad`, HTTP)
#     → auditor reads the bytes back over /v1/verify        (`curl`)
#     → auditor RE-PROVES them fully offline                (`kriya-audit --readback`:
#                                                            sig + chain + merkle + tail anchor)
#     → coverage reads `current`.
# Plain HTTP keeps the demo dependency-free; mTLS is exercised by the kriyd-ca + tls tests.
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

export KRIYAD_DB="$WORK/kriyad.sqlite"
export KRIYAD_LICENSE="$ROOT/crates/kriya-aggregator/fixtures/dev-control-plane-license.json"
export KRIYAD_BIND="127.0.0.1:8455"
export KRIYAD_CA_DIR="$WORK/no-certs" # absent → plain HTTP
DEVICE=$(tr -d '[:space:]' < "$FIX/pilot-device-pub.txt")

echo "== 1. device → kriyad (AIR-GAP side-load): offline re-verify + ingest =="
"$KRIYAD" ingest-file "$FIX/pilot-outbox.ndjson"

echo "== 2. kriyad serves the same append-only store over HTTP =="
"$KRIYAD" & SRV=$!
for _ in $(seq 1 50); do curl -fsS "http://$KRIYAD_BIND/healthz" >/dev/null 2>&1 && break || sleep 0.1; done

echo "== 3. device heartbeat (the tail-truncation anchor) =="
curl -fsS -X POST --data-binary @"$FIX/pilot-heartbeat.json" "http://$KRIYAD_BIND/v1/heartbeat"

echo "== 4. auditor → /v1/verify (trustless read-back of the EXACT signed bytes) =="
curl -fsS "http://$KRIYAD_BIND/v1/verify?device_pub=$DEVICE" > "$WORK/readback.json"

echo "== 5. coverage =="
curl -fsS "http://$KRIYAD_BIND/v1/coverage"; echo

echo "== 6. OFFLINE re-prove the read-back (sig + chain + merkle + tail anchor) =="
"$AUDIT" --readback "$WORK/readback.json"

echo "✅ e2e pilot demo passed end-to-end over the real binaries"
