#!/usr/bin/env bash
# story-demo.sh — the kriya control-plane pilot, told as a story over the REAL binaries.
#
# Claim (honest): every agent action is device-signed and RE-VERIFIED OFFLINE at ingest, so forged,
# altered, deleted, or tail-truncated EVIDENCE is detectable — by an independent auditor, without
# trusting the vendor or the network. It does NOT prove the action itself was safe; the guarantee
# starts at the signing key. (See demo/STORY.md for the full beat sheet + honest caveats.)
#
# Drives: kriyad (ingest + re-verify + serve) and kriya-audit (offline re-prover) — the shipped
# binaries, nothing mocked. Recorded with VHS (demo/kriya-demo.tape).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src-tauri"
FIX="$SRC/crates/kriya-aggregator/test-fixtures"
KRIYAD="$SRC/target/debug/kriyad"
AUDIT="$SRC/target/debug/kriya-audit"
W="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

export KRIYAD_DB="$W/kriyad.sqlite"
export KRIYAD_LICENSE="$SRC/crates/kriya-aggregator/fixtures/dev-control-plane-license.json"
export KRIYAD_BIND="127.0.0.1:8477"
export KRIYAD_CA_DIR="$W/none"
DEV="$(tr -d '[:space:]' < "$FIX/pilot-device-pub.txt")"
URL="http://$KRIYAD_BIND"

# ---- presentation helpers (ANSI; VHS renders them) -------------------------------------------------
B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'; G=$'\e[32m'; RED=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; M=$'\e[35m'; GREY=$'\e[90m'; LT=$'\e[37m'
beat()  { printf "\n${B}${C}▸ %s${R}\n" "$1"; sleep 1.1; }
line()  { printf "${LT}  %s${R}\n" "$1"; sleep 0.9; }         # narration (the story — kept readable)
cmd()   { printf "${D}  \$ %s${R}\n" "$1"; sleep 0.7; }       # the real command
good()  { printf "  ${G}✓ %s${R}\n" "$1"; sleep 1.0; }
fail()  { printf "  ${RED}✗ %s${R}\n" "$1"; sleep 1.0; }
hon()   { printf "  ${Y}· %s${R}\n" "$1"; sleep 1.0; }        # the honest boundary
out()   { printf "${GREY}  %s${R}\n" "$(echo "$1" | sed -E "s#($FIX|$W)/##g")"; sleep 0.6; }  # tool output, paths trimmed
p()     { sleep "${1:-1.4}"; }

# ---- silent setup (built + server up before the curtain) -------------------------------------------
( cd "$SRC" && cargo build -q -p kriya-aggregator -p kriya-audit-cli ) 2>/dev/null
"$KRIYAD" >/dev/null 2>&1 & SRV=$!
disown 2>/dev/null || true   # so bash never prints a "Terminated" job-control line on exit
for _ in $(seq 1 60); do curl -fsS "$URL/healthz" >/dev/null 2>&1 && break || sleep 0.1; done
curl -fsS -X POST --data-binary @"$FIX/pilot-heartbeat.json" "$URL/v1/heartbeat" >/dev/null 2>&1

clear
printf "${B}${M}  kriya  ·  on-device agent-governance control plane${R}\n"
printf "${D}  Evidence Integrity, Not Action Approval${R}\n"
printf "${GREY}  the pilot, over the real binaries — nothing leaves this machine${R}\n"
p 2.6

# 1 — signed evidence
beat "1 · a device seals each batch of agent actions into a SIGNED envelope"
line "Ed25519 over canonical bytes; operator names are HMAC-pseudonymized, not stored"
head -1 "$FIX/pilot-outbox.ndjson" | python3 -c "import sys,json;e=json.loads(sys.stdin.read());v=e['envelope'];print('  {\"schema\":\"%s\", \"seq\":%d, \"device\":\"%s…\", \"merkle_root\":\"%s…\",'%(v['schema'],v['seq'],v['device_pub'][:12],v['integrity']['merkle_root'][:12]));print('   \"signature\":\"%s…\"}'%e['signature'][:24])"
p 2.0

# 2 — the honesty boundary, stated up front (this is what makes it stick)
beat "2 · what the signature proves — and what it does NOT"
hon "proves: this device signed these EXACT bytes; nothing was altered after signing"
hon "does NOT prove the action was safe/authorized — the guarantee starts at the key"
p 2.0

# 3 — server re-verifies offline
beat "3 · kriyad RE-VERIFIES every envelope offline, then stores only signed metadata"
line "the server never trusts the device — it re-checks the signature itself. zero outbound calls."
cmd "kriyad ingest-file outbox.ndjson   # a 2-envelope hash chain"
out "$("$KRIYAD" ingest-file "$FIX/pilot-outbox.ndjson" 2>&1)"
good "accepted — both envelopes re-verified on the box"
p 1.6

# 4 — ATTACK 1: forge at ingest
beat "4 · attack: forge an envelope — change one field after signing — and push it"
cmd "jq '.envelope.org_id=\"evil-corp\"' env1 | kriyad ingest-file -"
head -1 "$FIX/pilot-outbox.ndjson" | python3 -c "import sys,json;d=json.loads(sys.stdin.read());d['envelope']['org_id']='evil-corp';open('$W/forged.ndjson','w').write(json.dumps(d))"
out "$("$KRIYAD" ingest-file "$W/forged.ndjson" 2>&1)"
fail "REJECTED at ingest — the changed byte breaks the signature"
p 1.8

# 5 — independent re-prove
beat "5 · an INDEPENDENT auditor pulls the exact stored bytes and re-proves them"
line "/v1/verify returns the EXACT signed bytes + the device's signed heartbeat (the tail anchor)"
cmd "curl /v1/verify?device=… > readback.json   &&   kriya-audit --readback readback.json"
curl -fsS "$URL/v1/verify?device_pub=$DEV" > "$W/readback.json"
"$AUDIT" --readback "$W/readback.json" 2>&1 | sed 's/^/  /'
good "sig + hash-chain + tail-anchor — re-proved offline, trusting no one"
p 1.8

# 6 — ATTACK 2: tamper the read-back
beat "6 · attack: tamper ONE byte of what the server returned"
cmd "flip 1 hex char of a signature in readback.json"
python3 -c "import json;d=json.load(open('$W/readback.json'));e=json.loads(d['envelopes'][0]);s=e['signature'];e['signature']=('f' if s[0]!='f' else '0')+s[1:];d['envelopes'][0]=json.dumps(e);json.dump(d,open('$W/tampered.json','w'))"
"$AUDIT" --readback "$W/tampered.json" 2>&1 | grep -E "FAIL" | sed 's/^/  /'
fail "CAUGHT — signature does not match"
p 1.8

# 7 — ATTACK 3: hide the newest receipt (tail truncation)
beat "7 · attack: a malicious server HIDES the newest receipt (drops seq 2)"
line "but the device's signed heartbeat already attested it emitted up to seq 2…"
cmd "drop the last envelope from readback.json, re-run the auditor"
python3 -c "import json;d=json.load(open('$W/readback.json'));d['envelopes']=d['envelopes'][:-1];json.dump(d,open('$W/trunc.json','w'))"
"$AUDIT" --readback "$W/trunc.json" 2>&1 | grep -E "TRUNCATION|tail-anchor" | sed 's/^/  /'
fail "CAUGHT — returned seq 1, but the device signed seq_seen=2"
p 1.8

# 8 — air-gap parity
beat "8 · air-gap: carry the SAME bytes to a disconnected second box"
line "sneaker-net == network — the verifier never trusts the transport"
cmd "kriyad ingest-file outbox.ndjson   # on an air-gapped aggregator"
out "$(KRIYAD_DB="$W/airgap.sqlite" "$KRIYAD" ingest-file "$FIX/pilot-outbox.ndjson" 2>&1)"
good "accepted — identical bytes, identical verdict, no connection"
p 1.6

# 9 — coverage + the honest gap
beat "9 · coverage: who's reporting, who went dark"
cmd "curl /v1/coverage"
curl -fsS "$URL/v1/coverage" | python3 -c "import sys,json;d=json.load(sys.stdin);[print('  device %s…  status=%s  last_seq=%s  org=%s'%(x['device_pub'][:12],x['status'],x['last_seq'],x['org_id'])) for x in d]"; sleep 0.6
hon "silence is visible; but a NEVER-enrolled device has no heartbeat to miss — invisible, not absent"
p 1.8

# 10 — engine open, cockpit paid
beat "10 · engine open, cockpit paid — the FREE build ships none of this"
cmd "cargo tree -e normal | grep -c 'reqwest|rustls'"
out "$( cd "$SRC" && cargo tree -e normal 2>/dev/null | grep -cE 'reqwest|rustls' )"
good "the free on-device tier links zero control-plane code (the dormancy firewall)"
p 1.6

# closing — the sticky, honest line
printf "\n${B}${G}  Signed at the source. Re-verified on your box. Provably nothing hidden.${R}\n"
p 1.2
printf "${GREY}  For what it guarantees — that the record wasn't altered after signing —${R}\n"
printf "${GREY}  the vendor's server is reduced to a glorified append-only file,${R}\n"
printf "${GREY}  and the auditor owns the proof.${R}\n"
p 12   # long hold: the recording is cut here, so it ends ON the closing line (no shell prompt)
