# kriya-audit — re-prove kriya evidence offline

**Don't trust us — check.** `kriya-audit` re-verifies kriya governance evidence — Ed25519-signed
receipts, attestation envelopes, and `kriyad` read-backs — **fully offline**: no network, no account,
no telemetry. It links the exact same `kriya-verify` trust core the kriya Console and `kriyad` server
use, so its verdict is produced by the audited code path, not a re-implementation.

Exit codes: `0` = everything verified · `1` = any failure · `2` = usage error.

## Install

**macOS** (universal: Apple Silicon + Intel; signed with our Apple Developer ID and notarized by Apple):

```sh
curl -fsSLO https://github.com/sandeepshekhar26/kriya/releases/download/audit-v0.1.0/kriya-audit-0.1.0-macos-universal.zip
unzip -o kriya-audit-0.1.0-macos-universal.zip
```

**Linux** (fully static, zero dependencies — also `aarch64`):

```sh
curl -fsSL -o kriya-audit https://github.com/sandeepshekhar26/kriya/releases/download/audit-v0.1.0/kriya-audit-0.1.0-linux-x86_64-musl
chmod +x kriya-audit
```

Integrity: every asset is listed in [`SHA256SUMS`](https://github.com/sandeepshekhar26/kriya/releases/download/audit-v0.1.0/SHA256SUMS)
(`shasum -a 256 -c SHA256SUMS`).

## Verify our sample in 60 seconds

```sh
curl -fsSLO https://github.com/sandeepshekhar26/kriya/releases/download/audit-v0.1.0/sample-receipts.jsonl
./kriya-audit sample-receipts.jsonl
```

```
sample-receipts.jsonl: 20 receipt(s), 20 signature(s) verified, … — OK
```

Now tamper with one byte and watch it get caught:

```sh
sed '1s/list_transactions/list_transactionsX/' sample-receipts.jsonl > tampered.jsonl
./kriya-audit tampered.jsonl; echo "exit=$?"
```

```
tampered.jsonl:1: FAIL — signature does not match
tampered.jsonl: 20 receipt(s), 19 signature(s) verified, … — FAIL
exit=1
```

That is the whole product in two commands: the bytes either are what the signer signed, or the
verifier tells you they aren't.

## The three modes

| Mode | Input | What it proves |
|---|---|---|
| `kriya-audit <receipts.jsonl>` | signed audit receipts (what the runtime writes) | every receipt's Ed25519 signature (exit-gated); hash-chain continuity reported as a completeness signal |
| `kriya-audit --envelopes <outbox.ndjson>` | `AttestationEnvelope`s (what a device exports to `kriyad`) | each envelope's signature, the envelope chain (`prev_envelope_hash` — deletion/reorder shows up), Merkle-root well-formedness |
| `kriya-audit --readback <verify.json>` | a `kriyad` `GET /v1/verify` response | all of the above **plus** the device's signed heartbeat and the tail-truncation anchor (`returned_top_seq ≥ seq_seen` — a server hiding the newest envelopes is caught) |

Try the other two modes on the released samples:

```sh
curl -fsSLO https://github.com/sandeepshekhar26/kriya/releases/download/audit-v0.1.0/sample-envelopes.ndjson
curl -fsSLO https://github.com/sandeepshekhar26/kriya/releases/download/audit-v0.1.0/sample-readback.json
./kriya-audit --envelopes sample-envelopes.ndjson
./kriya-audit --readback  sample-readback.json
```

## Reading the verdicts honestly

- **OK means:** the bytes you hold are byte-identical to what the holder of the signing key signed,
  and (envelopes/read-back) nothing in the sequence was deleted, reordered, or truncated behind the
  signed anchors. **Pin your signer:** the verifier proves *that key* signed — confirm the key
  fingerprint out-of-band; it cannot tell you *who should* hold the key.
- The sample's `hash-chain break at line 2 (informational)` is expected: `sample-receipts.jsonl` is a
  bundle of independently signed receipts, not one chained stream. Real runtime logs chain per-stream
  via `prev_hash` inside the signed bytes, so whole-record deletion surfaces as a chain break.
- This is **tamper-evidence, not tamper-proofing**: a compromised host that never signs an action, or
  a device that was never enrolled, produces no evidence to verify. The guarantee starts at the
  signing key.
- Receipts are *also* independently re-verifiable with the open-source verifiers in this repo
  (TypeScript/Rust/Python/.NET/Java) — you don't need this binary to check receipts; it adds the
  envelope and read-back modes and packages the whole thing as one signed tool.

Free, no license required. Feedback: kriyanative@gmail.com · https://kriyanative.com
