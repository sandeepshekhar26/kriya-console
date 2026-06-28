# kriya control-plane pilot — demo

A ~65-second recording of the pilot running over the **real shipped binaries** (`kriyad` + `kriya-audit`),
not a mockup. Every command is real; every adversarial moment is staged from genuinely signed bytes.

![kriya pilot demo](kriya-pilot-demo.gif)

- **`kriya-pilot-demo.mp4`** (2.5 MB) — the shareable recording.
- **`kriya-pilot-demo.gif`** (4.7 MB) — for inline embedding.
- **`STORY.md`** — the narrative + the honest boundary (what it proves, and what it deliberately does not).
- **`story-demo.sh`** — the driver. **`kriya-demo.tape`** — the [VHS](https://github.com/charmbracelet/vhs) script.

## The one-sentence claim

> Every agent action is **device-signed** and **re-verified offline** at ingest, so forged, altered,
> deleted, or tail-truncated **evidence** is detectable — by an independent auditor, **without trusting
> the vendor or the network**. It proves *evidence integrity*, not that the action itself was safe; the
> guarantee starts at the signing key.

## What the recording shows (10 beats)

1. A device seals each batch of agent actions into an **Ed25519-signed** envelope (operator names HMAC-pseudonymized).
2. The honest boundary, stated up front: the signature proves the **bytes** are authentic — not that the action was safe.
3. `kriyad` **re-verifies every envelope offline**, then stores only signed metadata — zero outbound calls.
4. **Attack — forge at ingest:** change one field after signing → `kriyad` rejects it (`accepted=0`).
5. An **independent auditor** pulls the exact stored bytes (`/v1/verify`) and **re-proves** them offline.
6. **Attack — tamper the read-back:** flip one byte → `kriya-audit` catches it (signature fails).
7. **Attack — hide the newest receipt:** a malicious server drops seq 2 → the heartbeat **tail-truncation anchor** catches it.
8. **Air-gap parity:** the same bytes on a USB stick verify identically on a disconnected box — sneaker-net == network.
9. **Coverage:** who's reporting, who went dark (and the honest gap: a *never-enrolled* device is invisible, not absent).
10. **Engine open, cockpit paid:** the free on-device build links **zero** control-plane code (the dormancy firewall).

## Reproduce

```bash
# from the repo root
bash demo/story-demo.sh          # run the narrated demo over the real binaries
vhs demo/kriya-demo.tape         # re-record the GIF + MP4 (needs: vhs, ffmpeg)
```

The driver builds `kriyad` + `kriya-audit`, starts a local `kriyad` (offline license, plain HTTP for the
demo; mTLS is exercised by the `kriyd-ca` + tls tests), and runs the beats against it. Fixtures live in
`src-tauri/crates/kriya-aggregator/test-fixtures/` (regenerate with
`cargo test -p kriya-aggregator emit_pilot_fixtures -- --ignored`).
