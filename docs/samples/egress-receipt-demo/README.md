# Self-verifying egress receipts (EG-1 sample)

`kriya-egress-receipts.html` is one self-contained file (~32 KB) that
**re-verifies itself in your browser, offline**. Open it directly from disk (`file://`) with
networking off: it re-checks every Ed25519 signature and the hash-chain and shows a green verdict —
zero network requests. Press **Tamper one byte** (or hand-edit a `bytes_out` value in a text editor
and reopen) and the verdict goes red, naming the receipt and field.

It is the same verifier the Console runs (`src/lib/verify.ts`), bundled into the page — not a mock.

## What's in it

Seven signed, hash-chained receipts on the existing schema, using the `kriya.io.*` vocabulary
(`kriya.io.<direction>.<kind>.<decision>`):

| # | action_id | what it shows |
|---|---|---|
| 1 | `kriya.io.egress.mcp.allow` | an **allowed** connector call — destination, bytes, content hash |
| 2 | `kriya.io.ingress.mcp.allow` | **ingress provenance** — the response that came back |
| 3 | `kriya.io.egress.model.allow` | a **model** call |
| 4 | `kriya.io.egress.http.deny` | a **DENY** against `default-deny` (`success:false`) |
| 5 | `kriya.io.egress.mcp.allow` | a **second vendor** |
| 6 | `kriya.io.egress.http.approve` | an **APPROVE**, with `approved_by` |
| 7 | `kriya.io.ingress.http.allow` | **ingress http** (hook lane → `canonical-json` hash scheme) |

Each `kriya.io.*` receipt carries `hash_scheme` (`wire-bytes` on the gateway lane,
`canonical-json` on the hook lane) so the record says exactly what its `content_sha256` commits to.

## Verify it yourself, three ways

1. **In the browser** — open `kriya-egress-receipts.html`. No server, no network.
2. **With the open CLI** — `kriya-audit receipts.jsonl` (signature-gated; also reports the chain):
   ```
   ./dist-audit/kriya-audit docs/samples/egress-receipt-demo/receipts.jsonl
   ```
3. **Flip a byte** — edit any digit in `receipts.jsonl` and re-run the CLI, or edit the embedded
   block in the HTML and reopen it. Both go red.

## Regenerate

```
npm run gen:egress-demo
```

Deterministic: fixed demo key + fixed timestamps, so the committed files are byte-stable across runs.

## The demo key (published on purpose)

These receipts are signed by a **dedicated demo key** and every one carries `params.synthetic:true`,
so demo receipts are cryptographically distinguishable from real ones forever. The key is published so
anyone can regenerate and re-verify:

- private (32-byte seed, hex): `de70de70…de70` (repeated `de70`) — see `scripts/gen-egress-demo.mts`
- public: `21544be1e9da180df80b8f81f60733741e9959a079eb1318ca665ee4d9c50bab`

It is **never** used for real receipts.

## Scope (honest ceiling — read this)

These are **governed-lane** records: kriya signs the calls it proxies (MCP connectors, tool calls).
Host-level egress — a spawned `curl`, a subprocess, a stdio server's own outbound HTTP — is the
watcher layer, not claimed here. Rendering **real** receipts through this template is gated on a
redaction profile (actor pseudonymized, `content_sha256` omitted or keyed, `dest_host` only where
the export's stated purpose requires it) and the export itself is receipted — see the guardrail note
in `src/lib/selfverify.ts`.
