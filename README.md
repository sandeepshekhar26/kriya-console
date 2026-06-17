# kriya Console

**Proprietary — paid tier. Not open source.** All rights reserved; see [`LICENSE`](LICENSE).

> **The governance plane for on-device AI agents.** kriya Console is where an organization
> oversees, governs, and *proves* what agents did across every app they operate — built on top of
> the open-source [kriya](https://github.com/sandeepshekhar26/kriya) runtime.

The open `kriya` runtime (MIT) makes a single app safely drivable by an agent: every action runs
through **policy → human approval → budget → an Ed25519-signed audit receipt**, on-device. That's
the adoption funnel. **kriya Console is the layer organizations pay for** — the cross-app cockpit
that aggregates those signed receipts, verifies them, and lets you author the policy the runtime
enforces.

*The engine is open; the cockpit is paid.* (Public/private split + rationale: the runtime repo's
`docs/LICENSING.md`, decision **D-011**.)

---

## What's inside (R6 — increments 1 & 2)

### ▤ Audit log — tamper-evident, verified locally
Drop in one or many `kriya-audit.jsonl` logs from any kriya app. Every signed receipt is **verified
in the browser** against its embedded Ed25519 key — nothing leaves the machine. Tampered or forged
rows fail verification and surface in red. Filter by action, status, or source app; see a live
verified / failed / distinct-signer summary across apps.

The verifier is a from-scratch TypeScript reimplementation of the host's canonical signing
(`crates/kriya/src/audit.rs`), proven **byte-identical** against real Rust-signed receipts in the
test suite — if it drifted by a single byte, the signatures wouldn't verify.

### ⛨ Policy — author the rules the runtime enforces
The policy plane is where you decide what agents may do with your registered actions:

- **Ordered rules** (first match wins, no match = deny) mapping an action pattern (`delete_*`,
  `close_account`, `*`) to a tier — **Allow · Require approval · Deny** — with drag-to-reorder.
- **Coverage from your logs** — actions seen in your audit logs that *aren't* explicitly governed
  are surfaced as one-click suggestions, so nothing silently rides the catch-all.
- **Live decision preview** — see exactly how the current policy treats every observed action
  (and test any action id).
- **Lint** — the same checks the host runs at startup (`Policy::warnings()`): wildcard-allow,
  destructive-named actions without approval, missing catch-all, missing budget cap.
- **Budget** — a per-minute action cap to stop a looping agent.
- **Export / import** — download a host-ready `agent-policy.yaml`; paste an existing one to edit it.

The policy model is a faithful port of `crates/kriya/src/permissions.rs`, with parity tests against
the Rust unit tests — so what the console shows is what the runtime will do.

---

## Develop

```bash
npm install
npm test         # verifier + policy model, cross-checked against the Rust host
npm run dev      # the console → http://localhost:5173
npm run build    # typecheck (tsc --noEmit) + production build
```

`npm test` is the spine: it proves the TS verifier agrees with the Rust signer on real receipts
(and rejects tampered ones), and that the policy model decides + lints identically to the host.

## How it relates to the open runtime

```
 open   kriya (MIT)       per action →  policy → approval → budget → Ed25519-signed receipt
                                           ▲                                   │
 paid   kriya-console     ── authors agent-policy.yaml ──┘                     │
                          ── verifies + aggregates the signed receipts ────────┘
```

Dependency is **one-way**: the console consumes the open `kriya` audit + policy formats; the public
repo never references this one. Don't copy proprietary code into the open repo, and don't relicense
the open SDK.

## Why it sells

For regulated and multi-app organizations, "an agent did something" is not enough — they must
**prove what it did and constrain what it can do**, on-device, where cloud MCP gateways structurally
can't reach. The console is buy-not-build governance plus cryptographic, tamper-evident audit: the
willingness-to-pay surface that EU AI Act enforcement (Aug 2026) and SOC 2 make non-optional. Next
on the roadmap — approval routing, live budgets, compliance-evidence export, identity —
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## Layout

```
src/lib/verify.ts      canonical bytes + Ed25519 verification (the trust core)
src/lib/policy.ts      policy model: rules, decide(), lint — a port of permissions.rs
src/lib/receipts.ts    parse a JSONL log → verified rows
src/views/             Overview · AuditView · PolicyView
src/components/         Sidebar · AuditTable
src/sample/            real Rust-signed receipts (zero-setup demo + test fixtures)
test/                  verify.test.ts · policy.test.ts (parity with the Rust host)
```
