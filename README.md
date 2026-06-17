# kriya Console

**Proprietary — paid tier. Not open source.** All rights reserved; see [`LICENSE`](LICENSE).

kriya Console is the governance surface for [kriya](https://github.com/sandeepshekhar26/kriya):
the cross-app cockpit an organization uses to **oversee what on-device agents did** across many
apps, agents, and users — and to prove it.

> The open-source `kriya` runtime (MIT) makes one app safely drivable by an agent: every action
> runs through policy → human approval → budget → an Ed25519-**signed** audit receipt, on-device.
> **kriya Console is the layer on top:** aggregate those signed receipts across every app, verify
> them, search them, and (next) edit policy, route approvals, and export compliance evidence.
>
> *The engine is open; the cockpit is paid.* The full public/private split and rationale live in
> the runtime repo's `docs/LICENSING.md` (decision **D-011**).

## Status — R6, increment 1: the signed-audit viewer

What ships in this repo today:

- **Faithful, local receipt verification.** A from-scratch TypeScript reimplementation of the
  host's canonical signing (`crates/kriya/src/audit.rs`): top-level receipt fields in declaration
  order, `params` object keys sorted (serde_json's `BTreeMap`), compact bytes, Ed25519 verify
  (`@noble/ed25519`). It is **cross-checked against real Rust-signed receipts** the host emitted —
  byte-identical, or the signatures would not verify. See [`test/verify.test.ts`](test/verify.test.ts).
- **Cross-app audit viewer.** Drop in one or many `kriya-audit.jsonl` logs; every receipt is
  verified **locally** (nothing leaves the machine), tagged by source app, and shown in a
  filterable table with a verified / failed / tampered summary and a distinct-signer count.

The rest of R6 (policy editor, multi-approval routing, budget controls) and P2 (R7 compliance
export, R8 identity) are in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Develop

```bash
npm install
npm test         # the verifier, cross-checked against real Rust-signed fixtures
npm run dev      # the dashboard → http://localhost:5173
npm run build    # typecheck (tsc --noEmit) + production build
```

`npm test` is the one that matters: it proves the TS verifier agrees with the Rust signer on real
receipts and rejects tampered / forged ones.

## How it relates to the open runtime

```
 open   kriya (MIT)        signs an Ed25519 receipt per action  →  kriya-audit.jsonl
 paid   kriya-console      reads + verifies those receipts across apps   ← you are here
```

Dependency is **one-way**: this repo consumes the public `kriya` format/packages; the public repo
never references this one. Do not copy proprietary code into the open repo, and do not relicense
the open SDK.

## Layout

```
src/lib/verify.ts        canonical-bytes + Ed25519 verification (the trust core)
src/lib/receipts.ts      parse a JSONL log → verified rows
src/lib/types.ts         Receipt / SignedReceipt / AuditRow
src/App.tsx              the dashboard (load logs, filter, summarize)
src/components/          AuditTable
src/sample/              real Rust-signed receipts for zero-setup demo + tests
test/verify.test.ts      cross-check vs real receipts + tamper/forgery cases
```
