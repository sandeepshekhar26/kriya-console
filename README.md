# kriya Console

**Proprietary — paid tier. Not open source.** All rights reserved; see [`LICENSE`](LICENSE).

> **The agent control plane: govern everything your AI agents do — and prove it.** Built on the
> open-source [kriya](https://github.com/sandeepshekhar26/kriya) runtime (MIT). **The engine is open;
> the cockpit is paid.** One Mac free; a whole fleet from your own on-prem server (`kriyad`) — air-gap,
> on-prem, or your VPC, never our cloud.

The open `kriya` runtime makes any agent surface governable: every action runs through
**policy → human approval → budget → an Ed25519-signed, hash-chained receipt**, on-device. That's the
adoption funnel. kriya Console is the layer **organizations pay for** — it aggregates those signed
receipts, **re-verifies them locally**, authors the policy the runtime enforces, routes approvals,
exports compliance evidence, and (since v0.2.3) runs the **fleet cockpit** against a
customer-hosted `kriyad` aggregation server.

**New machine / new contributor? Start at [`SETUP.md`](SETUP.md)** — the from-scratch guide for the
Console + `kriyad` dev loop. **Strategy/product questions? Start at
[`docs/ideas/README.md`](docs/ideas/README.md)** (per [`CLAUDE.md`](CLAUDE.md), the repo is the
source of truth, not memory).

## Who it's for

Teams and regulated organizations running agents where *"an agent did something"* is not enough —
they must **prove what it did and constrain what it can do**. The sharpest fit: orgs that legally
can't ship agent activity to a cloud GRC (defense/CMMC, sovereign, air-gapped) — kriya installs where
a cloud governance product structurally can't.

## What you can do today (v0.2.3)

| | The view | The value |
|---|---|---|
| **Oversee** | **Monitor** (home) | Auto-tails `~/.kriya/audit/`, re-verifies every receipt on-device, posture at a glance, per-app attestation continuity. |
| **Prove** | **Audit log** | Every receipt verified against its embedded Ed25519 key — tampered/forged rows flagged on sight. |
| **Know the gaps** | **Coverage Map** | Six lanes (Claude Code · remote MCP · stdio MCP · desktop apps · file & exec · egress), each GREEN/AMBER/GREY — and every state change is itself a signed `coverage.snapshot` receipt in its own hash chain. The honest "what *isn't* recorded" answer. |
| **Decide** | **Approvals** | One cross-app, risk-ranked decision queue (RBAC-gated), attributed to agent + operator, reason recorded. *(A queue/record — the live prompt is the hook/gateway's own dialog; remote unblock is P7, planned.)* |
| **Constrain** | **Policy** | Author the `agent-policy.yaml` the runtime enforces (auto-persisted; every install path wires `--policy` — the B0 fix): ordered allow/approve/deny, budgets, lint, live preview. |
| **Wire** | **Connections / Govern-all** | Detect the agents on this Mac (Claude Code, Hermes) and wire hooks + gateway + policy in one click, reversibly; manage governed MCP connections; walks macOS permissions. |
| **Throttle** | **Budgets & rate** | Per-app/per-agent/per-operator usage vs caps. |
| **Attribute** | **Identity & access** | Per-operator + per-agent dashboards from the signed `actor`; RBAC roles. |
| **Report** | **Evidence** *(license)* | 19 controls across 5 frameworks — NIST 800-171/CMMC L2 AU-family (3.3.1–3.3.9), SOC 2, ISO 42001, EU AI Act, data-residency — statuses **computed from re-verified receipts**, gaps shown honestly. Markdown + JSON. |
| **Correlate** | **Fleet** *(license)* | Cross-app correlation on this machine: verified/failed, signers, policy coverage. |
| **Command the fleet** | **Control plane** *(license: `fleet-console`)* | The P0–P6 cockpit against your own `kriyad`: fleet table (liveness · inventory · drift), central policy authoring with an **org-key-signed downlink + anti-rollback**, a drift view **re-verified locally from each device's own signed envelopes** (kriyad's row is only a hint — disagreements get a loud mismatch badge), and the org-wide AU+CM evidence export. |

**Freemium:** free = Monitor, offline verification, Coverage, Connections, govern-all, guided setup —
fully usable, no account. An **offline license** unlocks the compliance tier (Evidence + Fleet) and,
with the `control-plane`/`fleet-console` flags, device enrollment + the fleet cockpit. Licensed, not
self-serve (the issuer/purchase path is a deferred stub; design-partner engagements today).

## The control plane (shipped: Phases 0–2 + fleet cockpit P0–P6)

Status board: [`docs/ideas/CONTROL-PLANE-ROADMAP.md`](docs/ideas/CONTROL-PLANE-ROADMAP.md) · spec:
[doc 13](docs/ideas/13-control-plane-full-spec-and-gtm.md) · cockpit design:
[doc 22](docs/ideas/22-fleet-cockpit-design.md) · positioning (control + proof, egress honesty):
[doc 23](docs/ideas/23-egress-ingress-governance.md).

```
device (Console, enrolled)                    your kriyad (BOX / K8S / air-gap)          operator (Console cockpit)
  verified receipts                             mTLS on every route                        fleet table · drift · org evidence
   └→ Evidence Compiler                         verifies EVERYTHING on ingest              author policy → org-key sign
      allowlist redaction (drop-by-default)     append-only SQLite                          └→ publish
      signed AttestationEnvelope                stores signed bytes only                   re-verifies every envelope LOCALLY
   └→ hash-chained outbox ──── push ──────────▶ coverage/liveness hints ◀──── pull ────────┘
   ◀─── org-key-signed PolicyBundle (pull on heartbeat · verify · anti-rollback · apply · signed receipt)
```

- **kriyad authors nothing**: evidence is device-signed, policy is operator-signed, the server holds
  neither key — a compromised kriyad can delay/withhold, never forge; withholding is caught
  (heartbeat gaps + the auditor CLI's tail-truncation anchor).
- **Cert roles (P6)**: device certs can't read the fleet; operator certs can't post evidence.
- **Three-tier data boundary** (free machine-level / enrolled boundary-level / operator) —
  [`docs/TRUST.md`](docs/TRUST.md) is canonical; the GDPR-minimized DeviceInfo beacon has *no schema
  field* for usernames/hostnames/IPs.
- Deferred (demand-pulled): P7 remote approvals, Phase 3 enrollment CA/CRL, Phase 4 HSM issuer +
  air-gap activation, Phase 5 k8s/Postgres/SSO. **Egress/ingress governance is planned, not built**
  (doc 23 — validate first; never claim SC-7/DLP).

## The trust spine — verify, don't trust

Every claim traces to a signed artifact re-verified locally: receipts (TS ↔ Rust canonical parity on
real signed bytes), envelopes, DeviceInfo beacons, policy bundles (verified against a **pinned** org
key, never one the payload asserts). `npm test` is the spine — it fails if the TS verifier and Rust
signer drift by one byte. The honest boundaries (tamper-*evidence* not tamper-proofing, pin your
signer, fail-open seams on Claude Code's side, the disclosed B0 bug) live in
[`docs/TRUST.md`](docs/TRUST.md) — we publish them rather than paper over them.

## Why now

**CMMC Level 2 enters new DoD contracts Nov 10, 2026** (Phase 2) — defense suppliers adopting agents
need AU-family evidence a C3PAO will credit, inside the boundary. EU AI Act record-keeping (high-risk
enforcement now Dec 2027 after the omnibus postponement), SOC 2, and ISO 42001 ask the same of any
agent touching real data. Pricing draft: [`docs/PRICING.md`](docs/PRICING.md) · GTM assets:
[`docs/gtm/`](docs/gtm/FEATURES.md) (features list, deck, playbooks, screenshots).

## How it relates to the open runtime

```
 open   kriya (MIT)       per action →  policy → approval → budget → Ed25519-signed receipt
                                           ▲                                   │
 paid   kriya-console     ── authors agent-policy.yaml ──┘                     │
                          ── aggregates + re-verifies the signed receipts ─────┘
                          ── evidence export · fleet cockpit · kriyad control plane
```

Dependency is **one-way**: the Console consumes the open `kriya` audit + policy formats; the public
repo never references this one. Don't copy proprietary code into the open repo, and don't relicense
the open SDK. The shared trust core lives in the `kriya-verify` crate (workspace member here).

## Develop

```bash
npm install
npm run tauri dev         # build + launch the desktop app
npm test                  # THE trust spine: TS verifier ↔ Rust signer parity + policy/approvals/compliance
npm run typecheck         # tsc --noEmit
cargo test                # workspace: app + kriya-verify + kriya-aggregator + kriya-audit-cli
cargo test --features control-plane   # + envelope/outbox/policy/fleet paths
npm run capture           # marketing stills of the free views (?capture=1 demo seed)
npm run capture:fleet     # marketing stills of the P2–P6 fleet cockpit (Playwright IPC stub)
```

## Layout

```
src/lib/                 verify.ts · envelope.ts · policyBundle.ts · policyDrift.ts · policy.ts ·
                         approvals.ts · compliance.ts · tauri.ts (bindings)
src/views/               Monitor · Coverage · Audit · Approvals · Policy · Budget · Identity ·
                         Reports(Evidence) · Fleet · ControlPlane{View,PolicyTab,EvidenceTab,DrillIn} ·
                         Connections · GetStarted · Settings
src-tauri/               the Tauri app (Rust): audit, paid.rs (evidence), license, govern, onboarding,
                         control_plane/ (compiler · envelope · redact · outbox · enrollment · policy ·
                         org_key · fleet · fleet_client · fleet_evidence · device_info · push)
src-tauri/crates/        kriya-verify (shared trust core, Tauri-free) · kriya-aggregator (kriyad) ·
                         kriya-audit-cli (offline re-prover)
test/                    TS↔Rust parity suites (receipts · envelopes · drift · org evidence · fixtures)
docs/                    TRUST · PRICING · ROADMAP · SETUP(root) · ideas/ (strategy, START AT ITS README) ·
                         gtm/ (FEATURES · deck · playbooks · screenshots)
demo/capture/            capture-shots.mjs (free views) · capture-fleet.mjs (fleet cockpit)
```

Enterprise & regulated deployments → [kriyanative.com](https://kriyanative.com) ·
**Sandeepshekhar26@gmail.com**.
