# kriya Console

**Proprietary — paid tier. Not open source.** All rights reserved; see [`LICENSE`](LICENSE).

> **The governance plane for on-device AI agents.** Where an organization oversees, governs, and
> *proves* what every agent did across every app it operates — built on the open-source
> [kriya](https://github.com/sandeepshekhar26/kriya) runtime. **The engine is open; the cockpit is paid.**

The open `kriya` runtime (MIT) makes a *single* app safely drivable by an agent: every action runs
through **policy → human approval → budget → an Ed25519-signed audit receipt**, on-device. That's the
adoption funnel. kriya Console is the layer **organizations pay for** — the cross-app cockpit that
aggregates those signed receipts, **re-verifies them locally**, lets you author the policy the
runtime enforces, routes approvals, and turns the whole trail into compliance evidence.

## Who it's for

Teams and regulated organizations running agents across **more than one** app, where *"an agent did
something"* is not enough — they must **prove what it did and constrain what it can do**, on-device,
where a cloud MCP gateway structurally can't reach. POS, CRM, finance, healthcare, legal, gov.

## What you can do today

| | The view | The value |
|---|---|---|
| **Oversee** | **Monitor** (home) | The live home: an auto-tailing stream of signed receipts **re-verified on-device**, posture at a glance (receipts, verified vs unverified, signers, coverage), and per-app **attestation continuity** — a colored band per receipt so a verification gap is obvious. |
| **Prove** | **Audit log** | Every signed receipt **verified on-device** against its embedded Ed25519 key — tampered or forged rows fail and get a tamper-flagged row. Filter by action / status / source app. |
| **Decide** | **Approvals** | One cross-app/agent queue for the actions a policy holds for a human — **risk-ranked** (destructive + financial first), per-app and per-agent, attributed to the requesting agent + operator, approve/deny with a recorded reason. **Role-gated** (RBAC): only an `approve`-capable role may decide. |
| **Constrain** | **Policy** | Author the `agent-policy.yaml` the runtime enforces: ordered Allow / Require-approval / Deny rules, one-click coverage for ungoverned actions, lint, per-minute action **and** per-hour api-call budget caps, import/export — with a live decision preview. |
| **Throttle** | **Budgets & rate** | Per-app / per-agent / per-operator usage against the rate caps — peak action rate, utilization, at-limit history. A scope *at* its cap is the host throttling it. |
| **Attribute** | **Identity & access** | Who operated each app — per-operator + per-agent dashboards from the signed `actor` (verified receipts only) — and **RBAC** roles (admin / approver / operator / viewer) keyed on the operator. |
| **Report** | **Evidence** | A report builder: pick a framework — **SOC 2 / ISO 42001 / EU AI Act** — and generate an auditor-ready bundle (control mapping, attribution, on-device attestations, action inventory), Markdown + JSON, on-device. |
| **Connect** | **Connections** | Add/manage **governed MCP connections** across the reach hierarchy: **kriya-native** (bolt-on), **proxy** any MCP server, or **govern a desktop app** via reach-in / computer-use. Wires `claude_desktop_config.json` and walks the macOS permissions for you. |

**Freemium:** the **free** tier is the live governance monitor, offline receipt verification, the
Connections manager, and guided setup — fully usable on its own. An **offline license** unlocks the
**compliance tier**: auditor-ready evidence export (**Evidence**) and cross-app correlation
(**Fleet**) across the apps on this machine. (Cross-*machine* fleet is on the roadmap; the license issuer/purchase path is a deferred
stub.)

Coming next: **SSO / OIDC** sign-in to back the RBAC roles — a **hosted-tier** feature, deliberately
gated to a concrete enterprise deal rather than built speculatively (the console currently sells on
"nothing leaves this machine"). See [`docs/ROADMAP.md`](docs/ROADMAP.md).

## See it in 30 seconds

Download and open the Console desktop app. It opens on the **Monitor** — it **auto-discovers and
tails the standard on-device audit location (`~/.kriya/audit/`)** — no import, no log-hunting — and
re-verifies every receipt on-device in its compiled backend. Then walk
**Monitor → Audit → Approvals → Policy → Budgets → Identity → Evidence**, and add a governed app from
**Connections**. Press **⌘K** to jump anywhere. To produce marketing screenshots, see
[`docs/screenshots/CAPTURE.md`](docs/screenshots/CAPTURE.md).

Developer path (run from source):

```bash
npm install
npm run tauri dev      # build + launch the desktop control-plane app
```

## The trust spine — verify, don't trust

The product's spine is **local, independent verification**: every "the agent did X" traces to a
signed receipt the Console re-verifies **on-device in its compiled (Rust/Tauri) backend**, and every
policy it shows decides *identically* to the host. Verification is proven **byte-identical** against
the host's canonical signing (`crates/kriya/src/audit.rs`) on real Rust-signed receipts in the test
suite, and the policy model is a parity-tested port of `permissions.rs`. Nothing leaves the
machine.

What that proof does — and, honestly, does **not** — guarantee (pin your signer; whole-record
deletion needs the R20 hash-chaining; full-host-compromise is out of scope) is written up for
security reviewers in **[`docs/TRUST.md`](docs/TRUST.md)**. We publish the boundaries rather than
paper over them — enterprise buyers reward the candor.

## Why now

**EU AI Act** high-risk obligations take effect **August 2, 2026** (penalties up to 7% of worldwide
turnover); **SOC 2** monitoring and **ISO 42001** ask the same of any agent touching real data. The
Console is buy-not-build governance plus cryptographic, tamper-evident audit — the willingness-to-pay
surface those mandates create, on-device. Pricing (open-core tiers) is drafted in
[`docs/PRICING.md`](docs/PRICING.md).

## How it relates to the open runtime

```
 open   kriya (MIT)       per action →  policy → approval → budget → Ed25519-signed receipt
                                           ▲                                   │
 paid   kriya-console     ── authors agent-policy.yaml ──┘                     │
                          ── aggregates + re-verifies the signed receipts ─────┘
                          ── routes approvals · exports compliance evidence
```

Dependency is **one-way**: the Console consumes the open `kriya` audit + policy formats; the public
repo never references this one. Don't copy proprietary code into the open repo, and don't relicense
the open SDK. (Split + rationale: runtime repo `docs/LICENSING.md`, decision **D-011**.)

## Develop

```bash
npm test              # verifier + policy + approvals + compliance — cross-checked against the Rust host
npm run tauri dev     # build + launch the desktop control-plane app
npm run build         # typecheck (tsc --noEmit) + production build
npm run demo:approvals    # walk the approval-routing flow in the terminal
npm run demo:compliance   # print a full compliance-evidence report
```

`npm test` is the spine: it proves the TS verifier agrees with the Rust signer on real receipts (and
rejects tampered ones), and that the policy model decides + lints identically to the host.

## Layout

```
src/lib/verify.ts        canonical bytes + Ed25519 verification (the trust core)
src/lib/policy.ts        policy model: rules, decide(), lint — a port of permissions.rs
src/lib/approvals.ts     approval queue: risk ranking, routing, persistence
src/lib/compliance.ts    verified trail → SOC 2 / ISO 42001 / EU AI Act evidence bundle
src/lib/receipts.ts      parse a JSONL log → verified rows
src/views/               Monitor · Audit · Approvals · Policy · Budget · Identity · Reports(Evidence) · Fleet · Connections · Settings
src/components/          Sidebar · Icon · CommandPalette · AuditTable · LicenseGate
src/styles.css           the design system — light-first tokens, one rationed accent, hairline structure
src/sample/              real Rust-signed receipts (zero-setup demo + test fixtures)
test/                    verify · policy · approvals · compliance · actor (parity with the Rust host)
docs/                    ROADMAP · TRUST · PRICING · screenshots/CAPTURE
```

Enterprise & regulated deployments → [kriyanative.com](https://kriyanative.com) ·
**Sandeepshekhar26@gmail.com**.
