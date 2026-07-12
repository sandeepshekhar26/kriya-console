# kriya Console

**Proprietary — paid tier. Not open source.** All rights reserved; see [`LICENSE`](LICENSE).
Built on the open-source [kriya](https://github.com/sandeepshekhar26/kriya) runtime (MIT).
**The engine is open; the cockpit is paid.**

> **Your AI agents act on your machine. kriya controls what they can do — and gives you signed
> proof of what they did.** Everything runs on your device or your own server. Nothing goes to
> our cloud, because we don't have one.

**Current release: v0.2.3** — signed + notarized macOS app.
[Download the latest DMG](https://github.com/sandeepshekhar26/kriya/releases/tag/console-v0.2.3) ·
[kriyanative.com](https://kriyanative.com)

---

## The problem

You let an AI agent loose on your laptop — Claude Code, Hermes, an MCP server, a desktop app.
It edits files, calls APIs, spends money, talks to the internet. Then someone asks a simple
question:

> *"What exactly did the agent do — and can you prove it?"*

A chat transcript is not proof. A plain log file can be edited after the fact. And "we trust the
vendor's dashboard" doesn't work when your rules say agent activity can't leave the building at
all (defense, government, healthcare, banks, air-gapped sites).

kriya answers that question with cryptography instead of trust: **every agent action passes
through a policy check, an optional human approval, and a budget cap — and comes out the other
side as a signed, tamper-evident receipt you can re-verify yourself, offline.**

## What kriya does, in one minute

- **See** — a live view of every action every governed agent takes on the machine, each one
  signature-checked as it appears. Edited or faked entries show up red.
- **Control** — you write the rules: *allow this, ask a human for that, never allow those.* The
  open runtime enforces them. Runaway agents hit rate and budget caps.
- **Approve** — dangerous actions (deleting things, moving money) pause until a person says yes.
  Who approved, and why, becomes part of the permanent record.
- **Prove** — one click turns the verified record into compliance evidence (CMMC/NIST 800-171,
  SOC 2, ISO 42001, EU AI Act) that an auditor can independently re-check with a free CLI tool.
- **Scale** — the same story across a whole fleet of machines, aggregated on **your** server
  (`kriyad`), on-prem or fully air-gapped. Never our cloud.

## Quick start

**Use it (macOS):**

1. [Download the DMG](https://github.com/sandeepshekhar26/kriya/releases/tag/console-v0.2.3) and open **kriya Console**.
2. Click **Govern All**. The Console detects the agents on your Mac (Claude Code, Hermes) and
   wires them into governance in one click — reversible, no config files to edit.
3. Use your agents as normal. Watch the **Monitor** view fill with live, signed, verified receipts.

The free tier needs no account, no license, and opens no network connection — that's
[dormancy-tested](docs/TRUST.md), not a promise.

**Develop:**

```bash
npm install
npm run tauri dev   # build + launch the desktop app
npm test            # THE trust spine: TS verifier ↔ Rust signer byte parity
```

New machine or new contributor? Start at [`SETUP.md`](SETUP.md). Strategy or product questions?
Start at [`docs/ideas/README.md`](docs/ideas/README.md) — the repo, not memory, is the source of
truth ([`CLAUDE.md`](CLAUDE.md)).

## What it does

### 1. See everything your agents do

| Feature | In plain terms |
|---|---|
| **Monitor** (home view) | Opens on a live feed of agent activity on this machine. Every entry is re-verified against its signature as it arrives — you're watching checked facts, not trusted logs. |
| **Audit log** | The full searchable history. Any receipt that was altered, forged, or signed by an unexpected key is flagged red on sight. Deleting or reordering records breaks a hash chain and gets flagged too. |
| **Coverage Map** | The honest view of what *isn't* recorded. Six lanes (Claude Code, remote MCP, local MCP, desktop apps, file & exec, network egress) each show GREEN / AMBER / GREY — and every change to that map is itself a signed receipt, so nobody can quietly claim coverage they didn't have. |

### 2. Control what agents are allowed to do

| Feature | In plain terms |
|---|---|
| **Policy** | Write ordered rules — *allow*, *require approval*, *deny* — with live preview and linting. The Console authors the exact policy file the open runtime enforces. Fails closed on errors. |
| **Approvals** | One queue, across all agents, ranked by risk. Destructive and financial actions wait for a human; the decision, the person, and the reason are recorded and signed. |
| **Budgets & rate caps** | A runaway agent stops at the cap, not at your data. Per-app, per-agent, per-operator usage against limits, visible at all times. |
| **Identity & access** | Who ran what — per human operator and per agent — computed only from verified receipts. Console roles: admin / approver / operator / viewer. |

### 3. Wire it up without pain

| Feature | In plain terms |
|---|---|
| **Govern All** | One button: detect the agents on this Mac and wire hooks + gateway + policy for all of them. Reversible. |
| **Connections** | Add and manage governed MCP servers without hand-editing JSON config files; walks you through macOS permissions. |
| **Broad agent coverage** | Claude Code (native hook — every tool call, including subagents and headless runs), Hermes, any MCP server via the zero-change gateway, and no-API desktop apps via computer-use. Vendor-neutral by design. |

### 4. Prove it to an auditor *(paid tier)*

| Feature | In plain terms |
|---|---|
| **Evidence export** | 19 controls across 5 frameworks — NIST 800-171 / CMMC L2 (AU 3.3.1–3.3.9), SOC 2, ISO 42001, EU AI Act, data-residency. Every control's status is **computed from re-verified receipts**, never typed in. Gaps are shown, not hidden. Markdown + JSON. |
| **Auditor CLI** (`kriya-audit`, free) | *Don't trust us — check.* A standalone offline tool any assessor can run to re-prove the receipts, the fleet envelopes, and a server read-back. Exit 0 or exit 1. |
| **Fleet correlation (this machine)** | One posture number per Mac: verified vs failed, signers seen, share of actions under policy. |

### 5. Run a whole fleet from your own server *(paid tier)*

| Feature | In plain terms |
|---|---|
| **`kriyad` aggregator** | One static binary on **your** infrastructure — box, Kubernetes, or fully air-gapped. It verifies everything it ingests and stores only signed bytes. It holds no signing keys, so it **can author nothing**: a compromised server can delay evidence, never forge it. |
| **Fleet cockpit** | Every enrolled device on one screen: alive or silent, versions, which agents are wired (and which aren't). Drill into any device's signed evidence chain. |
| **Central policy, signed** | Author policy once, sign it with an org key **only you hold**, and the fleet converges on it — every device verifies the signature, applies locally, and emits a signed "applied" receipt. Anti-rollback built in. An admin never walks 500 laptops. |
| **Drift view** | "Is the fleet actually on policy v13?" answered from each device's own signed statements — not the server's word. Disagreements get a loud mismatch badge. |
| **Org-wide evidence** | The export a CMMC assessor asks the *organization* for: fleet coverage (silent devices named honestly as red cells), AU-family + CM-family, computed across every machine. |
| **Privacy by structure** | What leaves each device is a minimized, allowlisted summary — raw parameters and operator names **cannot** leave; the schema has no field to put them in. Operators become pseudonyms. Survives a works-council review. |

### 6. Control what leaves the machine — egress governance 🔨 *(in build — the current engineering push; nothing in this section ships in v0.2.3)*

The next release closes the loop from *"what did the agent do"* to *"what did the agent send, and
to whom"* — at full feature parity with the strongest egress tools, plus one thing nobody else
has:

| Feature | In plain terms |
|---|---|
| **Egress allowlist** | Deny-by-default outbound rules by destination: agents talk only to the hosts you listed. |
| **"No receipt, no egress"** ⭐ | The kriya-native inversion: the signed receipt is a **precondition** of the network call. If the tamper-evident record can't be written, the byte doesn't leave. Competitors log what their firewall did; kriya makes the proof the gate. |
| **Byte budgets** | Per-destination caps that catch slow-drip exfiltration, not just single big leaks. |
| **Ask-before-send** | Unknown destination? The call parks and a human decides — same approval flow as everything else. |
| **Secret / PII scanning** | Outbound bodies scanned for credentials and personal data: redact or deny per policy. Only a hash and a match-type are ever stored — never the secret itself. |
| **Exfiltration detection** | DNS-tunnel patterns, anomalous destinations, canary tokens that trip a loud alarm the moment they leave. |
| **SSRF & rebinding guard** | Private-IP, cloud-metadata, and DNS-rebinding attempts blocked on governed lanes. |
| **Connector registry** | A new MCP server or tool is **disabled until a human approves it**, and tool descriptions are scanned for drift and poisoning. |
| **Operation rails** | Allow or deny specific outbound API operations — down to the HTTP verb, path, or GraphQL mutation. |
| **Credential brokering** | The agent holds a placeholder; the real secret is injected only at the moment of egress. The agent never sees your keys. |
| **OS containment** | Launch agents inside a sandbox that *forces* their traffic through the governed lane — turning all of the above from "observed" into "enforced" for everything kriya launches. |
| **Fleet egress** | The allowlist, the kill-switch, and the egress evidence, distributed and rolled up across the fleet. |

Honest scope, stated up front: until containment lands, these controls cover the **governed
lanes** (what routes through kriya's hook, gateway, and broker) — a determined agent spawning raw
processes can bypass a lane; containment is what closes that. Status and design:
[doc 24](docs/ideas/24-egress-study.md).

## How it works

```
your agents                 the open kriya runtime (MIT)                 kriya Console (this app)
Claude Code · Hermes        every action:                                re-verifies every receipt
MCP servers · desktop  ──▶  policy → approval → budget → Ed25519-  ──▶   on-device · authors policy
apps                        signed, hash-chained receipt                 approvals · evidence export
```

And for a fleet:

```
each device (Console)                your kriyad (on-prem / air-gap)          operator (Console cockpit)
verified receipts                    mTLS · verifies all ingest               fleet · drift · org evidence
 └→ minimized signed envelopes ────▶ append-only, signed bytes only ◀──────── author policy → org-key sign
 ◀── org-key-signed policy (pull on heartbeat · verify · anti-rollback · apply · signed receipt)
```

Three design laws hold everywhere:

1. **Verify, don't trust.** Every claim on every screen traces to a signed artifact re-verified
   locally. `npm test` proves the TypeScript verifier and the Rust signer agree byte-for-byte.
2. **The server authors nothing.** Evidence is signed by devices, policy by the operator's org
   key. `kriyad` holds neither key — it can withhold, never invent, and withholding is caught.
3. **Your data stays yours.** Free tier: nothing leaves the machine, ever. Fleet tier: minimized
   evidence moves only to *your* server. Air-gap: signed files on approved media, same verifier.

## What it does *not* do (read this)

We publish our limits instead of papering over them — [`docs/TRUST.md`](docs/TRUST.md) is
canonical:

- **Tamper-evidence, not tamper-proofing.** Altered, forged, or deleted receipts are *detected*.
  A fully compromised host that holds the signing key is out of scope — pin your signer.
- **kriya sees governed lanes.** Actions that route through the hook, gateway, or SDK are
  recorded; the Coverage Map shows honestly what doesn't. GREEN means "the watcher was up," not
  "physics guarantees capture."
- **Seams belong to their owners.** Claude Code's own hook timeout fails open on *its* side;
  whoever controls its settings file has the last word there. kriya fails closed on its own errors.
- **Evidence, not certification.** Every export says so in the footer. Controls kriya can't
  earn (e.g. OS-level audit-role separation, 3.3.9) are shown as permanent, visible gaps.
- **No egress claims today.** Until the egress build ships, kriya does not claim SC-7, DLP, or
  boundary enforcement — and even after, enforcement verbs stay scoped to the lanes that actually
  enforce.

## Free vs paid

| | Free (no account, no license) | Paid (offline license) |
|---|---|---|
| Monitor, Audit, Coverage Map | ✅ | ✅ |
| Policy, Approvals, Budgets, Identity | ✅ | ✅ |
| Govern All, Connections, guided setup | ✅ | ✅ |
| Auditor CLI | ✅ | ✅ |
| Evidence export (5 frameworks) | — | ✅ |
| Fleet cockpit + `kriyad` control plane | — | ✅ (`fleet-console`) |

The license is an Ed25519-signed offline token — no phone-home, no accounts. Licensed via
design-partner engagements today (not self-serve yet). Draft pricing:
[`docs/PRICING.md`](docs/PRICING.md).

## How it compares

| | Vendor dashboards / lab logs | Cloud GRC (Vanta, Drata) | Egress proxies / firewalls | **kriya** |
|---|---|---|---|---|
| Works where data can't leave the building | ❌ | ❌ | some | ✅ built for it |
| Governs a *competitor's* agent too | ❌ | partial | ✅ | ✅ vendor-neutral |
| Record is independently re-verifiable | ❌ trust us | ❌ trust us | some (signed logs) | ✅ offline, free CLI |
| Sees agent *decisions* (hook seam), not just packets | ❌ | ❌ | ❌ | ✅ |
| Maps evidence to CMMC / SOC 2 / ISO 42001 / EU AI Act | ❌ | ✅ cloud-resident | ❌ | ✅ on-device |
| Proof is a precondition of the action | ❌ | ❌ | ❌ | ⭐ "no receipt, no egress" (in build) |

## Who it's for

Teams where *"an agent did something"* is not an acceptable answer — they must **prove what it
did and constrain what it can do**. Sharpest fit: organizations that legally can't ship agent
activity to a cloud dashboard (defense/CMMC, sovereign, air-gapped). **CMMC Level 2 enters new
DoD contracts Nov 10, 2026** — kriya installs where a cloud governance product structurally can't.

## Relationship to the open runtime

Dependency is **one-way**: the Console consumes the open `kriya` audit + policy formats; the
public repo never references this one. The shared trust core is the `kriya-verify` crate
(workspace member here). Don't copy proprietary code into the open repo.

## Develop & layout

```bash
npm install && npm run tauri dev      # the desktop app
npm test                              # trust spine: TS ↔ Rust byte parity + policy/approvals/compliance
npm run typecheck                     # tsc --noEmit
cargo test --features control-plane   # workspace incl. envelope/outbox/policy/fleet paths
npm run capture && npm run capture:fleet   # marketing stills (free views · fleet cockpit)
```

```
src/lib/          verify · envelope · policyBundle · policyDrift · policy · approvals · compliance
src/views/        Monitor · Coverage · Audit · Approvals · Policy · Budget · Identity · Reports ·
                  Fleet · ControlPlane · Connections · GetStarted · Settings
src-tauri/        Rust backend: audit · paid (evidence) · license · govern · onboarding · control_plane/
src-tauri/crates/ kriya-verify (shared trust core) · kriya-aggregator (kriyad) · kriya-audit-cli
test/             TS↔Rust parity suites (receipts · envelopes · drift · org evidence)
docs/             TRUST · FEATURE-PROOF (the claim→proof ledger) · PRICING · ROADMAP ·
                  ideas/ (strategy — start at its README) · gtm/
```

---

Enterprise & regulated deployments → [kriyanative.com](https://kriyanative.com) ·
**Sandeepshekhar26@gmail.com**
