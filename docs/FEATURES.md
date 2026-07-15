# kriya Console — every feature, in plain words

kriya governs the AI agents that act on your machine: every action passes a **policy check**, an
optional **human approval**, and a **budget cap**, and comes out the other side as a **signed,
tamper-evident receipt** you can re-verify yourself, offline. Everything runs on your device or
your own server — there is no vendor cloud to trust.

Status labels, used honestly:

- ✅ **Shipped** — in the current notarized DMG (v0.2.4).
- 🟢 **Merged** — built, tested, and merged on `main`; ships in the next DMG.
- 🧭 **Roadmap** — not built; we don't sell it.

Every ✅/🟢 claim traces to a test, a signed sample, or a public release —
[`FEATURE-PROOF.md`](FEATURE-PROOF.md) is the claim→proof ledger.

---

## 1 · See everything your agents do — ✅ free

- **Monitor** — a live feed of every action every governed agent takes on this machine. Each row is
  re-verified against its cryptographic signature as it arrives: you watch checked facts, not a
  trusted log file.
- **Audit log** — the full searchable history. An altered, forged, or wrong-key receipt is flagged
  red on sight; deleting or reordering records breaks a hash chain and is flagged too.
- **Coverage Map** — the honest view of what *isn't* recorded. Six lanes (Claude Code, remote MCP,
  local MCP, desktop apps, file & exec, network egress) each show GREEN / AMBER / GREY, and every
  change to the map is itself a signed receipt — nobody can quietly claim coverage they didn't have.

## 2 · Control what agents may do — ✅ free

- **Policy** — ordered *allow / require-approval / deny* rules with live preview and linting. The
  Console authors the exact policy file the open runtime enforces. Fails closed on errors.
- **Approvals** — one queue across all agents, ranked by risk. Destructive and financial actions
  wait for a human; the decision, the person, and the reason become part of the signed record.
- **Budgets & rate caps** — a runaway agent stops at the cap, not at your data.
- **Identity** — who ran what, per human operator and per agent, computed only from verified
  receipts. Console roles: admin / approver / operator / viewer.

## 3 · Wire it up without pain — ✅ free

- **Govern All** — one button: detect the agents on this Mac (Claude Code, Hermes) and wire hooks +
  gateway + policy for all of them. Reversible.
- **Connections** — add governed MCP servers without hand-editing JSON; walks you through macOS
  permissions.
- **Broad coverage** — Claude Code (native hook: every tool call, including subagents and headless
  runs), Hermes, any MCP server via the zero-change gateway, and no-API desktop apps via
  computer-use. Vendor-neutral by design.

## 4 · Prove it to an auditor — ✅ paid (CLI free)

- **Evidence export** — 19 controls across 5 frameworks (NIST 800-171 / CMMC L2, SOC 2, ISO 42001,
  EU AI Act, data-residency). Every control's status is **computed from re-verified receipts**,
  never typed in. Gaps are shown, not hidden.
- **Auditor CLI** (`kriya-audit`, free) — *don't trust us: check.* A standalone offline tool any
  assessor can run to re-prove receipts, fleet envelopes, and a live server read-back. Exit 0 or 1.
- **Machine posture** — one number per Mac: verified vs failed, signers seen, share of actions
  under policy.

## 5 · Run a whole fleet from your own server — ✅ paid

- **`kriyad` aggregator** — one static binary on **your** infrastructure: box, Kubernetes, or fully
  air-gapped. It verifies everything it ingests, stores only signed bytes, and holds no signing
  keys — a compromised server can delay evidence, never forge it.
- **Fleet cockpit** — every enrolled device on one screen: alive or silent, versions, which agents
  are wired. Drill into any device's signed evidence chain.
- **Central policy, signed** — author once, sign with an org key only you hold; every device
  verifies, applies, and emits a signed "applied" receipt. Anti-rollback built in.
- **Drift view** — "is the fleet actually on policy v13?" answered from each device's own signed
  statements, not the server's word.
- **Org-wide evidence** — the export a CMMC assessor asks the organization for, computed across
  every machine; silent devices are named honestly as red cells.
- **Privacy by structure** — what leaves each device is a minimized, allowlisted summary. Raw
  parameters and operator names **cannot** leave: the schema has no field to put them in.

## 6 · Control what leaves the machine — ✅ shipped in v0.2.4

The egress pack closes the loop from *"what did the agent do"* to *"what did it send, and to
whom."*

- **Egress allowlist** — deny-by-default outbound rules: agents talk only to hosts you listed.
- **"No receipt, no egress"** ⭐ — the inversion nobody else has: the signed receipt is a
  **precondition** of the network call. If the tamper-evident record can't be written, the byte
  doesn't leave. Others log what their firewall did; kriya makes the proof the gate.
- **Byte budgets** — per-destination caps that catch slow-drip exfiltration, not just big leaks.
- **Ask-before-send** — unknown destination? The call parks until a human decides, in the same
  approval queue as everything else.
- **Secret & PII scanning** — outbound bodies scanned for credentials and personal data; redact or
  deny per policy. Only a hash and a match-type are stored — never the secret.
- **Exfiltration detection** — DNS-tunnel patterns, anomalous destinations, and canary tokens that
  trip a signed alarm the moment they leave.
- **SSRF & rebinding guard** — private-IP, cloud-metadata, and DNS-rebinding attempts blocked on
  governed lanes.
- **Connector registry** — a new MCP server or tool is disabled until a human approves it; tool
  descriptions are scanned for drift and poisoning.
- **Operation rails** — allow or deny specific outbound operations, down to the HTTP verb, path,
  or GraphQL mutation.
- **Credential brokering** — the agent holds a placeholder; the real secret (kept in the OS
  keychain) is injected only at the moment of egress. The agent never sees your keys. Own threat
  model: [`THREAT-MODEL-brokering.md`](THREAT-MODEL-brokering.md).
- **OS containment** — launch an agent with `kriya-gateway run -- <agent>` and a generated macOS
  Seatbelt profile forces its traffic through the governed lane — turning the controls above from
  *observed* into *enforced* for everything kriya launches.
- **Fleet egress + kill switch** — the allowlist, budgets, kill-switch, and egress evidence,
  distributed and rolled up across the fleet under the same signed policy bundle.
- **Fleet destination visibility** — a privacy-minimized pattern-echo of destinations in the
  fleet envelopes, so the cockpit can answer "which hosts is the fleet talking to" without raw
  parameters ever leaving a device.

**Honest scope, stated first:** these controls cover the governed lanes — what routes through
kriya's hook, gateway, and broker, plus anything launched under containment. A determined agent
spawning raw processes outside a contained session can bypass a lane; the Coverage Map shows that
honestly instead of papering over it. kriya does not claim host-wide DLP or network-boundary
enforcement. Full limits: [`TRUST.md`](TRUST.md).

---

## Free vs paid

| | Free (no account, no license, no network) | Paid (offline license) |
|---|---|---|
| Monitor, Audit, Coverage Map | ✅ | ✅ |
| Policy, Approvals, Budgets, Identity | ✅ | ✅ |
| Govern All, Connections, egress controls | ✅ | ✅ |
| Auditor CLI | ✅ | ✅ |
| Evidence export (5 frameworks) | — | ✅ |
| Fleet cockpit + `kriyad` control plane | — | ✅ |

The license is an Ed25519-signed offline token — no phone-home, no accounts.
Releases: [`CHANGELOG.md`](../CHANGELOG.md) · Setup: [`SETUP.md`](../SETUP.md) ·
Site: [kriyanative.com](https://kriyanative.com)
