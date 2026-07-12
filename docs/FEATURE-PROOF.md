# Feature proof ledger — every claim, its category, its proof

> **The single canonical claim → proof table.** Every feature kriya presents anywhere (README,
> decks, website, outreach) appears here **once**, categorized **NON-EGRESS** (the shipped
> control-and-proof product) or **EGRESS** (the doc-24 build-first parity set), with the concrete
> artifact that proves it: a test suite, a code path, a signed sample, a screenshot, or a public
> release. **Rule: a feature may be claimed only as far as its proof cell is real.** If a claim
> and this ledger disagree, the ledger wins; if this ledger and [`TRUST.md`](TRUST.md) disagree,
> TRUST.md wins.
>
> Companions: [`gtm/FEATURES.md`](gtm/FEATURES.md) (the GTM framing: why a buyer cares),
> [doc 24](ideas/24-egress-study.md) (the egress build plan §9 / feature spec §11).
> Current release: **Console v0.2.3**
> ([public DMG](https://github.com/sandeepshekhar26/kriya/releases/tag/console-v0.2.3)) ·
> auditor CLI **audit-v0.1.0**.

**Status legend:** ✅ shipped (v0.2.3 or earlier) · 🔨 in build (doc-24 egress push, phase named) ·
🕓 demand-gated (designed, not building yet).
**Proof types:** `test:` a suite in this repo (`npm test` / `cargo test`) · `code:` the
implementing path · `artifact:` a signed sample or release anyone can re-verify · `shot:` a
captured screenshot · `open:` proven in the public [kriya](https://github.com/sandeepshekhar26/kriya)
runtime repo.

---

## PART A — NON-EGRESS (shipped: control + proof, device → fleet)

### A1. Govern — the enforcement layer (open runtime, free)

| # | Feature | Status | Proof |
|---|---|---|---|
| A1.1 | Governance gateway — wrap any MCP server, zero changes; policy → approval → budget → signed receipt on every tool call | ✅ | `open:` kriya repo `kriya-gateway` + its tests; receipts it emits verify in `test:verify.test.ts` |
| A1.2 | Govern Claude Code — PreToolUse hook on every tool call (subagents + headless verified) | ✅ | `open:` kriya repo `kriya-hook` (isError fix landed 2026-07-03); `shot:docs/screenshots/connections.png` |
| A1.3 | Govern Hermes — gateway (zero-change) + native-tool hook since v0.2.2 | ✅ | `open:` kriya repo `kriya-hermes-hook`; doc 21 Part B verification record |
| A1.4 | Govern desktop / no-API apps (computer-use, accessibility tree) | ✅ | `open:` kriya runtime reach-in drivers; demo `demo/kriya-gui-demo.mp4` |
| A1.5 | Policy engine — ordered allow / require-approval / deny, deny-by-default, **fail-closed on kriya's own errors** (B0 fixed + regression-tested) | ✅ | `test:policy.test.ts` · `code:src/lib/policy.ts` · B0 regression matrix (doc 22) · `shot:docs/screenshots/policy.png` |
| A1.6 | Human approval gate — pause for a person, 300s self-bound, fail-closed on timeout | ✅ | `open:` runtime ApprovalGate tests · `test:approvals.test.ts` (Console queue/record) |
| A1.7 | Budgets & rate caps (denial-of-wallet stop) — **egress-parity item B15, already shipped** | ✅ | `test:budget.test.ts` · `shot:` Budget view via `npm run capture` |
| A1.8 | Ed25519-signed, hash-chained receipts (`prev_hash` inside the signed bytes) | ✅ | `test:verify.test.ts` (TS↔Rust byte parity on real signed bytes; tamper → red) · `code:src-tauri/crates/kriya-verify` |
| A1.9 | SDK `registerAction` / `wrapAction` for in-process governance | ✅ | `open:` kriya repo SDK tests; Actual Budget integration (~37 lines) |
| A1.10 | Broad agent coverage (Claude Code, Hermes, any MCP client, desktop) — **egress-parity item B17, already shipped** | ✅ | union of A1.1–A1.4; Coverage Map lanes (A2.3) |

### A2. See — the live cockpit (Console, free)

| # | Feature | Status | Proof |
|---|---|---|---|
| A2.1 | Monitor — auto-tail `~/.kriya/audit/`, re-verify every receipt on-device, live posture | ✅ | `code:src/views/Monitor` + `src-tauri/audit.rs` · `shot:docs/screenshots/monitor.png` |
| A2.2 | Audit log — per-receipt signature check, tampered/forged rows red, chain-break flagging | ✅ | `test:verify.test.ts` · `artifact:` tamper-a-byte demo in release audit-v0.1.0 · `shot:docs/screenshots/audit.png` |
| A2.3 | Coverage Map — six lanes GREEN/AMBER/GREY; every state change is itself a signed `coverage.snapshot` receipt in its own chain | ✅ | `test:coverage-fixture.test.ts`, `p2-era-coverage-fixture.test.ts` · `code:src-tauri/coverage.rs` |
| A2.4 | Govern All — detect agents on the machine, wire hooks + gateway + policy in one click, reversibly | ✅ | `test:govern.test.ts`, `govern-view.test.ts` · `code:src-tauri/govern.rs` |
| A2.5 | Connections — managed MCP wiring, `claude_desktop_config.json`, macOS permission walkthrough | ✅ | `code:src/views/Connections` · `shot:docs/screenshots/connections.png` |
| A2.6 | Guided setup / onboarding | ✅ | `code:src-tauri/onboarding.rs` |

### A3. Decide & attribute (Console, free)

| # | Feature | Status | Proof |
|---|---|---|---|
| A3.1 | Approvals queue — cross-app, risk-ranked, RBAC-gated; decision + reason recorded (a queue/record; live remote-unblock = P7, 🕓) | ✅ | `test:approvals.test.ts` · `shot:docs/screenshots/approvals.png` |
| A3.2 | Identity & access — per-operator / per-agent dashboards from the signed `actor`; roles admin/approver/operator/viewer | ✅ | `test:identity.test.ts`, `actor.test.ts` |
| A3.3 | Budgets & rate view — usage vs caps, at-limit history | ✅ | `test:budget.test.ts` |

### A4. Prove — the compliance tier (paid license; verification itself stays free)

| # | Feature | Status | Proof |
|---|---|---|---|
| A4.1 | Evidence export — 19 controls / 5 frameworks (NIST 800-171/CMMC AU 3.3.1–3.3.9, SOC 2, ISO 42001, EU AI Act, residency), statuses **computed from re-verified receipts**; 3.3.9 a permanent visible gap; footer "evidence, not a certification" | ✅ | `test:compliance.test.ts` · `code:src-tauri/paid.rs` · `shot:docs/screenshots/evidence.png` |
| A4.2 | Auditor CLI `kriya-audit` — offline re-prover (receipts, envelopes, kriyad read-back), exit 0/1 | ✅ | `code:src-tauri/crates/kriya-audit-cli` · `artifact:` public release **audit-v0.1.0** with sample evidence + tamper demo |
| A4.3 | Assessor sample pack — 28 receipts, 1 deliberately tampered, test-guarded, never in the build | ✅ | `artifact:docs/gtm/samples/au-family-sample` · `test:au-family-sample.test.ts`, `no-sample-in-build.test.ts` |
| A4.4 | Cross-app fleet correlation (this machine) — verified/failed, signers, policy coverage | ✅ | `code:src/views/Fleet` · `test:` rollups in `compliance.test.ts` |
| A4.5 | Offline license — Ed25519-signed token, no phone-home, no accounts | ✅ | `code:src-tauri/license.rs` (self-serve checkout 🕓 — R0) |

### A5. Fleet control plane (paid `fleet-console`; P0–P6 shipped)

| # | Feature | Status | Proof |
|---|---|---|---|
| A5.1 | `kriyad` aggregator — customer-run static binary (BOX/K8S/air-gap), mTLS everywhere, verifies all ingest, append-only, **authors nothing** (holds no keys) | ✅ | `code:src-tauri/crates/kriya-aggregator` · `cargo test --features control-plane` |
| A5.2 | Evidence Compiler + enforced redaction — allowlist drop-by-default minimized `AttestationEnvelope`s; params/operator names structurally cannot leave; hash-chained outbox | ✅ | `test:envelope.test.ts` · `code:control_plane/{compiler,envelope,redact,outbox}.rs` |
| A5.3 | Device inventory beacon — signed `DeviceInfo`, GDPR-allowlisted schema with **no field** for usernames/hostnames/IPs/serials | ✅ | `test:device-info-fixture.test.ts` · `code:control_plane/device_info.rs` (adversarially tested) |
| A5.4 | Fleet table cockpit — liveness, versions + update badges, agent chips, drill-in to signed chains | ✅ | `code:src/views/ControlPlane*` · `shot:docs/gtm/screenshots/fleet-*.png` (`npm run capture:fleet`) |
| A5.5 | Central policy authoring + org-key-signed downlink — pull on heartbeat, verify against a **pinned** org key, anti-rollback, signed `policy.applied` receipt; air-gap = signed file | ✅ | `test:policy-bundle.test.ts` · `code:control_plane/{org_key,policy}.rs` · `shot:fleet-policy-author.png` |
| A5.6 | Policy-drift view — verdict from each device's own re-verified envelopes; kriyad's row only a hint; mismatch badge on disagreement | ✅ | `test:policyDrift.test.ts` · `shot:fleet-drift.png` |
| A5.7 | Org-wide evidence export — AU fleet-wide + CM 3.4.1/3.4.2 from the signed policy chain; silent devices named as red cells | ✅ | `test:orgEvidence.test.ts` · `code:control_plane/fleet_evidence.rs` · `shot:fleet-org-evidence.png` |
| A5.8 | mTLS cert-role separation — device certs can't read the fleet; operator certs can't post evidence; fail-closed per route | ✅ | `cargo test` (aggregator route guards, P6) |
| A5.9 | Zero-egress attestation (air-gap posture only) — signed proof nothing left; free tier opens **no socket at all** | ✅ | dormancy guard (`code:src-tauri/control_plane.rs`; free build links no fleet networking — [`TRUST.md`](TRUST.md)) |
| A5.10 | Remote approvals (P7) — operator-signed verdict unblocks a paused device action | 🕓 | design partner gate (doc 22) |
| A5.11 | Enrollment CA/CRL · HSM issuer · MDM zero-touch · SSO/OIDC (phases 3–5) | 🕓 | demand-pulled (doc 14) |

### A6. The trust spine (cross-cutting, free — what makes every row above checkable)

| # | Feature | Status | Proof |
|---|---|---|---|
| A6.1 | TS ↔ Rust canonical byte parity on every signed artifact type (receipts, envelopes, device-info, policy bundles) | ✅ | `npm test` — fails on one byte of drift; cross-version fixtures in `test/fixtures` |
| A6.2 | Three independent verifications for evidence (device → kriyad ingest → cockpit/auditor); two for policy (ingest → device apply) | ✅ | union: `verify`, `envelope`, `policy-bundle` suites + aggregator `cargo test` |
| A6.3 | Published honest limits — tamper-**evidence** not proofing; pin your signer; seams fail-open on their owners' side; disclosed shipped bugs (B0) | ✅ | [`TRUST.md`](TRUST.md) (canonical) |

---

## PART B — EGRESS (doc-24 build-first parity set: in build now, sold only when real)

> The founder decision of 2026-07-12 ([doc 24 exec summary](ideas/24-egress-study.md)): build the
> **complete** egress feature set B1–B18 to full competitive parity, **then** sell. Until a row
> below flips ✅ with a real proof cell, it is presented everywhere as *in build* — never shipped.
>
> **2026-07-12 late: EG-2 (runtime, kriya#5) + EG-3 (console, PR #19) LANDED** — the signed
> `kriya.io.<direction>.<kind>.<decision>` ledger (closed 24-id set), the egress policy tier,
> allowlist-enforced redaction, computed evidence rows (3.1.3/3.4.2/3.14.6-7/AC-4/SI-4/CC6.x/Art.12/
> DORA — SC-7/3.13.x deliberately absent), and the Policy/Coverage UI. Rows below flip individually
> only as each capability is verified.
> Honest ceiling ships with each feature: before containment (B14), controls cover **governed
> lanes** (hook · gateway · broker); a raw-socket bypass is stated first, unprompted. Compliance
> claims stay stricter than marketing verbs: SC-7 / 3.13.6 appear in an export only after a Q-B
> assessor validation, even once the code enforces (doc 24 §3, §11.5).

| # | Feature | Phase | Status | Proof today → proof when it ships |
|---|---|---|---|---|
| B0′ | Self-verifying egress-receipt demo — one HTML file, embedded verifier, tamper-a-byte demo over `kriya.io.*` receipts | EG-1 | 🔨 next | spec `ideas/24 §4.4` → the artifact itself + a TS chain-check suite (trust-spine) |
| B1 | Egress allowlist / deny-by-default by destination host + kind | EG-2/3 | ✅ **shipped 2026-07-12** | `artifact:` runtime fixture `kriya-verify/fixtures/runtime-egress-ledger.jsonl` (verified by the kriya-verify suite) · `shot:policy-egress.png` (host tiers + deny-by-default posture round-tripping into the enforced YAML) |
| B2 | Per-destination byte budgets + rate limits (anti slow-drip) | EG-2 | 🔨 | → budget-tier tests over observed payload bytes (L2 honesty label) |
| B3 | **Fail-closed receipt-precondition — "no receipt, no egress"** ⭐ the kriya-native differentiator: the proof is the gate | EG-2 | 🔨 | → the flagship test: receipt write fails ⇒ egress denied; demo in EG-1 artifact |
| B4 | Ask / defer approvals on egress (park unlisted destinations for a human) | EG-2/3 | ✅ **shipped 2026-07-12** | `require-approval` tier per destination + `kriya.io.*.approve` ids in the closed set (`code:control_plane/redact.rs`) · `shot:policy-egress.png` (existing approval UX caveats carry over) |
| B5 | DNS-exfil + anomalous-destination + subdomain-entropy detection | EG-P | 🔨 | → detection suite, alert-or-deny per policy |
| B6 | SSRF / private-IP / cloud-metadata / DNS-rebinding blocking (resolve-then-pin) | EG-P | 🔨 | → adversarial network tests on governed lanes |
| B7 | Credential + secret + PII scanning & redaction on outbound bodies (hash + match-type stored, never the secret) | EG-P | 🔨 | → redaction suite + privacy-pack review (EG-3 pack) |
| B8 | Operation rails — allow/deny specific API operations (HTTP verb/path, GraphQL mutations); parse-fail ⇒ deny | EG-P | 🔨 | → rail tests incl. parse-failure fail-closed |
| B9 | Canary tokens — planted string ⇒ immediate deny + loud alert | EG-P | 🔨 | → canary trip test + signed alert receipt |
| B10 | Connector registry — new MCP server/tool **disabled-until-approved**; tool-description drift/poisoning scan | EG-P | 🔨 | → registry state tests + drift-scan fixtures |
| B11 | Per-connector / per-tool enable-disable + read-only rails | EG-P | 🔨 | → per-action tier tests (rides the existing policy engine) |
| B12 | MCP response enforcement — block-by-default responses + per-server trust classes | EG-P | 🔨 | → response-gate tests on governed MCP lanes |
| B13 | Credential brokering — agent holds a placeholder; real secret injected at egress (keychain/Secure-Enclave custody) | EG-B | 🔨 | threat-model section first → brokering tests; new trust posture documented in TRUST.md |
| B14 | OS containment — launch-under sandbox (Seatbelt/Landlock/nftables) forces agent traffic through the governed lane; turns observe into **enforce** for the governed subtree | EG-C | 🔨 (spike first) | → containment escape tests; enforcement verbs earned for the subtree only (§11.5) |
| B15 | Spend / budget caps | — | ✅ **shipped** | see A1.7 (surface in egress collateral via EG-AB) |
| B16 | Fleet egress — policy distribution + stale-policy kill-switch + fleet receipt report | EG-F | 🔨 | rides doc-22 P3 PolicyBundle (A5.5) → fleet egress tests |
| B17 | Broad agent coverage | — | ✅ **shipped** | see A1.10 — the native hook seam (agent *decisions*) no proxy has |
| B18 | A2A (agent-to-agent) governance | EG-F | 🔨 thin | → broker-extension tests when A2A traffic is real |
| B19 | Deeper host rungs — Linux eBPF/Tetragon host observation (EG-5) · macOS host-wide enforcement (EG-6, Apple ES entitlement) | EG-5/6 | 🔨 later | after EG-C proves the model; WATCHER-ROADMAP W3–W6 discipline |

**Egress compliance truth (fixed, not negotiable):** the governed-lane ledger honestly supports
AC + CM + SI *slices* (3.1.3 ◐, 3.4.2 scoped, 3.14.6/7 ◐, AC-4 ◐, SI-4 feeds-never-is, SOC 2
CC6.1/CC6.7/CC7.2 ◐, Art. 12 readiness, DORA 28–30). **Killed at that layer:** 3.13.1, 3.13.6,
SC-7, SC-8, CC6.6. Containment (B14) lets the *code* earn SC-7-monitor→control and 3.13.6 for the
contained subtree; the *export claim* still waits for assessor validation. Never claim "DLP" or
"firewall" unqualified. (Doc 24 §3, §11.5.)

---

## Maintenance rules

1. A row flips ✅ only with a real proof cell (test merged + artifact/screenshot where applicable).
2. New feature ⇒ new row **here first**, then FEATURES.md, then collateral (EG-AB order).
3. Screenshots regenerate via `npm run capture` / `npm run capture:fleet`; keep `shot:` paths live.
4. If TRUST.md and this file ever disagree, TRUST.md wins and this file has a bug.
