# Feature proof ledger — every claim, its category, its proof

> **The single canonical claim → proof table.** Every feature kriya presents anywhere (README,
> website, docs) appears here **once**, categorized **SEE / CONTROL / PROVE** (the on-device
> control-and-proof product) or **EGRESS** (the outbound-governance set), with the concrete
> artifact that proves it: a test suite, a code path, a signed sample, a screenshot, or a public
> release. **Rule: a feature may be claimed only as far as its proof cell is real.** If a claim
> and this ledger disagree, the ledger wins; if this ledger and [`TRUST.md`](TRUST.md) disagree,
> TRUST.md wins.
>
> Companion: [`FEATURES.md`](FEATURES.md) — the same features in plain words.
> Current release: **Console v0.2.4**
> ([public DMG](https://github.com/sandeepshekhar26/kriya/releases/tag/console-v0.2.4)) ·
> auditor CLI **audit-v0.1.0**.

**Status legend:** ✅ shipped (in the current DMG) · 🧭 roadmap (designed, not built) ·
🕓 demand-gated (built when a design partner needs it).
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
| A1.3 | Govern Hermes — gateway (zero-change) + native-tool hook since v0.2.2 | ✅ | `open:` kriya repo `kriya-hermes-hook` |
| A1.4 | Govern desktop / no-API apps (computer-use, accessibility tree) | ✅ | `open:` kriya runtime reach-in drivers; demo `demo/kriya-gui-demo.mp4` |
| A1.5 | Policy engine — ordered allow / require-approval / deny, deny-by-default, **fail-closed on kriya's own errors** (B0 fixed + regression-tested) | ✅ | `test:policy.test.ts` · `code:src/lib/policy.ts` · B0 regression matrix · `shot:docs/screenshots/policy.png` |
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
| A4.3 | Assessor sample pack — 28 receipts, 1 deliberately tampered, test-guarded, never in the build | ✅ | `artifact:docs/samples/au-family-sample` · `test:au-family-sample.test.ts`, `no-sample-in-build.test.ts` |
| A4.4 | Cross-app fleet correlation (this machine) — verified/failed, signers, policy coverage | ✅ | `code:src/views/Fleet` · `test:` rollups in `compliance.test.ts` |
| A4.5 | Offline license — Ed25519-signed token, no phone-home, no accounts | ✅ | `code:src-tauri/license.rs` (self-serve checkout 🕓 — R0) |

### A5. Fleet control plane (paid `fleet-console`; P0–P6 shipped)

| # | Feature | Status | Proof |
|---|---|---|---|
| A5.1 | `kriyad` aggregator — customer-run static binary (BOX/K8S/air-gap), mTLS everywhere, verifies all ingest, append-only, **authors nothing** (holds no keys) | ✅ | `code:src-tauri/crates/kriya-aggregator` · `cargo test --features control-plane` |
| A5.2 | Evidence Compiler + enforced redaction — allowlist drop-by-default minimized `AttestationEnvelope`s; params/operator names structurally cannot leave; hash-chained outbox | ✅ | `test:envelope.test.ts` · `code:control_plane/{compiler,envelope,redact,outbox}.rs` |
| A5.3 | Device inventory beacon — signed `DeviceInfo`, GDPR-allowlisted schema with **no field** for usernames/hostnames/IPs/serials | ✅ | `test:device-info-fixture.test.ts` · `code:control_plane/device_info.rs` (adversarially tested) |
| A5.4 | Fleet table cockpit — liveness, versions + update badges, agent chips, drill-in to signed chains | ✅ | `code:src/views/ControlPlane*` · `shot:docs/screenshots/fleet-*.png` (`npm run capture:fleet`) |
| A5.5 | Central policy authoring + org-key-signed downlink — pull on heartbeat, verify against a **pinned** org key, anti-rollback, signed `policy.applied` receipt; air-gap = signed file | ✅ | `test:policy-bundle.test.ts` · `code:control_plane/{org_key,policy}.rs` · `shot:fleet-policy-author.png` |
| A5.6 | Policy-drift view — verdict from each device's own re-verified envelopes; kriyad's row only a hint; mismatch badge on disagreement | ✅ | `test:policyDrift.test.ts` · `shot:fleet-drift.png` |
| A5.7 | Org-wide evidence export — AU fleet-wide + CM 3.4.1/3.4.2 from the signed policy chain; silent devices named as red cells | ✅ | `test:orgEvidence.test.ts` · `code:control_plane/fleet_evidence.rs` · `shot:fleet-org-evidence.png` |
| A5.8 | mTLS cert-role separation — device certs can't read the fleet; operator certs can't post evidence; fail-closed per route | ✅ | `cargo test` (aggregator route guards, P6) |
| A5.9 | Zero-egress attestation (air-gap posture only) — signed proof nothing left; free tier opens **no socket at all** | ✅ | dormancy guard (`code:src-tauri/control_plane.rs`; free build links no fleet networking — [`TRUST.md`](TRUST.md)) |
| A5.10 | Remote approvals (P7) — operator-signed verdict unblocks a paused device action | 🕓 | design partner gate |
| A5.11 | Enrollment CA/CRL · HSM issuer · MDM zero-touch · SSO/OIDC (phases 3–5) | 🕓 | demand-pulled |

### A6. The trust spine (cross-cutting, free — what makes every row above checkable)

| # | Feature | Status | Proof |
|---|---|---|---|
| A6.1 | TS ↔ Rust canonical byte parity on every signed artifact type (receipts, envelopes, device-info, policy bundles) | ✅ | `npm test` — fails on one byte of drift; cross-version fixtures in `test/fixtures` |
| A6.2 | Three independent verifications for evidence (device → kriyad ingest → cockpit/auditor); two for policy (ingest → device apply) | ✅ | union: `verify`, `envelope`, `policy-bundle` suites + aggregator `cargo test` |
| A6.3 | Published honest limits — tamper-**evidence** not proofing; pin your signer; seams fail-open on their owners' side; disclosed shipped bugs (B0) | ✅ | [`TRUST.md`](TRUST.md) (canonical) |

---

## PART B — EGRESS (outbound governance — shipped in v0.2.4)

> The egress set was built to full competitive parity **before** being sold — no row was claimed
> until its proof cell was real. As of **Console v0.2.4** the whole set below ships in the notarized
> DMG, in the free tier. B19 (deeper host rungs) is the one genuinely-later row and is marked so.
>
> Every capability is built on the signed `kriya.io.<direction>.<kind>.<decision>` ledger (a closed
> id set), the egress policy tier, allowlist-enforced redaction, and the Policy/Coverage UI.
> **The honest ceiling ships with the features:** the controls cover **governed lanes** (hook ·
> gateway · broker) plus anything launched under **containment** (B14) — a raw-socket bypass
> outside a contained session is stated first, unprompted, and the Coverage Map shows it. Compliance
> claims stay stricter than the marketing verbs: SC-7 / 3.13.6 appear in an export only after a
> per-assessor validation, even though the contained code enforces.

| # | Feature | Status | Proof |
|---|---|---|---|
| B0′ | Self-verifying egress-receipt demo — one HTML file, embedded verifier, tamper-a-byte over `kriya.io.*` receipts | ✅ **v0.2.4** | `artifact:docs/samples/egress-receipt-demo/` (self-verifying HTML + `receipts.jsonl`) · `test:selfverify.test.ts` (chain-check, trust-spine) |
| B1 | Egress allowlist / deny-by-default by destination host + kind | ✅ **v0.2.4** | runtime fixture `kriya-verify/fixtures/runtime-egress-ledger.jsonl` (verified by the kriya-verify suite) · `shot:docs/screenshots/policy-egress.png` (host tiers + deny-by-default round-tripping into enforced YAML) |
| B2 | Per-destination byte budgets + rate limits (anti slow-drip) | ✅ **v0.2.4** | budget-tier enforcement over observed payload bytes (runtime egress tests; L2 honesty label on observed-bytes) |
| B3 | **Fail-closed receipt-precondition — "no receipt, no egress"** ⭐ the kriya-native differentiator: the proof is the gate | ✅ **v0.2.4** | receipt write fails ⇒ egress denied (runtime governor tests) · demonstrated in the B0′ self-verifying artifact |
| B4 | Ask / defer approvals on egress (park unlisted destinations for a human) | ✅ **v0.2.4** | `require-approval` tier per destination + `kriya.io.*.approve` ids in the closed set (`code:src-tauri/src/control_plane/redact.rs`) · `shot:docs/screenshots/policy-egress.png` |
| B5 | DNS-exfil + anomalous-destination + subdomain-entropy detection | ✅ **v0.2.4** | detection pack in the runtime governor (alert-or-deny per policy); Policy UI rows |
| B6 | SSRF / private-IP / cloud-metadata / DNS-rebinding blocking (resolve-then-pin) | ✅ **v0.2.4** | guard on governed lanes (`code:permissions.rs`/`governor.rs`); adversarial network tests |
| B7 | Credential + secret + PII scanning & redaction on outbound bodies (hash + match-type stored, never the secret) | ✅ **v0.2.4** | redaction manifest (`test:redaction_manifest.rs`) + the customer privacy pack ([`privacy/`](privacy/)) |
| B8 | Operation rails — allow/deny specific API operations (HTTP verb/path, GraphQL mutations); parse-fail ⇒ deny | ✅ **v0.2.4** | rail enforcement incl. parse-failure fail-closed (runtime egress tests); Policy UI rows |
| B9 | Canary tokens — planted string ⇒ immediate deny + loud alert | ✅ **v0.2.4** | canary trip → signed alert receipt (runtime governor) |
| B10 | Connector registry — new MCP server/tool **disabled-until-approved**; tool-description drift/poisoning scan | ✅ **v0.2.4** | registry state + drift-scan (broker + Policy UI) |
| B11 | Per-connector / per-tool enable-disable + read-only rails | ✅ **v0.2.4** | per-action tier on the existing policy engine; Policy UI read-only presets |
| B12 | MCP response enforcement — block-by-default responses + per-server trust classes | ✅ **v0.2.4** | response-gate on governed MCP lanes; trust-class rows |
| B13 | Credential brokering — agent holds a placeholder; real secret injected at egress (keychain / Secure-Enclave custody) | ✅ **v0.2.4** | [`THREAT-MODEL-brokering.md`](THREAT-MODEL-brokering.md) (its own trust posture) + brokering path in the gateway |
| B14 | OS containment (macOS) — launch-under Seatbelt sandbox + recording CONNECT proxy forces agent traffic through the governed lane; turns *observe* into **enforce** for the governed subtree | ✅ **v0.2.4** | `kriya-gateway run -- <agent>`; contained sessions light the raw-egress Coverage lane; enforcement verbs earned for the subtree only |
| B15 | Spend / budget caps | ✅ shipped | see A1.7 |
| B16 | Fleet egress — policy distribution + stale-policy kill-switch + fleet receipt report | ✅ **v0.2.4** | egress policy/budgets/kill-switch in the signed PolicyBundle (rides A5.5); fleet egress-receipt report |
| B17 | Broad agent coverage | ✅ shipped | see A1.10 — the native hook seam (agent *decisions*) no proxy has |
| B18 | A2A (agent-to-agent) governance | ✅ **v0.2.4** (thin) | broker A2A-lane seam + PolicyBundle convergence proof |
| B19 | Deeper host rungs — Linux eBPF/Tetragon host observation · macOS host-wide enforcement (Apple ES entitlement) | 🧭 roadmap | after containment proves the model; not built, not claimed |

**Egress compliance truth (fixed, not negotiable):** the governed-lane ledger honestly supports
AC + CM + SI *slices* (3.1.3 ◐, 3.4.2 scoped, 3.14.6/7 ◐, AC-4 ◐, SI-4 feeds-never-is, SOC 2
CC6.1/CC6.7/CC7.2 ◐, Art. 12 readiness, DORA 28–30). **Not claimed at that layer:** 3.13.1, 3.13.6,
SC-7, SC-8, CC6.6. Containment (B14) lets the *code* earn SC-7-monitor→control and 3.13.6 for the
contained subtree; the *export claim* still waits for assessor validation. Never claim "DLP" or
"firewall" unqualified.

---

## Maintenance rules

1. A row flips ✅ only with a real proof cell (test merged + artifact/screenshot where applicable).
2. New feature ⇒ new row **here first**, then FEATURES.md, then the rest of the collateral.
3. Screenshots regenerate via `npm run capture` / `npm run capture:fleet`; keep `shot:` paths live.
4. If TRUST.md and this file ever disagree, TRUST.md wins and this file has a bug.
