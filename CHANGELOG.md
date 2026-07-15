# Changelog — kriya Console

All notable changes to the Console and the `kriyad` control plane. Dates are release dates of the
signed, notarized macOS DMG unless noted.

## Unreleased (v0.2.4) — the egress pack

Everything below is merged on `main` and ships in the next DMG.

- **Egress governance core** — per-destination allowlists (deny-by-default), byte budgets,
  fail-closed *"no receipt, no egress"* (the signed receipt is a precondition of the network call),
  and ask-before-send approvals for unknown destinations.
- **Detection pack** — secret & PII scanning on outbound bodies (redact/deny; only hashes stored),
  DNS-exfiltration and subdomain-entropy detection, SSRF / private-IP / cloud-metadata /
  DNS-rebinding guard, canary tokens, operation rails (verb / path / GraphQL mutation),
  connector registry (new MCP servers disabled until approved) with tool-description drift
  scanning, per-connector read-only presets, MCP-response trust classes.
- **Credential brokering** — agents hold placeholders; real secrets live in the OS keychain and
  are injected only at egress. New public threat model: `docs/THREAT-MODEL-brokering.md`.
- **OS containment (macOS)** — `kriya-gateway run -- <agent>` launches an agent inside a generated
  Seatbelt profile with a recording CONNECT proxy, forcing traffic through the governed lane;
  contained sessions light up the raw-egress Coverage lane.
- **Fleet egress** — egress policy, budgets, and a kill switch distributed in the org-signed
  PolicyBundle; fleet egress-receipt report; agent-to-agent lane governance.
- **Evidence & privacy** — egress control rows in the compliance export (scoped honestly to
  governed lanes), redaction manifest for egress receipts, and a customer privacy pack
  (`docs/privacy/`): DPIA template, employee notice, works-agreement clause.
- In review: fleet destination visibility (pattern-echo, privacy-minimized).

## v0.2.3 — 2026-07-10

- **The fleet control plane** (paid): mTLS device uplink with signed DeviceInfo beacons, the fleet
  cockpit view, org-key-signed policy distribution with anti-rollback (author → sign → publish →
  device pull/verify/apply → signed "applied" receipt), the drift & governance view, org-wide
  evidence export, and cert-role separation (a device credential cannot read the fleet; an
  operator credential cannot post evidence).
- **One-click Hermes governance** via the new `kriya-hermes-hook`.
- **Govern All hardening** — every install path now wires policy plus a real approval default.
- Refreshed in-app onboarding and marketing stills.

## v0.1.2 — 2026-07-06

- **Coverage Map** — the six-lane honest view of what is and isn't recorded, with signed
  coverage-change receipts and TS↔Rust parity fixtures.
- **CMMC / NIST 800-171 AU-family mapping** in the evidence export.
- **Free auditor CLI published** — `kriya-audit` as a signed public download.
- **kriyad release CI** — one tag builds every deployment skin (systemd box, container, air-gap
  bundle), gated on the trust-spine tests, with a real-systemd verification job.

## v0.1.0 — 2026-07-01

- First **signed + notarized universal macOS DMG** (Apple Silicon + Intel).
- The Console core: Monitor, Audit, Policy, Approvals, Budgets, Identity, Reports — every view
  computed from Ed25519-signed, hash-chained receipts re-verified on device.
- The trust spine: byte-for-byte parity between the TypeScript verifier and the Rust signer,
  enforced by `npm test`.
- `kriyad` aggregator ship skins: static-musl binary, distroless image, systemd box install,
  cosign-signed air-gap bundle; end-to-end pilot demo (air-gap ingest → mTLS serve → offline
  auditor re-verification).
- First-run setup wizard, clean shippable build, app icon, screenshot pipeline.
