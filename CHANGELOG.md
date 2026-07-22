# Changelog — kriya Console

All notable changes to the Console and the `kriyad` control plane. Dates are release dates of the
signed, notarized macOS DMG unless noted.

## v0.3.0 — 2026-07-22 — sessions, test-before-apply, more agents

- **Sessions — run correlation.** A new **Sessions** view reconstructs every governed run as a tree
  — *which session → which sub-agent → which action, in order* — from the signed receipts alone.
  Governed lanes now stamp an optional `kriya.corr` block into each receipt (`run_id`, and where the
  seam really exposes them, `parent_step_id` / `agent_id`); the bundled `kriya-hook` and
  `kriya-gateway` sidecars emit it, and the SDK middleware threads explicit nested-call lineage.
  Honest by construction: the tree is computed from **verified receipts only**, Claude Code's hook
  payload has no parent pointer so none is invented (sub-agents group by `agent_id`), and run ids
  live in receipt `params` — structurally unreachable by the fleet envelope minimizer, so they never
  leave the device. The compliance export gains a session-correlation appendix **only** when
  correlated receipts exist; a zero-correlation export is byte-identical to v0.2.6's.
- **Policy — "test before apply."** Replay a candidate policy over this device's own re-verified
  receipts and see which past actions would land on a different tier ("this edit would have changed
  N of last week's M actions") — in the Policy view and as the fleet pre-publish gate. Scope stated
  in the UI: the action-tier gate only; the simulation itself is a signed, chained
  `kriya.policy.sim.result` receipt.
- **Govern All: Cursor · Cline · GitHub Copilot · Gemini CLI.** One-click detection + routing of
  each client's stdio MCP servers through the governed gateway — idempotent, non-clobbering, fully
  reversible. Ceiling stated where it's shown: the MCP lane is governed; each agent's native
  built-in tools bypass MCP unless launched under containment; cloud-executed agents are out of
  scope.
- **In the open runtime** (same release train): `kriya-govern` (per-call govern + sign over stdio),
  SDK middleware for **LangGraph · OpenAI Agents SDK · CrewAI · Claude Agent SDK** (TypeScript +
  Python, no crypto in the wrappers), and **`kriya-ci`** — the governed CI lane (run an agent step
  in CI under a repo-committed policy; the build fails on a policy block and the signed receipts are
  the build artifact, re-verifiable offline).

## v0.2.6 — 2026-07-16

- **Audit log: date-range filter + sort by time.** The Audit log now has a From/To date filter
  (UTC, matching the "When" column) and a Newest/Oldest sort, defaulting to newest-first — so a
  receipt is findable by *when* it happened, not only by text/status/source.

## v0.2.5 — 2026-07-15

- **Stale-hook detection.** After an in-place upgrade, Claude Code can keep calling an *older*
  `kriya-hook` (a leftover `cargo install`, or a pre-`--policy` wiring) that predates egress
  capture — so WebSearch/WebFetch egress silently never records and the network-egress lane stays
  grey. The Coverage view now compares the wired hook against the binary this build ships and, when
  they differ, shows a warning with a one-click **Re-run Govern All** to re-point it. Previously the
  app treated any `kriya-hook` string as healthy.

## v0.2.4 — 2026-07-15 — the egress pack

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
- **Fleet destination visibility** — privacy-minimized pattern-echo of destinations in fleet
  envelopes (additive `io_destinations` field, sealed minimizer, per-bundle `io_verbosity`).

## v0.2.3 — 2026-07-10

The control-plane cockpit comes together — central governance, fleet drift, org-wide evidence.

- **Central policy authoring + signed downlink** — author once, sign with your org key, publish to
  your on-prem `kriyad`; each device pulls, re-verifies, and applies (anti-rollback included), and
  the applied policy becomes part of that device's own signed evidence trail.
- **Fleet drift & governance view** — per device: in-sync / behind / silent-behind, every verdict
  re-verified locally from the device's own signed envelopes, never the server's word.
- **Org-wide assessor-ready evidence export** — coverage-completeness + AU-family + CM controls
  across the fleet, computed from re-verified envelopes.
- **mTLS cert-role separation** — a device cert can't read the fleet; an operator cert can't post
  device evidence.
- `kriyad` ship skins: static binary, distroless image, systemd box install, cosign-signed
  air-gap bundle, release CI gated on the trust-spine tests.

## v0.2.2 / v0.2.1 — 2026-07-08

- **Hermes native-tool governance** via the new `kriya-hermes-hook` — terminal, file edits,
  computer-use, browser automation, plus every MCP server it's attached to; one-click install
  from Govern All. (v0.2.1 fixed Hermes detection: `mcp_servers` vs `mcpServers`.)

## v0.2.0 — 2026-07-08

- **Govern All** — one button detects every governable agent on the machine (Claude Code, Claude
  Desktop, Hermes, desktop apps) and wires each through its seam: preview, apply, revert. Idempotent.
- **Bundled `kriya-hook`** — the Console ships the Claude Code hooks adapter itself; no separate
  install to govern native tools.
- **Multi-agent Coverage Map** — lanes grouped per agent, with an honest "cloud, out of scope"
  line for surfaces that execute off-device.
- Compliance export names the distinct governed agents and cites the signed
  coverage-completeness chain (NIST 800-171 3.3.1 / 3.3.4).

## v0.1.2 — 2026-07-07

- **NIST SP 800-171 / CMMC L2 AU-family mapping** (3.3.1–3.3.9, with 800-53 crosswalk) in the
  evidence export — every status derived from re-verified receipts, never hard-coded.
- Notarized universal (Intel + Apple Silicon) DMG.

## v0.1.1 — 2026-07-03

- **The Coverage Map** — six lanes, three states, signed into its own hash chain so a stopped
  watcher is visible by absence, not a quiet nothing.
- `kriya-hook` shipped in the public runtime; the gateway's remote-MCP broker (hosted MCP servers
  over HTTP/SSE).

## v0.1.0 — 2026-07-01

- First public release: the live governance Monitor, offline receipt verification, Connections
  manager, guided first-run setup — signed with our Apple Developer ID and notarized by Apple.
- The free **`kriya-audit` CLI** published alongside — verify any signed receipt log offline,
  independent of the Console.
- The trust spine: byte-for-byte parity between the TypeScript verifier and the Rust signer,
  enforced by `npm test`.

Every tagged release (notarized DMG + SHA-256) lives on
[GitHub Releases](https://github.com/sandeepshekhar26/kriya-console/releases), tagged `vX.Y.Z`
(releases through v0.2.4 were published on the runtime repo, tagged `console-vX.Y.Z`).
