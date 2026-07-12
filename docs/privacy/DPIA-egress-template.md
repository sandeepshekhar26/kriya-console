# Data Protection Impact Assessment (DPIA) — kriya egress/ingress governance (E1)

> **What this is.** A vendor-prefilled starting point for the DPIA a controller (the customer
> deploying kriya) may be required to run under **GDPR Art. 35** before enabling the E1 egress/
> ingress ledger on an enrolled fleet — or as good practice even where Art. 35's strict trigger
> (high-risk processing) isn't met. kriya is the **processor** here; the customer organization is
> the **controller** and is responsible for completing, reviewing, and — where Art. 35 applies —
> filing this assessment. Nothing in this document is legal advice; have your own counsel or DPO
> review it before relying on it.
>
> **Why this exists as a precondition, not an afterthought.** An egress/ingress ledger bound to
> `actor.user` is employee-behavioral data the moment it's identity-stamped and timestamped — this
> is true structurally, regardless of how thoughtfully it's built (see [`docs/TRUST.md`](../TRUST.md)
> and doc 24 §6-P1 in the engineering record). Shipping the DPIA template alongside the feature,
> not after a customer asks, is the honesty discipline this project holds itself to.

## 1. Processing description

| Field | Answer (vendor-prefilled — verify against your actual deployment) |
|---|---|
| **What is processed** | Per-action metadata for agent tool calls that egress (leave the device via a governed MCP connector or WebFetch/WebSearch call) or, if separately enabled, ingress (content returned to the agent). Fields: destination host, byte counts, a content hash, an allow/deny/approve decision, the acting agent identity, and the operator (`actor.user`) on whose behalf the agent ran. **Never** the request/response content itself — see §3. |
| **Who is processed** | Employees / contractors operating kriya-governed agents (Claude Code, or any MCP client routed through the kriya gateway/broker). This is the data subject population. |
| **Purpose** | Compliance and security evidence: proving which governed destinations an agent reached, under what policy decision, for audit/assessment purposes (NIST 800-171, SOC 2, EU AI Act record-keeping). **Never** employee performance evaluation, productivity scoring, or monitoring of an individual's general computer use — this is a purpose-limitation commitment, not an incidental effect, and it should be stated in the same words in your organization's internal notice (see the companion `employee-notice-template.md`). |
| **Legal basis (EU deployments)** | Typically **legitimate interest** (Art. 6(1)(f)) for security/compliance monitoring, balanced against employee privacy — a legitimate-interest assessment (LIA) is a normal companion to this DPIA. Some jurisdictions/sectors may require **consent** or rely on a **legal obligation** (Art. 6(1)(c)) where a compliance framework mandates the logging. Confirm with counsel; kriya does not select a legal basis for you. |
| **Retention** | Configurable per `retention.io_days` in the runtime policy (default: unset = indefinite until the operator sets one — see "Retention and the chain" in `docs/TRUST.md`). The io-ledger class is designed to carry a **shorter** default than the policy/approval receipt class, reflecting that it is the most granular, least evidence-durable data on the trail. |
| **Where it lives** | On-device only, in `~/.kriya/audit/*.jsonl`, unless the device is enrolled in a customer-run `kriyad` fleet server (see the three-tier data-boundary promise in `docs/TRUST.md`) — in which case only **counts**, never raw per-employee destination data, reach that server by default. Raw receipts never reach any kriya-operated infrastructure, at any tier. |
| **Who can read it** | Whoever has filesystem access to the device (device-local) or console/drill-down access to the enrolled fleet's `kriyad` (operator-scoped). Operator drill-down into a specific device's raw trail is itself a receipted, auditable action (`kriya.console.drilldown`) — "the surveillance is itself audited." |

## 2. Necessity and proportionality

- **Is the processing necessary for the stated purpose?** Governed-lane egress/ingress metadata is the mechanism by which kriya delivers its core, previously-agreed product function (signed, offline-verifiable audit evidence for agent activity) — the assessment should confirm this is proportionate to *your* actual compliance driver (a named framework/control), not adopted as a generic "more logging is better" default.
- **Is there a less invasive alternative?** Yes, and it's a real dial, not a rhetorical one: the egress *tier itself* (allow/approval/deny by destination) can be enabled with the `kriya.io.*` receipt content minimized further, and **ingress digest recording is OFF by default** even when egress logging is on (its own policy switch — see doc 24 §6-P3 in the engineering record). Ingress hashing means reading every response byte, which is its own processing activity distinct from egress logging; enable it only if your compliance driver actually requires proof of what came back, not just what went out.
- **Data minimization built into the architecture, not bolted on:** the redaction minimizer that governs what ever leaves a device (`kriya-verify::redact::minimize_window`) reads **only** `action_id` and `success` from any receipt — full-fidelity `params` (destination host, byte counts, content hash) are **structurally unreachable** by that code path, at any verbosity dial. This is a build-time, testable guarantee (`redaction_manifest.rs`), not a policy promise.

## 3. What is *not* collected, ever

- Request or response **content** — only a hash + byte count. The hash on the ingress side is **keyed** (HMAC under a device-local salt), specifically so that a receipt holder without the salt cannot reverse-engineer "did this agent read `salary.xlsx`" from a guessable filename or content pattern.
- Anything beyond the destination **host** — no URL path, query string, or request body is recorded.
- Centrally, at any enrolled-fleet tier: the raw destination host itself. Only aggregate counts against operator-authored policy patterns ever leave a device (the "pattern-echo" design, gated behind this DPIA existing).

## 4. Risks to data subjects and mitigations

| Risk | Mitigation |
|---|---|
| An identity-bound activity log could be misused for performance surveillance rather than its stated compliance/security purpose. | Purpose limitation stated in-product and in this template; a `PolicyBundle` purpose-statement field is echoed in every fleet export; the employee notice template names the actual purpose. This is a policy and process control your organization must actually operationalize — kriya provides the mechanism, not the enforcement of your internal use policy. |
| Centralizing per-device destination data (even patterns) creates a re-identification risk if patterns are narrow enough to single out one person. | The pattern-echo fleet view (when built) applies a k-threshold — a pattern matched by fewer than N devices is flagged, not silently shown, and daily time-bucketing reduces per-action timing precision. |
| An operator with device or `kriyad` access could read another employee's raw trail without oversight. | Operator drill-down into device-level detail is itself a signed, chained receipt (`kriya.console.drilldown`), auditable the same way agent activity is. |
| Deletion requests (Art. 17) collide with the tamper-evident chain design (deleting a receipt normally looks like tampering). | The retention design uses a signed **epoch-checkpoint** receipt: receipts before a cutoff are pruned and the checkpoint attests "receipts before T pruned per policy P; prior chain head was H" — verifiers accept this as a sealed boundary, not a break. See "Retention and the chain" in `docs/TRUST.md`. |

## 5. Consultation

- [ ] Data Protection Officer (DPO) reviewed — **mandatory** for deployments processing DORA-regulated financial-entity data or where Art. 35(3) applies.
- [ ] Works council / employee representative body consulted where required (DE/AT/NL/FR and similar co-determination jurisdictions — see the model works-agreement clause in this pack). Treat this as a **precondition** to deployment in those jurisdictions, not paperwork that follows it.
- [ ] Legal/compliance sign-off on the stated legal basis (§1).

## 6. Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| Controller DPO | | | |
| Deploying team lead | | | |
| Works council (if applicable) | | | |

---
*This template is provided by kriya as a starting point. It does not constitute legal advice and
does not itself satisfy your Art. 35 obligation — completing, verifying, and (where required) filing
it is the controller's responsibility.*
