# Model works-agreement clause — agent egress governance (E1)

> For organizations in co-determination jurisdictions (Germany's `Betriebsvereinbarung`, Austria,
> Netherlands, France, and similar), deploying kriya's egress/ingress ledger to employee devices is
> very likely to trigger a **works council consultation and agreement requirement** — treat this as a
> **precondition to deployment**, not paperwork that follows it; unprepared, it can add 3–9 months to
> a rollout. This is a starting-point clause for that agreement, drafted to be adapted with your
> works council and legal counsel, not filed as-is.

## Clause: Governance and monitoring of AI-agent activity via kriya

### 1. Scope

This agreement governs the Employer's use of kriya to record and audit the activity of AI software
agents (e.g. Claude Code) operated by Employees on Employer-provided or Employer-managed devices,
specifically:

(a) which external network destinations a governed agent's tool calls reach ("egress"), and
optionally
(b) a cryptographic digest of content returned to the agent ("ingress" — see §4, separately gated).

### 2. Purpose limitation (binding)

Data collected under this agreement is used **exclusively** for:

- Compliance evidence toward named regulatory/contractual obligations: **[list your actual drivers,
  e.g. NIST 800-171 / CMMC, SOC 2, EU AI Act Art. 12, DORA]**.
- Security incident investigation where a specific, documented trigger exists (e.g. a suspected
  policy violation or security event).

Data collected under this agreement **may not** be used for:

- Individual performance evaluation or productivity measurement.
- General surveillance of an Employee's work activity beyond the scope in §1.
- Any purpose not listed above without a renegotiation of this agreement.

### 3. What is collected (technical description)

Per governed agent action that egresses: destination host, byte counts, a content hash (not
content), the policy decision, the acting Employee's identity, and a timestamp. See the companion
`employee-notice-template.md` for the Employee-facing plain-language version, and
`DPIA-egress-template.md` for the full data-protection assessment this clause is paired with.

### 4. Ingress content-digest recording (separately gated)

Recording a digest of *response* content returned to an agent is a **separate, opt-in** capability,
off by default even when egress logging is enabled. If the Employer wishes to enable it, that
requires a **specific amendment to this agreement** — it is not covered by the general egress
provisions above, because computing a content hash means processing (reading) the full response
content, a materially different processing activity from logging a destination.

### 5. Access and audit of access

Access to Employee-level (non-aggregated) records is restricted to **[named roles/individuals]**, for
the purposes in §2 only. Every instance of an administrator drilling into an individual device's raw
record is itself logged in a separate, tamper-evident trail, available to the works council on
request under the terms of **[your local works-council information-rights provision]**.

### 6. Data minimization commitments

- Aggregated/centralized reporting (where the Employer operates a fleet evidence server) contains
  only **counts against destination patterns the Employer itself authored** — never a raw,
  per-Employee destination list — unless a further, explicit amendment to this agreement authorizes
  raw-detail centralization for a stated, narrow purpose.
- Any centralized "unlisted destination" count is subject to a minimum-device threshold before it is
  shown, specifically to prevent a pattern from being narrow enough to single out one Employee.

### 7. Retention

Records are retained for **[N days/months]**, after which they are provably deleted (a signed
retention marker, not a silent purge — see `docs/TRUST.md`'s "Retention and the chain").

### 8. Review

This agreement is reviewed **[annually / on material feature change]**. The Employer commits to
notifying the works council before enabling any capability described in this pack (e.g. ingress
digest recording, §4) that is not already covered by an existing clause.

### 9. Signatures

| Party | Name | Date |
|---|---|---|
| Employer representative | | |
| Works council representative | | |

---
*Model clause provided by kriya as a drafting aid. It is not legal advice and does not by itself
satisfy any jurisdiction's co-determination requirement — negotiate and adapt it with your actual
works council and counsel.*
