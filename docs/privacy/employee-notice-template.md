# Employee / operator notice — agent egress governance (E1)

> **What this is.** A model notice under **GDPR Arts. 13/14** (information to be provided where
> personal data is collected) for employees or contractors whose AI-agent activity is governed and
> recorded by kriya. Adapt the bracketed fields to your organization; this is a starting point, not
> legal advice — have counsel or your DPO review before issuing it. Pair this with the model
> works-agreement clause in this pack where a works council applies.

---

## Notice: what kriya records about your AI agent's activity

**[Organization name]** uses kriya to govern and record what AI coding/office agents (e.g. Claude
Code) do on your work device, including — where enabled — a record of the external destinations
those agents' governed tool calls reach.

### What is recorded

When an AI agent you operate makes a governed call to an external service (an MCP connector, a web
fetch), kriya may record:

- The **destination** it reached (e.g. `api.example.com`) and the kind of connection.
- **Byte counts** of what was sent and received (not the content itself).
- A **cryptographic hash** of the request/response content — this proves later that content wasn't
  tampered with, but by itself does not reveal the content, and (for responses, if enabled) is
  computed with a device-local secret key so it cannot be reverse-engineered from a guessable value.
- The **decision** kriya's policy made (allowed, denied, or held for approval) and, for an approval,
  who approved it.
- **Your identity** as the operator on whose behalf the agent acted, and the agent's own identity.
- The **time** of the action.

### What is NOT recorded

- The actual content of what the agent sent or received.
- Your general web browsing, personal device use, or anything outside a kriya-governed agent's
  actions.
- Anything from a spawned subprocess the agent's own code starts outside kriya's oversight — see the
  honest coverage limits in `docs/TRUST.md`; kriya is explicit about what it cannot see, and does not
  claim total visibility.

### Why this is recorded

**Purpose:** compliance and security evidence — proving to auditors, assessors, and regulators which
governed destinations agents reached and under what policy. **This is never used for individual
performance evaluation, productivity scoring, or general monitoring of your work.** If your
organization uses this data for a purpose beyond what's stated here, that is a deviation from
kriya's intended use and should be raised with your DPO or works council.

### Where it goes

By default, this record stays on your own device. If your organization has enrolled devices in a
company-run evidence server (**their own infrastructure — never kriya's**), only **aggregate counts**
against policy patterns your organization already authored travel there — never your raw destination
list. See the "three-tier data-boundary promise" in `docs/TRUST.md` for the precise, per-tier claim.

### Who can see it

- You, on your own device, at any time.
- An administrator with access to your device or the company's evidence server, for the stated
  compliance/security purpose. Any such access to your individual device-level record is itself
  logged in a separate, auditable trail — the same tamper-evident mechanism that protects your
  record protects the record of who looked at it.

### Retention

**[State your organization's retention period here — e.g. "N days," matching the `retention.io_days`
value set in your kriya policy]**. After that period, records are pruned; the deletion is itself
provable (a signed "this was pruned under this retention policy" marker), not silent.

### Your rights

Under GDPR (or your local equivalent), you may have the right to access, correct, or request erasure
of your personal data, and to object to processing based on legitimate interest. Contact
**[DPO / privacy contact]** to exercise these rights.

---
*Model notice provided by kriya. Your organization is the controller and is responsible for
completing, issuing, and where required, translating this notice, and for satisfying any works
council / co-determination consultation obligation before deployment.*
