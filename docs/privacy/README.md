# Privacy artifact pack — E1 egress/ingress governance

Ships alongside the egress/ingress ledger (doc 24 EG-3) as a **customer-deployment precondition**,
not an afterthought: an identity-bound, timestamped record of agent activity is employee-behavioral
data the moment it exists, regardless of how carefully it's built. This pack gives a deploying
organization (and its DPO / works council) the artifacts to run that conversation honestly, before
enabling the ledger on employee devices.

| File | For | Maps to |
|---|---|---|
| [`DPIA-egress-template.md`](DPIA-egress-template.md) | The controller's data-protection impact assessment | GDPR Art. 35 |
| [`employee-notice-template.md`](employee-notice-template.md) | The Employee-facing plain-language notice | GDPR Arts. 13/14 |
| [`works-agreement-clause.md`](works-agreement-clause.md) | Co-determination jurisdictions (DE/AT/NL/FR…) | Works council / `Betriebsvereinbarung` |

## Retention defaults

The retention design (see "Retention and the chain" in [`../TRUST.md`](../TRUST.md)) is a policy
dial, not a hardcoded value — but the runtime's `retention:` policy section is deliberately shaped so
the **io-ledger class defaults to a shorter window than the policy/approval-receipt class**, because
per-destination egress/ingress metadata is the most granular, least evidence-durable data on the
trail:

| Receipt class | Suggested default | Why |
|---|---|---|
| `kriya.io.*` (egress/ingress ledger) | **30–90 days**, organization's choice | Highest granularity, lowest per-record evidentiary weight on its own — its value is in aggregate/pattern evidence, not any single record. Shorter retention reduces both re-identification surface and storage of stale, low-value detail. |
| Policy / approval receipts | **6–12 months**, or your compliance framework's stated minimum (e.g. NIST 800-171's implicit expectation, DORA's incident-timeline needs) | These are the higher-value evidentiary records an assessor is actually likely to ask for by name. |
| Retention is **unset by default** | — | Kriya does not impose a retention period; an operator who sets none gets indefinite retention (today's pre-EG-2 behavior, unchanged). Setting an explicit `retention:` policy is the deploying organization's decision, made with its DPO, not a kriya default. |

Retention is enforced via a signed **epoch-checkpoint** receipt (`kriya.retention.checkpoint`):
receipts older than the cutoff are pruned and the checkpoint attests *"receipts before T pruned per
policy P; prior chain head was H"* — every verifier (the TS verifier, `kriya-verify`, the offline
`kriya-audit` CLI) accepts this as a sealed, legitimate chain boundary, not a tamper signal. This is
what makes GDPR Art. 17 erasure and the tamper-evidence guarantee compatible instead of contradictory.

## Before you deploy

1. Run the DPIA (or confirm with your DPO that Art. 35's threshold isn't met and a lighter privacy
   review suffices).
2. Issue the employee notice.
3. In co-determination jurisdictions, negotiate the works-agreement clause **before** enabling the
   ledger — not after.
4. Set an explicit `retention:` policy matching your organization's actual retention decision, rather
   than relying on the indefinite-retention default.
