# Compliance evidence — Sample contractor — illustrative data

_Generated 2026-07-06T00:00:00.000Z by kriya Console. Evidence derived from cryptographically signed audit receipts, verified locally._

**Period:** 2026-06-17T12:40:00.000Z → 2026-06-17T13:46:48.000Z

## Audit integrity

- Receipts: **28**
- Verified: **27**
- Failed / tampered: **1**
- Distinct signer keys: **3**

## Attribution (who acted)

- Coverage: **100%** of verified receipts carry an actor
- Agents: claude-desktop, cursor
- Operators: fin-ops, platform-eng, sales-ops

## Human oversight & on-device posture

- Deny-by-default policy: **yes**
- Approval-gated actions observed: restart_service, scale_service, deploy
- Budget cap: 60/min
- On-device attestations: **0**

## Action inventory

| Action | Count | Policy tier | Destructive |
| --- | ---: | --- | --- |
| `categorize_transaction` | 6 | allow |  |
| `update_contact` | 3 | allow |  |
| `get_logs` | 3 | allow |  |
| `create_note` | 3 | allow |  |
| `list_transactions` | 2 | allow |  |
| `list_contacts` | 2 | allow |  |
| `list_services` | 2 | allow |  |
| `get_balance` | 2 | allow |  |
| `restart_service` | 1 | approval |  |
| `list_deals` | 1 | allow |  |
| `scale_service` | 1 | approval |  |
| `deploy` | 1 | approval |  |

## Control mapping

| Framework | Control | Status | Evidence |
| --- | --- | --- | --- |
| EU AI Act | Art. 12 — Record-keeping | ◐ partial | 27 signed receipt(s) verified, 1 failed/tampered; 3 signer key(s). |
| EU AI Act | Art. 14 — Human oversight | ✓ satisfied | 3 action(s) gated behind human approval: restart_service, scale_service, deploy. Deny-by-default: yes. |
| EU AI Act | Art. 12(2) — Traceability | ✓ satisfied | 100% of verified receipts attributed to an agent + operator (agents: claude-desktop, cursor). |
| EU AI Act | Art. 26(6) — Deployer log retention | ◐ partial | 28 receipt(s) retained locally as JSONL under the deployer's own control; kriya does not enforce or verify a specific retention schedule (e.g. the six-month minimum) — that is the deployer's responsibility. |
| SOC 2 | CC7.2 — Monitoring | ◐ partial | 1 receipt(s) failed verification — tampering or corruption detected. |
| SOC 2 | CC7.3 — Security event evaluation | ◐ partial | Per-receipt verification failures and hash-chain-break flags surface the security-event signal; the evaluation and response process itself is organizational, outside kriya. |
| SOC 2 | CC8.1 — Change management | ✓ satisfied | 3 agent-driven change action(s) require human approval before execution: restart_service, scale_service, deploy. Deny-by-default: yes. |
| ISO 42001 | A.9 — Operation controls | ✓ satisfied | Deny-by-default policy with 12 action(s) observed; budget cap 60/min. |
| ISO 42001 | A.6.2.6 — Operation and monitoring | ◐ partial | The signed receipt stream is the operation/monitoring log (27 verified of 28), surfaced live in the Console Monitor. |
| Data residency | On-device processing | ✗ gap | No on-device attestations in this trail. |
| NIST 800-171 | 3.3.1 (AU.L2-3.3.1 · AU-2/3/12) — Audit record creation & retention | ◐ partial | 28 signed receipt(s) retained across 1 app(s) and 2 governed agent(s) as a hash-chained local JSONL log; 1 failed verification; each record carries action id, parameters, timestamp, outcome, and signer. Completeness is itself attested: 14 signed coverage snapshot(s) (chain intact) record which lanes were governed over the window — what was and wasn't logged is provable, not asserted. |
| NIST 800-171 | 3.3.2 (AU.L2-3.3.2 · AU-3) — Individual accountability | ✓ satisfied | 100% of verified receipts carry a signed agent + individual-operator identity (operators: fin-ops, platform-eng, sales-ops). |
| NIST 800-171 | 3.3.3 (AU.L2-3.3.3 · AU-2) — Review & update logged events | ◐ partial | 12 distinct action type(s) captured across policy tiers (allow/approval/deny); the periodic review and update of which events to log is an organizational process outside kriya. |
| NIST 800-171 | 3.3.4 (AU.L2-3.3.4 · AU-5) — Audit logging process failure alerting | ◐ partial | Per-receipt verification failures and hash-chain breaks surface live in the Console, and the Coverage Map flags silent lanes; no external paging/alerting integration exists. The signed coverage chain makes a stopped or silenced logging process visible by absence — a gap in the heartbeat chain, not a quiet nothing. |
| NIST 800-171 | 3.3.5 (AU.L2-3.3.5 · AU-6(3)) — Correlate audit review & analysis | ◐ partial | Cross-app correlation on this machine (Audit view filtering across 1 app(s)) plus tamper flags support investigation; this is single-machine correlation, not cross-machine SIEM aggregation. |
| NIST 800-171 | 3.3.6 (AU.L2-3.3.6 · AU-7) — Audit record reduction & report generation | ✓ satisfied | This Markdown + JSON evidence bundle is itself the reduction/report artifact, generated on-demand from the signed trail and independently re-verifiable offline via kriya-audit. |
| NIST 800-171 | 3.3.7 (AU.L2-3.3.7 · AU-8) — Clock synchronization for time stamps | ◐ partial | Every receipt carries a host timestamp (ts_ms); clock synchronization against an authoritative source is OS-provided (NTP), outside kriya's control — this control is capped at partial regardless of trail size. |
| NIST 800-171 | 3.3.8 (AU.L2-3.3.8 · AU-9) — Protect audit information & tools | ◐ partial | 1 receipt(s) failed verification — tampering detected; the detection control is functioning as intended, investigate the flagged record(s). |
| NIST 800-171 | 3.3.9 (AU.L2-3.3.9 · AU-9(4)) — Limit audit-logging management to privileged users | ✗ gap | kriya's audit tooling runs under the operator's own OS account, and in-app roles are self-asserted (see docs/TRUST.md) — kriya enforces no privileged-user restriction on who can manage audit logging; this must be enforced by an OS-level or organizational access control. |

_Status: ✓ satisfied · ◐ partial · ✗ gap. This report is evidence, not a certification._
