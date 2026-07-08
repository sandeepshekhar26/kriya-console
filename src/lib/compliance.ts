// Compliance-evidence export (R7) — turn a verified signed-audit trail into the artifacts an
// auditor asks for: an integrity attestation, an attribution + oversight summary, and a mapping
// of the evidence to named controls (NIST 800-171 rev 2 / CMMC L2 AU family, SOC 2, ISO 42001, EU
// AI Act). The near-dated hook is CMMC Phase 2 (Nov 10, 2026), when DoD solicitations begin
// requiring a CMMC L2 assessment; the EU AI Act's Annex III high-risk obligations (incl. Art. 12
// logging, Art. 14 oversight) are deferred to Dec 2, 2027 pending the Digital Omnibus's final
// adoption — later than this file's earlier "enforcement opens in 2026" framing assumed. "Show me
// your agent's audit trail" is exactly what a kriya deployment already has — signed.
//
// Pure + framework-free; renders to JSON (machine) and Markdown (human). The view is a shell.

import { decide, type Policy, type Tier } from "./policy.ts";
import type { AuditRow } from "./types";

/** Reserved action id for the R13 on-device attestation receipt. */
export const ATTESTATION_ON_DEVICE = "kriya.attestation.on_device";

const DESTRUCTIVE = ["delete", "remove", "destroy", "drop", "purge", "wipe"];
const isDestructive = (a: string) => DESTRUCTIVE.some((k) => a.toLowerCase().includes(k));

export type ControlStatus = "satisfied" | "partial" | "gap";

export interface EvidenceControl {
  framework: string;
  control: string;
  requirement: string;
  evidence: string;
  status: ControlStatus;
}

export interface ActionInventoryItem {
  action: string;
  count: number;
  tier: Tier;
  destructive: boolean;
}

/** A summary of the signed coverage-completeness chain (`coverage.jsonl`), cited as AU-2/AU-12
 *  completeness evidence for NIST 3.3.1 / 3.3.4 (GA-3). Optional — evidence is unchanged when absent. */
export interface CoverageEvidence {
  /** Number of signed `kriya.coverage.snapshot` receipts in the chain. */
  snapshots: number;
  /** Whether that chain verifies end-to-end (hash-chain continuity + signatures). */
  chainOk: boolean;
}

export interface EvidenceBundle {
  generatedAt: string;
  organization: string;
  period: { from: string | null; to: string | null };
  integrity: { totalReceipts: number; verified: number; failed: number; distinctSigners: number };
  attribution: { attributed: number; coveragePct: number; agents: string[]; users: string[] };
  onDevice: { attestations: number; sealedBackends: string[]; components: string[] };
  humanOversight: {
    approvalGatedActions: string[];
    denyByDefault: boolean;
    budgetCapPerMinute: number | null;
  };
  actionInventory: ActionInventoryItem[];
  controls: EvidenceControl[];
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** Build the evidence bundle from verified audit rows + the governing policy. */
export function buildEvidence(
  rows: AuditRow[],
  policy: Policy,
  opts: { generatedAt: number; organization?: string; coverage?: CoverageEvidence },
): EvidenceBundle {
  const withReceipt = rows.filter((r) => r.receipt);
  const verified = withReceipt.filter((r) => r.outcome.ok);
  const failed = rows.length - verified.length;

  const times = withReceipt.map((r) => r.receipt!.ts_ms).filter((n) => Number.isFinite(n));
  const signers = new Set(verified.map((r) => r.receipt!.public_key));

  // Attribution (R8) — only verified receipts count as evidence; a failed row proves nothing.
  const attributed = verified.filter((r) => r.receipt!.actor).length;
  const agents = new Set<string>();
  const users = new Set<string>();
  for (const r of verified) {
    if (r.receipt!.actor) {
      agents.add(r.receipt!.actor.agent);
      users.add(r.receipt!.actor.user);
    }
  }

  // On-device attestations (R13).
  const attestations = verified.filter((r) => r.receipt!.action_id === ATTESTATION_ON_DEVICE);
  const sealedBackends = new Set<string>();
  // Gateway sessions (R24) attest with a `component` (e.g. "kriya-gateway") instead of a sealed
  // inference `backend` — they proxy a downstream / reach into a no-API app, with no model egress.
  // Surface that provenance so an auditor sees a governed proxy/reach-in session ran on-device, not
  // only an in-process host backend.
  const components = new Set<string>();
  for (const r of attestations) {
    const p = r.receipt!.params;
    if (p && typeof p === "object" && !Array.isArray(p)) {
      if (typeof p.backend === "string") sealedBackends.add(p.backend);
      if (typeof p.component === "string") components.add(p.component);
    }
  }

  // Action inventory (verified app actions, excluding the attestation marker).
  const counts = new Map<string, number>();
  for (const r of verified) {
    const id = r.receipt!.action_id;
    if (id === ATTESTATION_ON_DEVICE) continue;
    counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  const actionInventory: ActionInventoryItem[] = [...counts.entries()]
    .map(([action, count]) => ({
      action,
      count,
      tier: decide(policy, action).decision,
      destructive: isDestructive(action),
    }))
    .sort((a, b) => b.count - a.count);

  const approvalGatedActions = actionInventory.filter((a) => a.tier === "approval").map((a) => a.action);
  const denyByDefault = policy.rules.some((r) => r.action === "*" && r.tier === "deny") ||
    !policy.rules.some((r) => r.action === "*");

  const totalReceipts = withReceipt.length;
  const coveragePct = totalReceipts === 0 ? 0 : Math.round((attributed / verified.length || 0) * 100);

  const bundle: Omit<EvidenceBundle, "controls"> = {
    generatedAt: iso(opts.generatedAt),
    organization: opts.organization?.trim() || "Local workspace",
    period: { from: times.length ? iso(Math.min(...times)) : null, to: times.length ? iso(Math.max(...times)) : null },
    integrity: { totalReceipts, verified: verified.length, failed, distinctSigners: signers.size },
    attribution: { attributed, coveragePct, agents: [...agents].sort(), users: [...users].sort() },
    onDevice: {
      attestations: attestations.length,
      sealedBackends: [...sealedBackends].sort(),
      components: [...components].sort(),
    },
    humanOversight: {
      approvalGatedActions,
      denyByDefault,
      budgetCapPerMinute: policy.maxActionsPerMinute,
    },
    actionInventory,
  };

  const distinctApps = new Set(withReceipt.map((r) => r.source)).size;
  return {
    ...bundle,
    controls: mapControls(bundle, {
      distinctApps,
      distinctAgents: bundle.attribution.agents.length,
      coverage: opts.coverage,
    }),
  };
}

/** Derive control-by-control status from the computed facts. */
function mapControls(
  b: Omit<EvidenceBundle, "controls">,
  meta: { distinctApps: number; distinctAgents: number; coverage?: CoverageEvidence },
): EvidenceControl[] {
  const { integrity, attribution, onDevice, humanOversight } = b;
  const hasReceipts = integrity.totalReceipts > 0;
  const allVerified = hasReceipts && integrity.failed === 0;
  // GA-3: cite the signed coverage-completeness chain as AU-2/AU-12 completeness evidence. Only when
  // a non-empty coverage summary is supplied — the evidence text is unchanged otherwise.
  const cov = meta.coverage && meta.coverage.snapshots > 0 ? meta.coverage : null;
  const coverageCreationCite = cov
    ? ` Completeness is itself attested: ${cov.snapshots} signed coverage snapshot(s) (${cov.chainOk ? "chain intact" : "chain BROKEN"}) record which lanes were governed over the window — what was and wasn't logged is provable, not asserted.`
    : "";
  const coverageFailureCite = cov
    ? " The signed coverage chain makes a stopped or silenced logging process visible by absence — a gap in the heartbeat chain, not a quiet nothing."
    : "";

  const integrityStatus: ControlStatus = !hasReceipts ? "gap" : allVerified ? "satisfied" : "partial";
  const attributionStatus: ControlStatus =
    attribution.coveragePct === 100 ? "satisfied" : attribution.coveragePct > 0 ? "partial" : "gap";
  const oversightStatus: ControlStatus =
    humanOversight.approvalGatedActions.length > 0 && humanOversight.denyByDefault
      ? "satisfied"
      : humanOversight.denyByDefault
        ? "partial"
        : "gap";
  const onDeviceStatus: ControlStatus = onDevice.attestations > 0 ? "satisfied" : "gap";
  // Several NIST/SOC2 controls describe an organizational or OS-level process (review cadence,
  // alerting/paging, clock-sync policy) that kriya can surface signal for but never itself
  // complete — so evidence alone can push these to "partial", never "satisfied".
  const partialWhenReceipts: ControlStatus = hasReceipts ? "partial" : "gap";

  return [
    {
      framework: "EU AI Act",
      control: "Art. 12 — Record-keeping",
      requirement: "High-risk AI systems must automatically log events over their lifetime.",
      evidence: `${integrity.verified} signed receipt(s) verified${integrity.failed ? `, ${integrity.failed} failed/tampered` : ""}; ${integrity.distinctSigners} signer key(s).`,
      status: integrityStatus,
    },
    {
      framework: "EU AI Act",
      control: "Art. 14 — Human oversight",
      requirement: "High-risk actions must be subject to effective human oversight.",
      evidence: humanOversight.approvalGatedActions.length
        ? `${humanOversight.approvalGatedActions.length} action(s) gated behind human approval: ${humanOversight.approvalGatedActions.join(", ")}. Deny-by-default: ${humanOversight.denyByDefault ? "yes" : "no"}.`
        : `Deny-by-default: ${humanOversight.denyByDefault ? "yes" : "no"}; no approval-gated actions observed.`,
      status: oversightStatus,
    },
    {
      framework: "EU AI Act",
      control: "Art. 12(2) — Traceability",
      requirement: "Logging shall enable the traceability of the AI system's functioning appropriate to its intended purpose.",
      evidence: `${attribution.coveragePct}% of verified receipts attributed to an agent + operator (agents: ${attribution.agents.join(", ") || "—"}).`,
      status: attributionStatus,
    },
    {
      framework: "EU AI Act",
      control: "Art. 26(6) — Deployer log retention",
      requirement: "Deployers of high-risk AI systems keep the automatically generated logs for an appropriate period (at least six months).",
      evidence: hasReceipts
        ? `${integrity.totalReceipts} receipt(s) retained locally as JSONL under the deployer's own control; kriya does not enforce or verify a specific retention schedule (e.g. the six-month minimum) — that is the deployer's responsibility.`
        : "No logs retained yet.",
      status: partialWhenReceipts,
    },
    {
      framework: "SOC 2",
      control: "CC7.2 — Monitoring",
      requirement: "Monitor system components and detect anomalies / tampering.",
      evidence: allVerified
        ? "Every receipt's Ed25519 signature verified; no tampering detected."
        : hasReceipts
          ? `${integrity.failed} receipt(s) failed verification — tampering or corruption detected.`
          : "No audit data provided.",
      status: integrityStatus,
    },
    {
      framework: "SOC 2",
      control: "CC7.3 — Security event evaluation",
      requirement: "The entity evaluates security events to determine whether they could or have resulted in a failure to meet objectives and, if so, takes action.",
      evidence: hasReceipts
        ? "Per-receipt verification failures and hash-chain-break flags surface the security-event signal; the evaluation and response process itself is organizational, outside kriya."
        : "No security-event signal available yet.",
      status: partialWhenReceipts,
    },
    {
      framework: "SOC 2",
      control: "CC8.1 — Change management",
      requirement: "The entity authorizes, designs, tests, approves, and implements changes.",
      evidence: humanOversight.approvalGatedActions.length
        ? `${humanOversight.approvalGatedActions.length} agent-driven change action(s) require human approval before execution: ${humanOversight.approvalGatedActions.join(", ")}. Deny-by-default: ${humanOversight.denyByDefault ? "yes" : "no"}.`
        : `Deny-by-default: ${humanOversight.denyByDefault ? "yes" : "no"}; no approval-gated change actions observed.`,
      status: oversightStatus,
    },
    {
      framework: "ISO 42001",
      control: "A.9 — Operation controls",
      requirement: "Operate the AI system under defined controls (policy, limits, oversight).",
      evidence: `Deny-by-default policy with ${b.actionInventory.length} action(s) observed; budget cap ${humanOversight.budgetCapPerMinute ?? "none"}${humanOversight.budgetCapPerMinute ? "/min" : ""}.`,
      status: oversightStatus,
    },
    {
      framework: "ISO 42001",
      control: "A.6.2.6 — Operation and monitoring",
      requirement: "Define and implement the elements necessary for the ongoing operation and monitoring of the AI system, including logging.",
      evidence: hasReceipts
        ? `The signed receipt stream is the operation/monitoring log (${integrity.verified} verified of ${integrity.totalReceipts}), surfaced live in the Console Monitor.`
        : "No operation log present yet.",
      status: integrityStatus,
    },
    {
      framework: "Data residency",
      control: "On-device processing",
      requirement: "Sensitive data is processed on-device with no remote egress.",
      evidence: onDevice.attestations
        ? `${onDevice.attestations} signed on-device attestation(s)` +
          (onDevice.sealedBackends.length ? `; sealed backend(s): ${onDevice.sealedBackends.join(", ")}` : "") +
          (onDevice.components.length ? `; governed component(s): ${onDevice.components.join(", ")}` : "") +
          "."
        : "No on-device attestations in this trail.",
      status: onDeviceStatus,
    },
    // NIST SP 800-171 rev 2, AU family (3.3.1–3.3.9) — CMMC L2 practice ids + NIST SP 800-53
    // crosswalk in the control label. The ICP is DIB/CMMC L2, so this is the headline mapping;
    // 3.3.9 is a deliberate, permanent gap (see below) — the honest ✗ is a credibility asset with
    // assessors, not a bug to hide.
    {
      framework: "NIST 800-171",
      control: "3.3.1 (AU.L2-3.3.1 · AU-2/3/12) — Audit record creation & retention",
      requirement: "Create and retain system audit logs/records to enable monitoring, analysis, investigation, and reporting of unlawful or unauthorized activity.",
      evidence: hasReceipts
        ? `${integrity.totalReceipts} signed receipt(s) retained across ${meta.distinctApps} app(s) and ${meta.distinctAgents} governed agent(s) as a hash-chained local JSONL log${integrity.failed ? `; ${integrity.failed} failed verification` : ""}; each record carries action id, parameters, timestamp, outcome, and signer.${coverageCreationCite}`
        : "No audit records present in this trail.",
      status: integrityStatus,
    },
    {
      framework: "NIST 800-171",
      control: "3.3.2 (AU.L2-3.3.2 · AU-3) — Individual accountability",
      requirement: "Ensure the actions of individual system users can be uniquely traced to those users so they can be held accountable.",
      evidence: `${attribution.coveragePct}% of verified receipts carry a signed agent + individual-operator identity (operators: ${attribution.users.join(", ") || "—"}).`,
      status: attributionStatus,
    },
    {
      framework: "NIST 800-171",
      control: "3.3.3 (AU.L2-3.3.3 · AU-2) — Review & update logged events",
      requirement: "Review and update logged events.",
      evidence: hasReceipts
        ? `${b.actionInventory.length} distinct action type(s) captured across policy tiers (allow/approval/deny); the periodic review and update of which events to log is an organizational process outside kriya.`
        : "No logged events to review yet.",
      status: partialWhenReceipts,
    },
    {
      framework: "NIST 800-171",
      control: "3.3.4 (AU.L2-3.3.4 · AU-5) — Audit logging process failure alerting",
      requirement: "Alert in the event of an audit logging process failure.",
      evidence: hasReceipts
        ? `Per-receipt verification failures and hash-chain breaks surface live in the Console, and the Coverage Map flags silent lanes; no external paging/alerting integration exists.${coverageFailureCite}`
        : "No audit logging process to alert on yet.",
      status: partialWhenReceipts,
    },
    {
      framework: "NIST 800-171",
      control: "3.3.5 (AU.L2-3.3.5 · AU-6(3)) — Correlate audit review & analysis",
      requirement: "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of suspicious activity.",
      evidence: hasReceipts
        ? `Cross-app correlation on this machine (Audit view filtering across ${meta.distinctApps} app(s)) plus tamper flags support investigation; this is single-machine correlation, not cross-machine SIEM aggregation.`
        : "No audit records to correlate yet.",
      status: partialWhenReceipts,
    },
    {
      framework: "NIST 800-171",
      control: "3.3.6 (AU.L2-3.3.6 · AU-7) — Audit record reduction & report generation",
      requirement: "Provide audit record reduction and report generation to support on-demand analysis and reporting.",
      evidence: hasReceipts
        ? "This Markdown + JSON evidence bundle is itself the reduction/report artifact, generated on-demand from the signed trail and independently re-verifiable offline via kriya-audit."
        : "No audit records to reduce or report on yet.",
      status: hasReceipts ? "satisfied" : "gap",
    },
    {
      framework: "NIST 800-171",
      control: "3.3.7 (AU.L2-3.3.7 · AU-8) — Clock synchronization for time stamps",
      requirement: "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source for audit-record time stamps.",
      evidence: hasReceipts
        ? "Every receipt carries a host timestamp (ts_ms); clock synchronization against an authoritative source is OS-provided (NTP), outside kriya's control — this control is capped at partial regardless of trail size."
        : "No timestamped receipts present.",
      status: partialWhenReceipts,
    },
    {
      framework: "NIST 800-171",
      control: "3.3.8 (AU.L2-3.3.8 · AU-9) — Protect audit information & tools",
      requirement: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
      evidence: allVerified
        ? "Every receipt is Ed25519-signed and hash-chained; modification or deletion is detectable, not prevented, and independently re-verifiable offline."
        : hasReceipts
          ? `${integrity.failed} receipt(s) failed verification — tampering detected; the detection control is functioning as intended, investigate the flagged record(s).`
          : "No audit information to protect yet.",
      status: integrityStatus,
    },
    {
      framework: "NIST 800-171",
      control: "3.3.9 (AU.L2-3.3.9 · AU-9(4)) — Limit audit-logging management to privileged users",
      requirement: "Limit management of audit logging functionality to a subset of privileged users.",
      evidence: "kriya's audit tooling runs under the operator's own OS account, and in-app roles are self-asserted (see docs/TRUST.md) — kriya enforces no privileged-user restriction on who can manage audit logging; this must be enforced by an OS-level or organizational access control.",
      status: "gap",
    },
  ];
}

export function renderJson(bundle: EvidenceBundle): string {
  return JSON.stringify(bundle, null, 2);
}

const ICON: Record<ControlStatus, string> = { satisfied: "✓", partial: "◐", gap: "✗" };

/** Render the bundle as a readable Markdown compliance report. */
export function renderMarkdown(b: EvidenceBundle): string {
  const L: string[] = [];
  L.push(`# Compliance evidence — ${b.organization}`);
  L.push("");
  L.push(`_Generated ${b.generatedAt} by kriya Console. Evidence derived from cryptographically signed audit receipts, verified locally._`);
  L.push("");
  L.push(`**Period:** ${b.period.from ?? "—"} → ${b.period.to ?? "—"}`);
  L.push("");
  L.push("## Audit integrity");
  L.push("");
  L.push(`- Receipts: **${b.integrity.totalReceipts}**`);
  L.push(`- Verified: **${b.integrity.verified}**`);
  L.push(`- Failed / tampered: **${b.integrity.failed}**`);
  L.push(`- Distinct signer keys: **${b.integrity.distinctSigners}**`);
  L.push("");
  L.push("## Attribution (who acted)");
  L.push("");
  L.push(`- Coverage: **${b.attribution.coveragePct}%** of verified receipts carry an actor`);
  L.push(`- Agents: ${b.attribution.agents.join(", ") || "—"}`);
  L.push(`- Operators: ${b.attribution.users.join(", ") || "—"}`);
  L.push("");
  L.push("## Human oversight & on-device posture");
  L.push("");
  L.push(`- Deny-by-default policy: **${b.humanOversight.denyByDefault ? "yes" : "no"}**`);
  L.push(`- Approval-gated actions observed: ${b.humanOversight.approvalGatedActions.join(", ") || "—"}`);
  L.push(`- Budget cap: ${b.humanOversight.budgetCapPerMinute ? `${b.humanOversight.budgetCapPerMinute}/min` : "none"}`);
  L.push(`- On-device attestations: **${b.onDevice.attestations}**${b.onDevice.sealedBackends.length ? ` (${b.onDevice.sealedBackends.join(", ")})` : ""}${b.onDevice.components.length ? ` · via ${b.onDevice.components.join(", ")}` : ""}`);
  L.push("");
  L.push("## Action inventory");
  L.push("");
  L.push("| Action | Count | Policy tier | Destructive |");
  L.push("| --- | ---: | --- | --- |");
  for (const a of b.actionInventory) {
    L.push(`| \`${a.action}\` | ${a.count} | ${a.tier} | ${a.destructive ? "yes" : ""} |`);
  }
  L.push("");
  L.push("## Control mapping");
  L.push("");
  L.push("| Framework | Control | Status | Evidence |");
  L.push("| --- | --- | --- | --- |");
  for (const c of b.controls) {
    L.push(`| ${c.framework} | ${c.control} | ${ICON[c.status]} ${c.status} | ${c.evidence} |`);
  }
  L.push("");
  L.push("_Status: ✓ satisfied · ◐ partial · ✗ gap. This report is evidence, not a certification._");
  L.push("");
  return L.join("\n");
}
