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
import { buildSessionTrees, summarizeCorrelation, type CorrelationSummary } from "./sessionTree.ts";

/** Reserved action id for the R13 on-device attestation receipt. */
export const ATTESTATION_ON_DEVICE = "kriya.attestation.on_device";

/** The reserved `kriya.io.*` namespace prefix (EG-2 / doc 24 §4.2) — the governed-lane egress/ingress
 *  ledger's signed receipts. Excluded from the app-action inventory (governance metadata, like the
 *  on-device attestation marker) and the sole gate on whether the egress control rows below appear. */
const KRIYA_IO_PREFIX = "kriya.io.";

/** The doc 24 §3.1 scope block, verbatim — embedded in every egress-bearing compliance export. States
 *  the honesty ceiling BEFORE it can be asked: which lanes are covered, what a governed-lane receipt
 *  can never prove, and that this artifact does not by itself render any control MET. */
export const EGRESS_SCOPE_BLOCK =
  "Scope: this artifact covers only agent traffic proxied through the kriya gateway (MCP-over-HTTP " +
  "connectors, gateway-proxied tool calls) and the hook-observed tool lane. Agent processes can " +
  "generate network traffic outside these lanes — spawned subprocesses, and the outbound connections " +
  "of stdio MCP servers — which kriya does not observe, control, or record. Enforcement rides a " +
  "cooperative hook that can be disabled at the host (see TRUST.md). This artifact is supporting " +
  "evidence toward the identified assessment objectives for the agent-connector lane only; it does " +
  "not by itself render any control MET, and coverage of non-governed agent egress must be documented " +
  "in the organization's SSP under its own boundary and flow controls.";

/** Egress/ingress ledger facts computed from VERIFIED `kriya.io.*` receipts in the window — the sole
 *  gate on whether the doc 24 §3 egress control rows appear at all (never hard-coded; absent, not
 *  "gap", when the trail carries no such receipts). */
export interface EgressEvidence {
  verifiedReceipts: number;
  allow: number;
  deny: number;
  approve: number;
}

/** The governed-surface posture statement (doc 24 §7.2 row 4) — deliberately WEAKER than the
 *  document's pinned target text, which assumes a signed toggle/policy-version receipt bounding the
 *  window (not yet built): this repo cannot yet PROVE the egress ledger was continuously enabled for
 *  the full window, only that governed-lane activity was (or wasn't) observed. Honesty over
 *  completeness (§6-H1/H10) — "not monitored" when the governed surface itself was silent, never
 *  "zero egress" without evidence the surface was even active. */
export type EgressPostureState = "not_monitored" | "zero_observed" | "egress_present";

export interface EgressPosture {
  state: EgressPostureState;
  governedLaneReceipts: number;
  egressReceipts: number;
}

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
  /** Egress/ingress ledger facts (EG-2/EG-3), `null` when the trail carries no verified `kriya.io.*`
   *  receipts in the window — the same signal that gates whether the doc 24 §3 control rows appear. */
  egress: EgressEvidence | null;
  /** The governed-surface posture statement (doc 24 §7.2 row 4) — always present, unlike `egress`. */
  egressPosture: EgressPosture;
  /** Run-correlation appendix (S3) — the session structure computed from verified `kriya.corr`
   *  receipts. **Omitted entirely** when the window carries no correlated receipts, so a
   *  zero-correlation export is byte-identical to a pre-S3 one (BC law). */
  correlation?: CorrelationSummary;
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

  // Action inventory (verified app actions, excluding the attestation marker and the kriya.io.*
  // governance-metadata ledger — both are meta-evidence, not "things the agent did", same treatment
  // as the coverage-snapshot exclusion (GA-3)).
  const counts = new Map<string, number>();
  for (const r of verified) {
    const id = r.receipt!.action_id;
    if (id === ATTESTATION_ON_DEVICE || id.startsWith(KRIYA_IO_PREFIX)) continue;
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

  // Egress/ingress ledger evidence (EG-2/EG-3, doc 24 §3) — COMPUTED from verified kriya.io.*
  // receipts only; `null` (not zeroed-out) when the trail carries none, which is what gates the
  // egress control rows below from appearing at all.
  const ioVerified = verified.filter((r) => r.receipt!.action_id.startsWith(KRIYA_IO_PREFIX));
  const egress: EgressEvidence | null = ioVerified.length
    ? {
        verifiedReceipts: ioVerified.length,
        allow: ioVerified.filter((r) => r.receipt!.action_id.endsWith(".allow")).length,
        deny: ioVerified.filter((r) => r.receipt!.action_id.endsWith(".deny")).length,
        approve: ioVerified.filter((r) => r.receipt!.action_id.endsWith(".approve")).length,
      }
    : null;

  // Governed-surface posture (doc 24 §7.2 row 4, weakened honestly — see EgressPosture's doc comment):
  // "was the governed surface even active" (actionInventory's total) vs "did it produce egress"
  // (egress-direction kriya.io.* receipts only, never ingress).
  const governedLaneReceipts = actionInventory.reduce((sum, a) => sum + a.count, 0);
  const egressReceiptCount = verified.filter((r) => r.receipt!.action_id.startsWith("kriya.io.egress.")).length;
  const egressPosture: EgressPosture = {
    state:
      governedLaneReceipts === 0 && egressReceiptCount === 0
        ? "not_monitored"
        : egressReceiptCount === 0
          ? "zero_observed"
          : "egress_present",
    governedLaneReceipts,
    egressReceipts: egressReceiptCount,
  };

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
    egress,
    egressPosture,
    // Run correlation (S3): the appendix numbers, present ONLY when correlated receipts exist so a
    // zero-correlation export stays byte-identical (undefined ⇒ omitted by JSON.stringify + Markdown).
    correlation: summarizeCorrelation(buildSessionTrees(rows)) ?? undefined,
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
  const { integrity, attribution, onDevice, humanOversight, egress } = b;
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

  const rows: EvidenceControl[] = [
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

  // Egress/ingress ledger controls (EG-2/EG-3, doc 24 §3) — appear ONLY when the trail carries
  // verified `kriya.io.*` receipts in the window; never hard-coded, never present as "gap" on an
  // egress-silent trail (that trail simply carries none of these rows at all). Every status here is
  // capped at "partial" (◐) — never "satisfied" — because the governed-lane ceiling (doc 24 §7.2) is
  // structural: a spawned subprocess or a stdio server's own outbound traffic bypasses this lane, so
  // no egress control here can honestly claim full/total flow enforcement. Deliberately absent:
  // 3.13.1, 3.13.6, SC-7, SC-8, CC6.6 — killed at the governed-lane layer (doc 24 §3); adding them
  // would break the honesty moat. The word "DLP" never appears.
  if (egress) {
    const denyCite = egress.deny > 0
      ? `${egress.deny} denial(s) against the allowlist observed in this window (unapproved-endpoint / anomalous-destination detection on governed lanes).`
      : "No denials observed in this window — the allowlist has not yet been exercised against an unlisted destination.";
    rows.push(
      {
        framework: "NIST 800-171",
        control: "3.1.3 (AC) — CUI flow enforcement",
        requirement: "Control CUI flows in accordance with approved authorizations.",
        evidence: `Egress allow/deny/approve by destination for governed connector lanes (${egress.verifiedReceipts} signed kriya.io.* receipt(s) verified: ${egress.allow} allow, ${egress.deny} deny, ${egress.approve} approve), signed per-decision. Governed lanes only — a spawned subprocess or a stdio MCP server's own outbound traffic is not observed. ${EGRESS_SCOPE_BLOCK}`,
        status: "partial",
      },
      {
        framework: "NIST 800-171",
        control: "3.4.2 (CM) — Enforce configuration settings",
        requirement: "Establish and enforce security configuration settings.",
        evidence: `The egress allowlist is an enforced, receipted setting — ${egress.verifiedReceipts} governed-lane decision(s) signed against it this window. Product-scoped: this is one enforced setting on one control-plane app, never a system-wide configuration-management claim.`,
        status: "partial",
      },
      {
        framework: "NIST 800-171",
        control: "3.14.6/3.14.7 (SI-4) — Monitor / identify unauthorized use",
        requirement: "Monitor and identify unauthorized use of organizational systems.",
        evidence: `Unapproved-endpoint and anomalous-egress detection on governed lanes. ${denyCite}`,
        status: "partial",
      },
      {
        framework: "NIST 800-53",
        control: "AC-4 — Information flow enforcement",
        requirement: "Enforce approved authorizations for controlling the flow of information.",
        evidence: `A signed, per-decision enforcement point on governed connector lanes (${egress.verifiedReceipts} kriya.io.* receipt(s) verified). Nothing at this layer stands in the way of a flow that avoids it entirely — a spawned subprocess bypasses it (see the E2 host-observation roadmap and TRUST.md).`,
        status: "partial",
      },
      {
        framework: "NIST 800-53",
        control: "SI-4 — System monitoring",
        requirement: "Monitor the system to detect attacks and indicators of potential attacks.",
        evidence: `The governed-lane egress ledger FEEDS an organization's SI-4 monitoring program as one signed source among others — it is a contributing signal, never claimed to BE the organization's system monitoring. ${egress.verifiedReceipts} receipt(s) verified in this window.`,
        status: "partial",
      },
      {
        framework: "SOC 2",
        control: "CC6.1 — Logical access boundaries",
        requirement: "The entity implements logical access security software, infrastructure, and architectures.",
        evidence: `The gateway is a managed access point for governed connector lanes — ${egress.verifiedReceipts} signed access decision(s) this window (${egress.allow} allow, ${egress.deny} deny, ${egress.approve} approve).`,
        status: "partial",
      },
      {
        framework: "SOC 2",
        control: "CC6.7 — Restrict transmission and movement",
        requirement: "The entity restricts the transmission, movement, and removal of information.",
        evidence: `A transmission-restriction control for governed agent lanes: destination-based allow/deny/approve, signed per decision (${egress.verifiedReceipts} receipt(s) verified this window). ${denyCite}`,
        status: "partial",
      },
      {
        framework: "SOC 2",
        control: "CC7.2 — Anomaly monitoring (governed-lane egress)",
        requirement: "The entity monitors system components for anomalies indicative of malicious acts, natural disasters, or errors.",
        evidence: `Detection tooling and logging of unusual egress activity on governed lanes. ${denyCite}`,
        status: "partial",
      },
      {
        framework: "EU AI Act",
        control: "Art. 12 — Record-keeping (governed-lane egress)",
        requirement: "High-risk AI systems must automatically log events over their lifetime.",
        evidence: `Readiness-framed: ${egress.verifiedReceipts} governed-lane egress/ingress event(s) signed and verified this window; Annex III high-risk obligations are deferred to Dec 2, 2027 pending the Digital Omnibus. If this agent system is not classified high-risk, this row is INAPPLICABLE, not partial — that classification is the deploying organization's own determination, not derived from this trail.`,
        status: "partial",
      },
      {
        framework: "DORA",
        control: "Art. 28(3) — Register reconciliation",
        requirement: "Maintain and keep updated a register of information on all contractual arrangements with ICT third-party service providers.",
        evidence: `A signed, actual-usage enumeration of governed-lane destinations feeds register reconciliation against the organization's Art. 28(3) ICT third-party register — ${egress.verifiedReceipts} receipt(s) verified this window. This is one input to that register, never a substitute for the organization's own maintained register.`,
        status: "partial",
      },
      {
        framework: "DORA",
        control: "Art. 10(2) / Art. 17 — Detection & incident management",
        requirement: "Put in place mechanisms to promptly detect anomalous activities; maintain an ICT-related incident management process.",
        evidence: `A lane-scoped detection/incident-timeline layer for governed agent egress — one of the "multiple layers of control" DORA expects, not the organization's full ICT risk framework. ${denyCite}`,
        status: "partial",
      },
    );
  }

  return rows;
}

/** Render the governed-surface posture statement (doc 24 §7.2 row 4). Three states, none of them
 *  ever "nothing left at all" or "zero egress" without governed-lane activity to back it (§6-H1/H10).
 *  Explicitly names the toggle-receipt gap rather than pretending it's closed. */
export function renderEgressPosture(p: EgressPosture): string {
  switch (p.state) {
    case "not_monitored":
      return "Governed-lane egress: NOT MONITORED in this window — zero governed-lane receipts of any kind were observed, so no statement about egress can be made either way. This is absent-by-configuration, not a zero-egress finding.";
    case "zero_observed":
      return `Governed-lane egress: zero kriya.io.egress.* receipts observed in this window, alongside ${p.governedLaneReceipts} other governed-lane receipt(s) — the governed surface was active and produced no egress. This does NOT prove the egress ledger was continuously enabled for the full window (no signed toggle/policy-version receipt bounds it yet — see docs/TRUST.md). The raw-egress lane (host-level observation) is a separate, GREY-by-default surface — see the Coverage Map. Any physical air gap or network isolation is the organization's own attested posture, not verified by kriya.`;
    case "egress_present":
      return `Governed-lane egress: NOT zero — ${p.egressReceipts} kriya.io.egress.* receipt(s) observed and verified in this window.`;
  }
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
  L.push("## Egress/ingress ledger (governed lanes)");
  L.push("");
  L.push(renderEgressPosture(b.egressPosture));
  if (b.egress) {
    L.push("");
    L.push(`- Signed \`kriya.io.*\` receipts verified in this window: **${b.egress.verifiedReceipts}** (${b.egress.allow} allow, ${b.egress.deny} deny, ${b.egress.approve} approve)`);
    L.push("");
    L.push(`> ${EGRESS_SCOPE_BLOCK}`);
  }
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
  // Run-correlation appendix (S3) — appended ONLY when correlated receipts exist, so a
  // zero-correlation report is byte-identical to a pre-S3 one.
  if (b.correlation) {
    const c = b.correlation;
    L.push("## Session correlation (appendix)");
    L.push("");
    L.push(
      `Computed from verified \`kriya.corr\` receipts: **${c.runs}** run(s) across **${c.actions}** correlated action(s); **${c.subAgents}** sub-agent(s) observed; **${c.spawns}** subagent-spawn action(s); **${c.blocked}** blocked/failed attempt(s).`,
    );
    L.push("");
    L.push(
      "_Run correlation groups a session's actions from the signed receipts; approval decisions are recorded separately in the approvals queue._",
    );
    L.push("");
  }
  L.push("_Status: ✓ satisfied · ◐ partial · ✗ gap. This report is evidence, not a certification._");
  L.push("");
  return L.join("\n");
}
