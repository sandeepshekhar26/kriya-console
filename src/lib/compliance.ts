// Compliance-evidence export (R7) — turn a verified signed-audit trail into the artifacts an
// auditor asks for: an integrity attestation, an attribution + oversight summary, and a mapping
// of the evidence to named controls (SOC 2 / ISO 42001 / EU AI Act). The EU AI Act's logging
// (Art. 12) and human-oversight (Art. 14) duties begin to bite as enforcement opens in 2026, and
// "show me your agent's audit trail" is exactly what a kriya deployment already has — signed.
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
  opts: { generatedAt: number; organization?: string },
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

  return { ...bundle, controls: mapControls(bundle) };
}

/** Derive control-by-control status from the computed facts. */
function mapControls(b: Omit<EvidenceBundle, "controls">): EvidenceControl[] {
  const { integrity, attribution, onDevice, humanOversight } = b;
  const hasReceipts = integrity.totalReceipts > 0;
  const allVerified = hasReceipts && integrity.failed === 0;

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
      control: "Art. 13 — Traceability",
      requirement: "Operation must be traceable to the actor responsible.",
      evidence: `${attribution.coveragePct}% of verified receipts attributed to an agent + operator (agents: ${attribution.agents.join(", ") || "—"}).`,
      status: attributionStatus,
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
      framework: "ISO 42001",
      control: "A.9 — Operation controls",
      requirement: "Operate the AI system under defined controls (policy, limits, oversight).",
      evidence: `Deny-by-default policy with ${b.actionInventory.length} action(s) observed; budget cap ${humanOversight.budgetCapPerMinute ?? "none"}${humanOversight.budgetCapPerMinute ? "/min" : ""}.`,
      status: oversightStatus,
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
