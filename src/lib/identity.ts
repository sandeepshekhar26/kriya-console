// Identity (R8, enterprise half) — per-operator / per-agent activity dashboards + an RBAC model
// keyed on the operator identity. The signed-receipt `actor` field (agent + user) is the open
// primitive (it stays in the runtime); this aggregates it across the VERIFIED audit log and adds
// role-based access control for the governance capabilities the console exposes.
//
// Scope note: SSO / OIDC (real authentication) needs a backend the client-only console doesn't have
// — it's a hosted-tier concern, deliberately out of scope here. What this provides is the
// client-feasible, auditable core of R8: who did what (attributed to verified receipts only) and
// which roles may approve / edit policy / view the audit. Pure + framework-free → exhaustively
// unit-testable; the React view is a thin shell.

import type { AuditRow } from "./types";

const ATTESTATION_ID = "kriya.attestation.on_device";
const UNATTRIBUTED = "(unattributed)";

export type IdentityKind = "user" | "agent";

/** Aggregated activity for one identity (an operator `user` or an `agent`). */
export interface IdentitySummary {
  id: string;
  kind: IdentityKind;
  /** Verified, executed actions attributed to this identity. */
  actions: number;
  /** Of those, how many the handler reported success for. */
  successes: number;
  /** successes / actions, 0..1 (0 when no actions). */
  successRate: number;
  /** Distinct apps (audit sources), sorted. */
  apps: string[];
  /** Distinct action ids, sorted. */
  actionIds: string[];
  /** For a user: the agents it drove; for an agent: the operators it ran for. Sorted. */
  counterparts: string[];
  firstSeenMs: number | null;
  lastSeenMs: number | null;
}

/**
 * Aggregate VERIFIED receipts by operator (`user`) or `agent`. Failed-verification rows are
 * excluded on purpose: their `actor` is part of the unverified bytes and can't be trusted to
 * attribute. The on-device attestation marker is a run record, not an app action, so it's skipped.
 */
export function summarizeIdentities(rows: AuditRow[], kind: IdentityKind): IdentitySummary[] {
  interface Acc {
    actions: number;
    successes: number;
    apps: Set<string>;
    actionIds: Set<string>;
    counterparts: Set<string>;
    first: number;
    last: number;
  }
  const acc = new Map<string, Acc>();

  for (const row of rows) {
    if (!row.outcome.ok || !row.receipt) continue;
    const r = row.receipt;
    if (r.action_id === ATTESTATION_ID) continue;

    const id = (kind === "user" ? r.actor?.user : r.actor?.agent) ?? UNATTRIBUTED;
    const counterpart = (kind === "user" ? r.actor?.agent : r.actor?.user) ?? UNATTRIBUTED;

    const e =
      acc.get(id) ??
      { actions: 0, successes: 0, apps: new Set(), actionIds: new Set(), counterparts: new Set(), first: r.ts_ms, last: r.ts_ms };
    e.actions += 1;
    if (r.success) e.successes += 1;
    e.apps.add(row.source);
    e.actionIds.add(r.action_id);
    if (r.actor) e.counterparts.add(counterpart);
    e.first = Math.min(e.first, r.ts_ms);
    e.last = Math.max(e.last, r.ts_ms);
    acc.set(id, e);
  }

  return [...acc.entries()]
    .map(([id, e]) => ({
      id,
      kind,
      actions: e.actions,
      successes: e.successes,
      successRate: e.actions === 0 ? 0 : e.successes / e.actions,
      apps: [...e.apps].sort(),
      actionIds: [...e.actionIds].sort(),
      counterparts: [...e.counterparts].sort(),
      firstSeenMs: e.actions ? e.first : null,
      lastSeenMs: e.actions ? e.last : null,
    }))
    .sort((a, b) => b.actions - a.actions || a.id.localeCompare(b.id));
}

// ── RBAC — roles keyed on the operator identity ────────────────────────────────

export type Role = "admin" | "approver" | "operator" | "viewer";
export const ROLES: Role[] = ["admin", "approver", "operator", "viewer"];

export type Capability = "approve" | "editPolicy" | "viewAudit";

/** Which governance capabilities each role grants. Fixed + simple so an auditor can read it. */
export const ROLE_CAPS: Record<Role, Capability[]> = {
  admin: ["approve", "editPolicy", "viewAudit"],
  approver: ["approve", "viewAudit"],
  operator: ["viewAudit"],
  viewer: ["viewAudit"],
};

export interface RbacModel {
  /** Operator (`user`) → role. Anyone unassigned falls to `defaultRole`. */
  assignments: Record<string, Role>;
  defaultRole: Role;
}

export function defaultRbac(): RbacModel {
  return { assignments: {}, defaultRole: "viewer" };
}

export function roleOf(rbac: RbacModel, user: string): Role {
  return rbac.assignments[user] ?? rbac.defaultRole;
}

export function can(rbac: RbacModel, user: string, capability: Capability): boolean {
  return ROLE_CAPS[roleOf(rbac, user)].includes(capability);
}

/** Assign (or change) a user's role — returns a NEW model (immutable). */
export function assignRole(rbac: RbacModel, user: string, role: Role): RbacModel {
  return { ...rbac, assignments: { ...rbac.assignments, [user]: role } };
}
