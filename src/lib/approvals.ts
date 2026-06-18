// Approval routing (R6 increment 3) — a cross-app/agent queue for the actions a policy holds
// for a human. A host emits an approval request when a guarded action is proposed; the console
// aggregates those requests across apps and agents, prioritizes them, and records approve/deny
// decisions (with a reason + who decided), persisting the queue so it survives a reload.
//
// Pure + framework-free so it is exhaustively unit-testable; the React view is a thin shell.

import type { Actor, Json } from "./types";

/** A guarded action awaiting a human decision, aggregated from one app/agent. */
export interface PendingApproval {
  /** Stable id — the host's step_id, unique per proposed action. */
  id: string;
  /** Which app / audit source the request came from. */
  source: string;
  /** Who is asking (R8): the agent + operator. Optional for pre-R8 hosts. */
  actor?: Actor;
  action_id: string;
  params: Json;
  reasoning: string;
  /** When the host raised the request (epoch ms). */
  requested_ms: number;
}

export type Risk = "high" | "normal";
export type DecisionKind = "approved" | "denied";

/** A pending approval annotated with routing metadata. */
export interface RoutedApproval extends PendingApproval {
  risk: Risk;
  /** Seconds the request has waited, given a "now" — surfaces stale, ignored approvals. */
  waitingSeconds: number;
}

/** A recorded decision on a previously-pending approval. */
export interface DecidedApproval extends PendingApproval {
  decision: DecisionKind;
  reason: string;
  decidedBy: string;
  decided_ms: number;
}

/** The full queue state — what the view persists to localStorage. */
export interface QueueState {
  pending: PendingApproval[];
  decided: DecidedApproval[];
}

// Action-name fragments that mark a high-risk request: destructive (mirrors the host's
// `is_destructive_name`) plus money movement and account closure. Routing only — it raises
// priority and review attention, it does not replace the policy decision.
const HIGH_RISK = [
  "delete",
  "remove",
  "destroy",
  "drop",
  "purge",
  "wipe",
  "close",
  "transfer",
  "wire",
  "send",
  "pay",
  "withdraw",
];

/** Classify an action's risk from its id. */
export function classifyRisk(actionId: string): Risk {
  const a = actionId.toLowerCase();
  return HIGH_RISK.some((k) => a.includes(k)) ? "high" : "normal";
}

/** Parse a JSONL stream of pending-approval records, skipping blank/malformed lines. */
export function parsePendingApprovals(text: string, source: string): PendingApproval[] {
  const out: PendingApproval[] = [];
  for (const raw of text.split("\n")) {
    if (raw.trim() === "") continue;
    let v: unknown;
    try {
      v = JSON.parse(raw);
    } catch {
      continue;
    }
    const p = asPending(v, source);
    if (p) out.push(p);
  }
  return out;
}

function asPending(v: unknown, source: string): PendingApproval | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  if (typeof o.id !== "string" || typeof o.action_id !== "string") return null;
  const actor =
    o.actor && typeof o.actor === "object"
      ? (o.actor as Record<string, unknown>)
      : undefined;
  return {
    id: o.id,
    source: typeof o.source === "string" ? o.source : source,
    actor:
      actor && typeof actor.agent === "string" && typeof actor.user === "string"
        ? { agent: actor.agent, user: actor.user }
        : undefined,
    action_id: o.action_id,
    params: (o.params ?? {}) as Json,
    reasoning: typeof o.reasoning === "string" ? o.reasoning : "",
    requested_ms: typeof o.requested_ms === "number" ? o.requested_ms : 0,
  };
}

/**
 * Order the queue for review: highest-risk first, then longest-waiting first (FIFO within a
 * risk tier, so nothing starves). `nowMs` is injected for deterministic tests.
 */
export function routeQueue(pending: PendingApproval[], nowMs: number): RoutedApproval[] {
  return pending
    .map((p) => ({
      ...p,
      risk: classifyRisk(p.action_id),
      waitingSeconds: Math.max(0, Math.round((nowMs - p.requested_ms) / 1000)),
    }))
    .sort((a, b) => {
      if (a.risk !== b.risk) return a.risk === "high" ? -1 : 1;
      return a.requested_ms - b.requested_ms; // older first
    });
}

/** Group routed approvals by a key — the cross-app / cross-agent lenses. */
export function groupBy(
  approvals: RoutedApproval[],
  key: "source" | "agent",
): Map<string, RoutedApproval[]> {
  const m = new Map<string, RoutedApproval[]>();
  for (const a of approvals) {
    const k = key === "source" ? a.source : (a.actor?.agent ?? "(unattributed)");
    const list = m.get(k) ?? [];
    list.push(a);
    m.set(k, list);
  }
  return m;
}

/**
 * Record a decision on one pending approval. Returns a NEW state (immutable) with the item
 * moved from `pending` to `decided`. A reason is required for denials so the audit trail
 * explains *why* — a no-op (unchanged state) if the id isn't pending.
 */
export function decide(
  state: QueueState,
  id: string,
  decision: DecisionKind,
  reason: string,
  decidedBy: string,
  decidedMs: number,
): QueueState {
  const item = state.pending.find((p) => p.id === id);
  if (!item) return state;
  return {
    pending: state.pending.filter((p) => p.id !== id),
    decided: [
      ...state.decided,
      { ...item, decision, reason: reason.trim(), decidedBy, decided_ms: decidedMs },
    ],
  };
}

/** Merge newly-ingested approvals into the queue, ignoring ids already pending or decided. */
export function ingestPending(state: QueueState, incoming: PendingApproval[]): QueueState {
  const known = new Set([
    ...state.pending.map((p) => p.id),
    ...state.decided.map((d) => d.id),
  ]);
  const fresh = incoming.filter((p) => !known.has(p.id));
  return { ...state, pending: [...state.pending, ...fresh] };
}

/** Headline counts for the overview + sidebar badge. */
export function summarize(state: QueueState) {
  const highPending = state.pending.filter((p) => classifyRisk(p.action_id) === "high").length;
  return {
    pending: state.pending.length,
    highRiskPending: highPending,
    approved: state.decided.filter((d) => d.decision === "approved").length,
    denied: state.decided.filter((d) => d.decision === "denied").length,
  };
}
