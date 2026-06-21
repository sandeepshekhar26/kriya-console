// Budget controls (R6 increment 4) — observed per-app / per-agent / per-operator usage against the
// policy's rate caps (pairs with runtime R11: budget.max_actions_per_minute /
// budget.max_api_calls_per_hour).
//
// Honest measurement note: the host ENFORCES the per-minute cap by stopping a run before it signs an
// over-budget action, so over-cap actions never reach the audit log. The console therefore measures
// the observed ACTION rate from verified receipts (peak actions in any trailing 60s window) and reads
// a scope sitting AT the cap as the visible proxy for the host throttling it. Inference/API calls are
// not individually signed, so the per-hour api-call cap is surfaced as configured-only — the log
// cannot measure it. Pure + framework-free so it is exhaustively unit-testable.

import type { AuditRow } from "./types";

const MINUTE_MS = 60_000;
const APPROACHING = 0.8; // peak ≥ 80% of the cap → "approaching"

/** Reserved attestation action id (R13) — a run marker, not an app action; excluded from rates. */
const ATTESTATION_ID = "kriya.attestation.on_device";

/** The lens a usage breakdown is grouped by: the app (audit source), the agent, or the operator. */
export type ScopeKind = "source" | "agent" | "user";

export interface BudgetCaps {
  /** Per-minute action cap from the policy (null = uncapped). */
  maxActionsPerMinute: number | null;
  /** Per-hour inference/API-call cap (null = uncapped). Informational: inference calls are not
   *  individually signed, so the audit log can't measure them — usage is computed only for the
   *  per-minute ACTION rate the receipts make visible. */
  maxApiCallsPerHour: number | null;
}

export type UsageStatus = "ok" | "approaching" | "at-limit";

/** Observed usage for one scope (an app source, an agent, or an operator) vs the action cap. */
export interface ScopeUsage {
  scope: string;
  totalActions: number;
  /** Max actions in any trailing 60s window — the closest the log ran to the cap. */
  peakPerMinute: number;
  /** Epoch ms the peak window ended, or null if the scope has no actions. */
  peakAtMs: number | null;
  /** peakPerMinute / cap as a %, or null when uncapped. */
  utilizationPct: number | null;
  status: UsageStatus;
}

/** A moment a scope's trailing-60s action count reached the cap — the observable proxy for the host
 *  throttling it (over-cap actions are stopped before signing, so they never reach the log). */
export interface AtLimitEvent {
  scope: string;
  ts_ms: number;
  windowCount: number;
}

function scopeKeyOf(row: AuditRow, kind: ScopeKind): string {
  if (kind === "source") return row.source;
  const actor = row.receipt?.actor;
  if (kind === "agent") return actor?.agent ?? "(unattributed)";
  return actor?.user ?? "(unattributed)";
}

/** Group the timestamps of verified app-action receipts by scope (excludes failed-verification rows
 *  and the on-device attestation marker, which is a run record, not an action). */
function timestampsByScope(rows: AuditRow[], kind: ScopeKind): Map<string, number[]> {
  const m = new Map<string, number[]>();
  for (const row of rows) {
    if (!row.outcome.ok || !row.receipt) continue;
    if (row.receipt.action_id === ATTESTATION_ID) continue;
    const key = scopeKeyOf(row, kind);
    const list = m.get(key) ?? [];
    list.push(row.receipt.ts_ms);
    m.set(key, list);
  }
  return m;
}

/** Max events in any trailing `windowMs` window over a list of timestamps, plus the window-end ts.
 *  The window is half-open `(t - windowMs, t]` — diff strictly `< windowMs` — mirroring the host's
 *  `now - t < WINDOW_MS` sliding-window budget check. */
export function peakWindow(
  timestamps: number[],
  windowMs: number = MINUTE_MS,
): { peak: number; atMs: number | null } {
  const ts = [...timestamps].sort((a, b) => a - b);
  let peak = 0;
  let atMs: number | null = null;
  let start = 0;
  for (let end = 0; end < ts.length; end++) {
    while (ts[end]! - ts[start]! >= windowMs) start++;
    const count = end - start + 1;
    if (count > peak) {
      peak = count;
      atMs = ts[end]!;
    }
  }
  return { peak, atMs };
}

/** Per-scope observed usage vs the per-minute action cap, busiest first. */
export function usageByScope(rows: AuditRow[], kind: ScopeKind, caps: BudgetCaps): ScopeUsage[] {
  const cap = caps.maxActionsPerMinute;
  const out: ScopeUsage[] = [];
  for (const [scope, timestamps] of timestampsByScope(rows, kind)) {
    const { peak, atMs } = peakWindow(timestamps);
    const capped = typeof cap === "number" && cap > 0;
    const utilizationPct = capped ? Math.round((peak / cap!) * 100) : null;
    let status: UsageStatus = "ok";
    if (capped) {
      if (peak >= cap!) status = "at-limit";
      else if (peak >= cap! * APPROACHING) status = "approaching";
    }
    out.push({ scope, totalActions: timestamps.length, peakPerMinute: peak, peakAtMs: atMs, utilizationPct, status });
  }
  return out.sort((a, b) => b.peakPerMinute - a.peakPerMinute || b.totalActions - a.totalActions);
}

/** Every moment a scope's trailing-60s action count reached the cap, newest first. Empty when
 *  uncapped (nothing to breach against). */
export function atLimitEvents(rows: AuditRow[], kind: ScopeKind, cap: number | null): AtLimitEvent[] {
  if (typeof cap !== "number" || cap <= 0) return [];
  const events: AtLimitEvent[] = [];
  for (const [scope, timestamps] of timestampsByScope(rows, kind)) {
    const ts = [...timestamps].sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < ts.length; end++) {
      while (ts[end]! - ts[start]! >= MINUTE_MS) start++;
      const windowCount = end - start + 1;
      if (windowCount >= cap) events.push({ scope, ts_ms: ts[end]!, windowCount });
    }
  }
  return events.sort((a, b) => b.ts_ms - a.ts_ms);
}

export interface BudgetSummary {
  scopesAtLimit: number;
  scopesApproaching: number;
  atLimitEvents: number;
  capPerMinute: number | null;
  capPerHour: number | null;
}

/** Headline counts for the overview / sidebar. */
export function summarizeBudget(rows: AuditRow[], kind: ScopeKind, caps: BudgetCaps): BudgetSummary {
  const usage = usageByScope(rows, kind, caps);
  return {
    scopesAtLimit: usage.filter((u) => u.status === "at-limit").length,
    scopesApproaching: usage.filter((u) => u.status === "approaching").length,
    atLimitEvents: atLimitEvents(rows, kind, caps.maxActionsPerMinute).length,
    capPerMinute: caps.maxActionsPerMinute,
    capPerHour: caps.maxApiCallsPerHour,
  };
}
