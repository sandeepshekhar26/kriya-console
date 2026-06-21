import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import type { Policy } from "../lib/policy";
import {
  usageByScope,
  atLimitEvents,
  summarizeBudget,
  type BudgetCaps,
  type ScopeKind,
  type UsageStatus,
} from "../lib/budget";

/** R6 increment 4 — live budget controls: observed per-app / per-agent / per-operator usage
 *  against the policy's rate caps, derived from the verified audit log. */
export function BudgetView({
  rows,
  policy,
  onLoadSample,
}: {
  rows: AuditRow[];
  policy: Policy;
  onLoadSample: () => void;
}) {
  const [kind, setKind] = useState<ScopeKind>("source");
  const caps: BudgetCaps = {
    maxActionsPerMinute: policy.maxActionsPerMinute,
    maxApiCallsPerHour: policy.maxApiCallsPerHour,
  };
  const usage = useMemo(() => usageByScope(rows, kind, caps), [rows, kind, caps.maxActionsPerMinute, caps.maxApiCallsPerHour]);
  const events = useMemo(() => atLimitEvents(rows, kind, caps.maxActionsPerMinute), [rows, kind, caps.maxActionsPerMinute]);
  const summary = useMemo(() => summarizeBudget(rows, kind, caps), [rows, kind, caps.maxActionsPerMinute, caps.maxApiCallsPerHour]);

  const empty = rows.filter((r) => r.outcome.ok).length === 0;

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Budget controls</h1>
          <p className="page-sub">
            How hard each app, agent, and operator runs against your policy's rate caps — derived
            from the verified audit log. A scope sitting <em>at</em> its cap is the host throttling it.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn ghost" onClick={onLoadSample}>
            Load sample
          </button>
        </div>
      </header>

      {empty ? (
        <div className="empty">
          <div className="empty-glyph">◔</div>
          <p>
            Budget usage is computed from your verified audit log. Load receipts in the{" "}
            <strong>Audit log</strong> tab (or here) to see per-app and per-agent action rates
            against the caps.
          </p>
          <button className="btn" onClick={onLoadSample}>
            Load sample audit
          </button>
        </div>
      ) : (
        <>
          <section className="caps-banner">
            <CapPill label="Actions / minute" value={caps.maxActionsPerMinute} />
            <CapPill
              label="API calls / hour"
              value={caps.maxApiCallsPerHour}
              note="Configured cap. Inference calls aren't individually signed, so usage isn't measurable from the audit log — set + enforced by the host."
            />
            <span className="muted small">
              Set caps in the <strong>Policy</strong> tab.
            </span>
          </section>

          <section className="stat-grid">
            <Stat label="At limit" value={summary.scopesAtLimit} tone={summary.scopesAtLimit > 0 ? "bad" : undefined} />
            <Stat label="Approaching" value={summary.scopesApproaching} tone={summary.scopesApproaching > 0 ? "warn" : undefined} />
            <Stat label="At-limit events" value={summary.atLimitEvents} />
            <Stat label={kindLabel(kind, true)} value={usage.length} />
          </section>

          <div className="toolbar">
            <span className="count">
              {usage.length} {kindLabel(kind, true).toLowerCase()}
            </span>
            <select value={kind} onChange={(e) => setKind(e.target.value as ScopeKind)}>
              <option value="source">By app</option>
              <option value="agent">By agent</option>
              <option value="user">By operator</option>
            </select>
          </div>

          <div className="table-wrap">
            <table className="audit">
              <thead>
                <tr>
                  <th>{kindLabel(kind)}</th>
                  <th>Actions</th>
                  <th>Peak / min</th>
                  <th>Utilization</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {usage.map((u) => (
                  <tr key={u.scope} className={u.status === "at-limit" ? "row-bad" : ""}>
                    <td className="mono strong">{u.scope}</td>
                    <td className="mono">{u.totalActions}</td>
                    <td className="mono">
                      {u.peakPerMinute}
                      {caps.maxActionsPerMinute !== null && (
                        <span className="muted"> / {caps.maxActionsPerMinute}</span>
                      )}
                    </td>
                    <td className="mono">{u.utilizationPct === null ? "—" : `${u.utilizationPct}%`}</td>
                    <td>
                      <StatusBadge status={u.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {events.length > 0 && (
            <>
              <h2 className="section-head">At-limit history</h2>
              <p className="muted small pad">
                Each moment a scope's trailing-minute action count reached the cap — the observable
                proxy for the host throttling it (over-cap actions are stopped before they're signed,
                so they never reach this log).
              </p>
              <div className="table-wrap">
                <table className="audit">
                  <thead>
                    <tr>
                      <th>{kindLabel(kind)}</th>
                      <th>When (UTC)</th>
                      <th>In-window count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.slice(0, 50).map((e, i) => (
                      <tr key={`${e.scope}-${e.ts_ms}-${i}`}>
                        <td className="mono strong">{e.scope}</td>
                        <td className="mono">{new Date(e.ts_ms).toISOString().replace("T", " ").slice(0, 19)}</td>
                        <td className="mono">{e.windowCount}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

function kindLabel(kind: ScopeKind, plural = false): string {
  const m: Record<ScopeKind, [string, string]> = {
    source: ["App", "Apps"],
    agent: ["Agent", "Agents"],
    user: ["Operator", "Operators"],
  };
  return m[kind][plural ? 1 : 0];
}

function CapPill({ label, value, note }: { label: string; value: number | null; note?: string }) {
  return (
    <span className="cap-pill" title={note}>
      <span className="cap-label">{label}</span>
      <span className="cap-value">{value === null ? "uncapped" : value}</span>
    </span>
  );
}

function StatusBadge({ status }: { status: UsageStatus }) {
  if (status === "at-limit") return <span className="badge bad">at limit</span>;
  if (status === "approaching") return <span className="badge warn">approaching</span>;
  return <span className="pill">ok</span>;
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "ok" | "bad" | "warn" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
