import { useMemo, useState } from "react";
import {
  routeQueue,
  groupBy,
  summarize,
  type DecisionKind,
  type QueueState,
  type RoutedApproval,
} from "../lib/approvals";
import { can, roleOf, type RbacModel } from "../lib/identity";
import { Icon } from "../components/Icon";
import type { View } from "../components/Sidebar";

type GroupKey = "none" | "source" | "agent";

export function ApprovalsView({
  queue,
  onIngest,
  onDecide,
  onClear,
  rbac,
  actingOperator,
  onActingOperatorChange,
  operators,
  onNavigate,
}: {
  queue: QueueState;
  onIngest: (text: string, source: string) => void;
  onDecide: (id: string, kind: DecisionKind, reason: string) => void;
  onClear: () => void;
  rbac: RbacModel;
  actingOperator: string;
  onActingOperatorChange: (op: string) => void;
  operators: string[];
  onNavigate: (v: View) => void;
}) {
  const [group, setGroup] = useState<GroupKey>("none");
  // RBAC gate (R8): only an `approve`-capable role may decide. Self-asserted operator here — real
  // sign-in (SSO/OIDC) is the enterprise-gated, hosted-tier item on the roadmap.
  const role = roleOf(rbac, actingOperator);
  const canApprove = can(rbac, actingOperator, "approve");
  // A single "now" per render so wait times + sort are stable within a frame.
  const now = Date.now();
  const routed = useMemo(() => routeQueue(queue.pending, now), [queue.pending, now]);
  const stats = useMemo(() => summarize(queue), [queue]);

  async function onFiles(files: FileList | null) {
    if (!files) return;
    for (const file of Array.from(files)) onIngest(await file.text(), file.name);
  }

  function act(id: string, kind: DecisionKind) {
    if (!canApprove) return; // RBAC gate — the buttons are disabled, but defend in code too.
    // A reason is mandatory on deny (it lands in the audit trail); optional on approve.
    const reason =
      kind === "denied"
        ? (window.prompt("Reason for denial (recorded in the trail):") ?? "").trim()
        : (window.prompt("Optional note for approval:") ?? "").trim();
    if (kind === "denied" && reason === "") return; // denial without a reason is cancelled
    onDecide(id, kind, reason);
  }

  const groups: [string, RoutedApproval[]][] =
    group === "none" ? [["", routed]] : [...groupBy(routed, group).entries()].sort();

  const empty = queue.pending.length === 0 && queue.decided.length === 0;

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Approval routing</h1>
          <p className="page-sub">
            One queue for every guarded action your agents propose, across apps. High-risk first;
            approve or deny with a reason that lands in the audit trail.
          </p>
        </div>
        <div className="page-actions">
          <label className="btn">
            Load queue(s)
            <input
              type="file"
              accept=".jsonl,.log,.txt"
              multiple
              hidden
              onChange={(e) => void onFiles(e.target.files)}
            />
          </label>
          {!empty && (
            <button className="btn ghost" onClick={onClear}>
              Clear
            </button>
          )}
        </div>
      </header>

      {empty ? (
        <div className="empty">
          <div className="empty-ico"><Icon name="approvals" size={22} /></div>
          <p className="empty-title">Queue clear</p>
          <p>
            Pending approvals from every governed app land here, risk-ranked. Import a{" "}
            <code>pending-approvals.jsonl</code> queue to triage what your agents are waiting to do —
            decisions stay on this machine.
          </p>
          <div className="page-actions">
            <label className="btn primary">
              Load queue(s)
              <input
                type="file"
                accept=".jsonl,.log,.txt"
                multiple
                hidden
                onChange={(e) => void onFiles(e.target.files)}
              />
            </label>
          </div>
        </div>
      ) : (
        <>
          <section className="stat-grid">
            <Stat label="Pending" value={stats.pending} />
            <Stat label="High-risk" value={stats.highRiskPending} tone={stats.highRiskPending > 0 ? "bad" : undefined} />
            <Stat label="Approved" value={stats.approved} tone="ok" />
            <Stat label="Denied" value={stats.denied} />
          </section>

          <div className="acting-bar">
            <span className="muted small">Acting as</span>
            <select value={actingOperator} onChange={(e) => onActingOperatorChange(e.target.value)}>
              {operators.map((op) => (
                <option key={op} value={op}>
                  {op}
                </option>
              ))}
            </select>
            <span className="badge">{role}</span>
            {canApprove ? (
              <span className="muted small">can decide approvals</span>
            ) : (
              <span className="warn small">
                this role can’t decide — grant an approver/admin role in{" "}
                <button className="link" onClick={() => onNavigate("identity")}>Identity &amp; access</button>
              </span>
            )}
          </div>

          <div className="toolbar">
            <span className="count">{routed.length} pending</span>
            <select value={group} onChange={(e) => setGroup(e.target.value as GroupKey)}>
              <option value="none">No grouping</option>
              <option value="source">Group by app</option>
              <option value="agent">Group by agent</option>
            </select>
          </div>

          {routed.length === 0 ? (
            <p className="muted pad">Queue clear — nothing waiting for a human.</p>
          ) : (
            groups.map(([key, items]) => (
              <div key={key || "all"}>
                {key && <div className="group-head mono">{key}</div>}
                <div className="table-wrap">
                  <table className="audit">
                    <thead>
                      <tr>
                        <th>Risk</th>
                        <th>App</th>
                        <th>Actor</th>
                        <th>Action</th>
                        <th>Reasoning</th>
                        <th>Waiting</th>
                        <th>Decision</th>
                      </tr>
                    </thead>
                    <tbody>
                      {items.map((a) => (
                        <tr key={a.id} className={a.risk === "high" ? "row-bad" : ""}>
                          <td>
                            <span className={a.risk === "high" ? "badge bad" : "pill"}>{a.risk}</span>
                          </td>
                          <td className="mono">{a.source}</td>
                          <td className="mono" title={a.actor ? `${a.actor.agent} / ${a.actor.user}` : undefined}>
                            {a.actor ? (
                              <>
                                {a.actor.agent}
                                <span className="muted"> / {a.actor.user}</span>
                              </>
                            ) : (
                              "—"
                            )}
                          </td>
                          <td className="mono strong" title={JSON.stringify(a.params)}>
                            {a.action_id}
                          </td>
                          <td className="params" title={a.reasoning}>
                            {a.reasoning || "—"}
                          </td>
                          <td className="mono">{fmtWait(a.waitingSeconds)}</td>
                          <td className="decide-cell">
                            <button
                              className="btn small"
                              disabled={!canApprove}
                              title={canApprove ? undefined : `${role} role can't decide approvals`}
                              onClick={() => act(a.id, "approved")}
                            >
                              Approve
                            </button>
                            <button
                              className="btn small ghost"
                              disabled={!canApprove}
                              title={canApprove ? undefined : `${role} role can't decide approvals`}
                              onClick={() => act(a.id, "denied")}
                            >
                              Deny
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))
          )}

          {queue.decided.length > 0 && (
            <>
              <h2 className="section-head">Decision history</h2>
              <div className="table-wrap">
                <table className="audit">
                  <thead>
                    <tr>
                      <th>Decision</th>
                      <th>App</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Reason</th>
                      <th>By</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...queue.decided].reverse().map((d) => (
                      <tr key={d.id}>
                        <td>
                          <span className={d.decision === "approved" ? "badge ok" : "badge bad"}>
                            {d.decision}
                          </span>
                        </td>
                        <td className="mono">{d.source}</td>
                        <td className="mono">{d.actor ? `${d.actor.agent} / ${d.actor.user}` : "—"}</td>
                        <td className="mono strong">{d.action_id}</td>
                        <td className="params" title={d.reason}>
                          {d.reason || "—"}
                        </td>
                        <td className="mono">{d.decidedBy}</td>
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

function Stat({ label, value, tone }: { label: string; value: number; tone?: "ok" | "bad" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function fmtWait(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}
