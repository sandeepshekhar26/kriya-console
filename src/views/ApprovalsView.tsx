import { useMemo, useState } from "react";
import {
  routeQueue,
  groupBy,
  summarize,
  type DecisionKind,
  type QueueState,
  type RoutedApproval,
} from "../lib/approvals";

type GroupKey = "none" | "source" | "agent";

export function ApprovalsView({
  queue,
  onIngest,
  onDecide,
  onClear,
  onLoadSample,
}: {
  queue: QueueState;
  onIngest: (text: string, source: string) => void;
  onDecide: (id: string, kind: DecisionKind, reason: string) => void;
  onClear: () => void;
  onLoadSample: () => void;
}) {
  const [group, setGroup] = useState<GroupKey>("none");
  // A single "now" per render so wait times + sort are stable within a frame.
  const now = Date.now();
  const routed = useMemo(() => routeQueue(queue.pending, now), [queue.pending, now]);
  const stats = useMemo(() => summarize(queue), [queue]);

  async function onFiles(files: FileList | null) {
    if (!files) return;
    for (const file of Array.from(files)) onIngest(await file.text(), file.name);
  }

  function act(id: string, kind: DecisionKind) {
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
          <button className="btn ghost" onClick={onLoadSample}>
            Load sample
          </button>
          {!empty && (
            <button className="btn ghost" onClick={onClear}>
              Clear
            </button>
          )}
        </div>
      </header>

      {empty ? (
        <div className="empty">
          <div className="empty-glyph">✓</div>
          <p>
            Pending approvals from every app land here. Drop in a{" "}
            <code>pending-approvals.jsonl</code> queue to triage what your agents are waiting to do.
          </p>
          <p className="muted">Decisions stay on this machine, persisted across reloads.</p>
          <button className="btn" onClick={onLoadSample}>
            Load sample queue
          </button>
        </div>
      ) : (
        <>
          <section className="stat-grid">
            <Stat label="Pending" value={stats.pending} />
            <Stat label="High-risk" value={stats.highRiskPending} tone={stats.highRiskPending > 0 ? "bad" : undefined} />
            <Stat label="Approved" value={stats.approved} tone="ok" />
            <Stat label="Denied" value={stats.denied} />
          </section>

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
                            <button className="btn small" onClick={() => act(a.id, "approved")}>
                              Approve
                            </button>
                            <button className="btn small ghost" onClick={() => act(a.id, "denied")}>
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
