import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import { Icon } from "../components/Icon";
import type { View } from "../components/Sidebar";
import { buildSessionTrees, type RunAction, type RunTree } from "../lib/sessionTree";

/**
 * Sessions (S3 run correlation) — the drill-down that groups a run's actions into a tree from the
 * signed `kriya.corr` receipts: run → sub-agents / nested calls → actions. Computed from VERIFIED
 * receipts only (a failed-verification row's correlation is untrusted bytes). This is the substrate
 * doc 26's I2 kill-chain graph and I5 session ABOM extend.
 */
export function SessionsView({
  rows,
  onNavigate,
}: {
  rows: AuditRow[];
  onNavigate: (v: View) => void;
}) {
  const trees = useMemo(() => buildSessionTrees(rows), [rows]);
  // `undefined` = "not yet chosen" → the most-recent run opens by default (and stays collapsible).
  const [openRun, setOpenRun] = useState<string | null | undefined>(undefined);
  const effectiveOpen = openRun === undefined ? (trees[0]?.runId ?? null) : openRun;

  if (trees.length === 0) {
    return (
      <div className="view">
        <header className="page-head">
          <div>
            <h1>Sessions</h1>
            <p className="page-sub">
              Every governed run, reconstructed as a tree from the signed receipts — which session,
              which sub-agent, which action, in order.
            </p>
          </div>
        </header>
        <div className="empty">
          <div className="empty-ico"><Icon name="folder" size={22} /></div>
          <p className="empty-title">No correlated sessions yet</p>
          <p>
            Governed agents stamp a <strong>run id</strong> (and, for Claude Code, a sub-agent id) into
            each signed receipt. Once a governed agent runs, its actions group into a session tree here
            — verified on-device, never from unverified bytes.
          </p>
          <div className="page-actions">
            <button className="btn primary" onClick={() => onNavigate("connections")}>Govern an agent</button>
          </div>
        </div>
      </div>
    );
  }

  const totalActions = trees.reduce((n, t) => n + t.actionCount, 0);

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Sessions</h1>
          <p className="page-sub">
            {trees.length} correlated run{trees.length === 1 ? "" : "s"} · {totalActions} action
            {totalActions === 1 ? "" : "s"} — reconstructed from verified <code>kriya.corr</code>{" "}
            receipts. Approval decisions live in the Approvals queue.
          </p>
        </div>
      </header>

      <div className="session-list">
        {trees.map((t) => (
          <RunCard
            key={t.runId}
            run={t}
            open={effectiveOpen === t.runId}
            onToggle={() => setOpenRun((cur) => ((cur ?? trees[0]?.runId) === t.runId ? null : t.runId))}
          />
        ))}
      </div>
    </div>
  );
}

function RunCard({ run, open, onToggle }: { run: RunTree; open: boolean; onToggle: () => void }) {
  return (
    <section className="run-card">
      <button className="run-head" onClick={onToggle} aria-expanded={open}>
        <Icon name={open ? "chevron-down" : "chevron-right"} size={14} />
        <span className="mono strong run-id" title={run.runId}>{run.runId}</span>
        <span className="run-stats">
          <span className="pill">{run.actionCount} action{run.actionCount === 1 ? "" : "s"}</span>
          {run.subAgents.length > 0 && (
            <span className="pill">{run.subAgents.length} sub-agent{run.subAgents.length === 1 ? "" : "s"}</span>
          )}
          {run.spawnCount > 0 && <span className="pill">{run.spawnCount} spawn{run.spawnCount === 1 ? "" : "s"}</span>}
          {run.blockedCount > 0 && <span className="pill bad">{run.blockedCount} blocked</span>}
          {run.orphanCount > 0 && <span className="pill warn">{run.orphanCount} orphan{run.orphanCount === 1 ? "" : "s"}</span>}
        </span>
        <span className="muted small run-time">{fmtTs(run.firstTs)} → {fmtTs(run.lastTs)}</span>
      </button>

      {open && (
        <div className="run-body">
          {run.subAgents.length > 0 && (
            <div className="subagent-row">
              <span className="muted small">Sub-agents:</span>
              {run.subAgents.map((s) => (
                <span key={s.agentId} className="badge" title={`${s.actions} action(s)`}>
                  {s.agentId} · {s.actions}
                </span>
              ))}
            </div>
          )}
          <ul className="action-tree">
            {run.roots.map((a) => (
              <ActionNode key={a.stepId} node={a} depth={0} />
            ))}
          </ul>
          <p className="muted small pad">
            Sources: {run.sources.join(", ")}. Nesting is by signed lineage (<code>parent_step_id</code>);
            Claude Code groups by <code>agent_id</code> (no parent pointer in its hook payload).
          </p>
        </div>
      )}
    </section>
  );
}

function ActionNode({ node, depth }: { node: RunAction; depth: number }) {
  return (
    <li className="action-node" style={{ marginLeft: depth === 0 ? 0 : 16 }}>
      <div className="action-line">
        <span className={`dot ${node.success ? "ok" : "bad"}`} aria-hidden />
        <span className="mono action-id">{node.actionId}</span>
        {node.isSpawn && <span className="badge">spawn</span>}
        {node.agentId && <span className="badge subtle" title="sub-agent">{node.agentId}</span>}
        {node.orphaned && <span className="badge warn" title="parent step not found in this run">orphan</span>}
        {!node.success && <span className="badge bad">blocked</span>}
        <span className="muted small action-time">{fmtTs(node.ts)}</span>
      </div>
      {node.children.length > 0 && (
        <ul className="action-tree">
          {node.children.map((c) => (
            <ActionNode key={c.stepId} node={c} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

function fmtTs(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}
