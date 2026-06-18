import { useEffect, useMemo, useState } from "react";
import { Sidebar, type View } from "./components/Sidebar";
import { OverviewView } from "./views/OverviewView";
import { AuditView } from "./views/AuditView";
import { PolicyView } from "./views/PolicyView";
import { ApprovalsView } from "./views/ApprovalsView";
import { loadAuditLog } from "./lib/receipts";
import type { AuditRow } from "./lib/types";
import { defaultPolicy, lintPolicy, type Policy } from "./lib/policy";
import {
  decide,
  ingestPending,
  parsePendingApprovals,
  summarize,
  type DecisionKind,
  type QueueState,
} from "./lib/approvals";
import sampleAudit from "./sample/sample-audit.jsonl?raw";
import sampleApprovals from "./sample/sample-approvals.jsonl?raw";

const QUEUE_KEY = "kriya-console:approvals";
const OPERATOR = "console-operator";

function loadQueue(): QueueState {
  try {
    const raw = localStorage.getItem(QUEUE_KEY);
    if (raw) return JSON.parse(raw) as QueueState;
  } catch {
    /* corrupt or unavailable storage → start empty */
  }
  return { pending: [], decided: [] };
}

export function App() {
  const [view, setView] = useState<View>("overview");
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [policy, setPolicy] = useState<Policy>(defaultPolicy);
  const [busy, setBusy] = useState(false);
  const [queue, setQueue] = useState<QueueState>(loadQueue);

  // Persist the approval queue so decisions + pending items survive a reload (R6 inc 3).
  useEffect(() => {
    try {
      localStorage.setItem(QUEUE_KEY, JSON.stringify(queue));
    } catch {
      /* storage full/unavailable — non-fatal */
    }
  }, [queue]);

  async function ingest(text: string, source: string) {
    setBusy(true);
    try {
      const next = await loadAuditLog(text, source);
      setRows((prev) => [...prev, ...next]);
    } finally {
      setBusy(false);
    }
  }

  const loadSample = () => void ingest(sampleAudit, "sample-audit.jsonl");

  function ingestApprovals(text: string, source: string) {
    setQueue((q) => ingestPending(q, parsePendingApprovals(text, source)));
  }
  function decideApproval(id: string, kind: DecisionKind, reason: string) {
    setQueue((q) => decide(q, id, kind, reason, OPERATOR, Date.now()));
  }
  const loadSampleApprovals = () => ingestApprovals(sampleApprovals, "sample-approvals.jsonl");
  const queueStats = useMemo(() => summarize(queue), [queue]);

  // distinct action ids seen in verified receipts — feeds policy coverage + suggestions
  const observedActions = useMemo(() => {
    const set = new Set<string>();
    for (const r of rows) if (r.receipt) set.add(r.receipt.action_id);
    return Array.from(set).sort();
  }, [rows]);

  const verified = rows.filter((r) => r.outcome.ok).length;
  const warningCount = useMemo(() => lintPolicy(policy).length, [policy]);

  return (
    <div className="shell">
      <Sidebar
        view={view}
        onNavigate={setView}
        receiptCount={rows.length}
        failedCount={rows.length - verified}
        warningCount={warningCount}
        pendingApprovals={queueStats.pending}
        highRiskApprovals={queueStats.highRiskPending}
      />
      <main className="main">
        {view === "overview" && (
          <OverviewView
            rows={rows}
            policy={policy}
            observedActions={observedActions}
            onNavigate={setView}
            onLoadSample={loadSample}
          />
        )}
        {view === "audit" && (
          <AuditView rows={rows} onIngest={ingest} onClear={() => setRows([])} onLoadSample={loadSample} />
        )}
        {view === "approvals" && (
          <ApprovalsView
            queue={queue}
            onIngest={ingestApprovals}
            onDecide={decideApproval}
            onClear={() => setQueue({ pending: [], decided: [] })}
            onLoadSample={loadSampleApprovals}
          />
        )}
        {view === "policy" && (
          <PolicyView policy={policy} onChange={setPolicy} observedActions={observedActions} />
        )}
      </main>
      {busy && <div className="busy">verifying…</div>}
    </div>
  );
}
