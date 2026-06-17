import { useMemo, useState } from "react";
import { Sidebar, type View } from "./components/Sidebar";
import { OverviewView } from "./views/OverviewView";
import { AuditView } from "./views/AuditView";
import { PolicyView } from "./views/PolicyView";
import { loadAuditLog } from "./lib/receipts";
import type { AuditRow } from "./lib/types";
import { defaultPolicy, lintPolicy, type Policy } from "./lib/policy";
import sampleAudit from "./sample/sample-audit.jsonl?raw";

export function App() {
  const [view, setView] = useState<View>("overview");
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [policy, setPolicy] = useState<Policy>(defaultPolicy);
  const [busy, setBusy] = useState(false);

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
        {view === "policy" && (
          <PolicyView policy={policy} onChange={setPolicy} observedActions={observedActions} />
        )}
      </main>
      {busy && <div className="busy">verifying…</div>}
    </div>
  );
}
