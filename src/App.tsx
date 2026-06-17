import { useMemo, useState } from "react";
import { loadAuditLog } from "./lib/receipts";
import type { AuditRow } from "./lib/types";
import { AuditTable } from "./components/AuditTable";
import sampleAudit from "./sample/sample-audit.jsonl?raw";

type StatusFilter = "all" | "verified" | "failed";

export function App() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [source, setSource] = useState("all");
  const [busy, setBusy] = useState(false);

  async function ingest(text: string, src: string) {
    setBusy(true);
    try {
      const next = await loadAuditLog(text, src);
      setRows((prev) => [...prev, ...next]);
    } finally {
      setBusy(false);
    }
  }

  async function onFiles(files: FileList | null) {
    if (!files) return;
    for (const file of Array.from(files)) {
      await ingest(await file.text(), file.name);
    }
  }

  const sources = useMemo(
    () => ["all", ...Array.from(new Set(rows.map((r) => r.source)))],
    [rows],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((r) => {
      if (status === "verified" && !r.outcome.ok) return false;
      if (status === "failed" && r.outcome.ok) return false;
      if (source !== "all" && r.source !== source) return false;
      if (!q) return true;
      const hay = `${r.receipt?.action_id ?? ""} ${r.receipt?.step_id ?? ""} ${r.raw}`.toLowerCase();
      return hay.includes(q);
    });
  }, [rows, query, status, source]);

  const stats = useMemo(() => {
    const verified = rows.filter((r) => r.outcome.ok).length;
    const signers = new Set(rows.map((r) => r.receipt?.public_key).filter(Boolean)).size;
    const apps = new Set(rows.map((r) => r.source)).size;
    return { total: rows.length, verified, failed: rows.length - verified, signers, apps };
  }, [rows]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">▣</span>
          <div>
            <h1>kriya Console</h1>
            <p className="tagline">Governed-agent oversight · signed-audit viewer</p>
          </div>
        </div>
        <div className="actions">
          <label className="btn">
            Load audit log(s)
            <input
              type="file"
              accept=".jsonl,.log,.txt"
              multiple
              hidden
              onChange={(e) => void onFiles(e.target.files)}
            />
          </label>
          <button className="btn ghost" onClick={() => void ingest(sampleAudit, "sample-audit.jsonl")}>
            Load sample
          </button>
          {rows.length > 0 && (
            <button className="btn ghost" onClick={() => setRows([])}>
              Clear
            </button>
          )}
        </div>
      </header>

      <section className="stats">
        <Stat label="Receipts" value={stats.total} />
        <Stat label="Verified" value={stats.verified} tone="ok" />
        <Stat label="Failed / tampered" value={stats.failed} tone={stats.failed ? "bad" : undefined} />
        <Stat label="Apps / sources" value={stats.apps} />
        <Stat label="Distinct signers" value={stats.signers} />
      </section>

      {rows.length === 0 ? (
        <div className="empty">
          <p>
            Drop in one or more <code>kriya-audit.jsonl</code> logs to verify every signed receipt and
            audit what agents did across your apps.
          </p>
          <p className="muted">Signatures are verified locally — no data leaves this machine.</p>
          <button className="btn" onClick={() => void ingest(sampleAudit, "sample-audit.jsonl")}>
            Load sample data
          </button>
        </div>
      ) : (
        <>
          <div className="toolbar">
            <input
              className="search"
              placeholder="Filter by action, step, params…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select value={status} onChange={(e) => setStatus(e.target.value as StatusFilter)}>
              <option value="all">All statuses</option>
              <option value="verified">Verified only</option>
              <option value="failed">Failed only</option>
            </select>
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              {sources.map((s) => (
                <option key={s} value={s}>
                  {s === "all" ? "All sources" : s}
                </option>
              ))}
            </select>
            <span className="count">
              {filtered.length} / {rows.length}
            </span>
          </div>
          <AuditTable rows={filtered} />
        </>
      )}

      {busy && <div className="busy">verifying…</div>}
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
