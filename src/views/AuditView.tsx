import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import { AuditTable } from "../components/AuditTable";

type StatusFilter = "all" | "verified" | "failed";

export function AuditView({
  rows,
  onIngest,
  onClear,
  onLoadSample,
}: {
  rows: AuditRow[];
  onIngest: (text: string, source: string) => Promise<void>;
  onClear: () => void;
  onLoadSample: () => void;
}) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [source, setSource] = useState("all");

  async function onFiles(files: FileList | null) {
    if (!files) return;
    for (const file of Array.from(files)) {
      await onIngest(await file.text(), file.name);
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

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="page-sub">
            Every signed receipt, verified locally against its embedded key. Tampered or forged rows
            fail verification.
          </p>
        </div>
        <div className="page-actions">
          <label className="btn">
            Load log(s)
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
          {rows.length > 0 && (
            <button className="btn ghost" onClick={onClear}>
              Clear
            </button>
          )}
        </div>
      </header>

      {rows.length === 0 ? (
        <div className="empty">
          <div className="empty-glyph">▤</div>
          <p>
            Drop in one or more <code>kriya-audit.jsonl</code> logs to verify every signed receipt and
            audit what agents did across your apps.
          </p>
          <p className="muted">Signatures are verified locally — no data leaves this machine.</p>
          <button className="btn" onClick={onLoadSample}>
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
    </div>
  );
}
