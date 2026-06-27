import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import { AuditTable } from "../components/AuditTable";
import { Icon } from "../components/Icon";
import type { View } from "../components/Sidebar";

type StatusFilter = "all" | "verified" | "failed";

export function AuditView({
  rows,
  onIngest,
  onClear,
  onNavigate,
  live,
}: {
  rows: AuditRow[];
  onIngest: (text: string, source: string) => Promise<void>;
  onClear: () => void;
  onNavigate: (v: View) => void;
  /** In the desktop app: the audit dir being tailed. The log auto-appears; import is demoted. */
  live?: string;
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
          {live && (
            <span className="live-pill" title={live}>
              <span className="dot live" /> Live · {live}
            </span>
          )}
          <label className="btn ghost">
            <Icon name="folder" size={14} /> Open a file…
            <input
              type="file"
              accept=".jsonl,.log,.txt"
              multiple
              hidden
              onChange={(e) => void onFiles(e.target.files)}
            />
          </label>
          {rows.length > 0 && (
            <button className="btn ghost" onClick={onClear}>
              Clear
            </button>
          )}
        </div>
      </header>

      {rows.length === 0 ? (
        <div className="empty">
          <div className="empty-ico"><Icon name="list" size={22} /></div>
          {live ? (
            <>
              <p className="empty-title">Watching for signed receipts</p>
              <p>
                Tailing <code>{live}</code>. Drive a governed app and receipts appear here live — every
                one verified in compiled Rust against its embedded key. Nothing leaves this machine.
              </p>
            </>
          ) : (
            <>
              <p className="empty-title">No receipts loaded</p>
              <p>
                Open a signed <code>kriya-audit.jsonl</code> trail to verify it, or connect a governed
                app to capture one live. Signatures are verified locally — nothing leaves this machine.
              </p>
              <div className="page-actions">
                <button className="btn primary" onClick={() => onNavigate("connections")}>Add a connection</button>
              </div>
            </>
          )}
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
