import type { AuditRow } from "../lib/types";

export function AuditTable({ rows }: { rows: AuditRow[] }) {
  if (rows.length === 0) {
    return <p className="muted pad">No receipts match the current filters.</p>;
  }
  return (
    <div className="table-wrap">
      <table className="audit">
        <thead>
          <tr>
            <th>Status</th>
            <th>Source</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Params</th>
            <th>Result</th>
            <th>When (UTC)</th>
            <th>Signer</th>
            <th>Step</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.source}:${r.lineNo}:${i}`} className={r.outcome.ok ? "" : "row-bad"}>
              <td>
                {r.outcome.ok ? (
                  <span className="badge ok">✓ verified</span>
                ) : (
                  <span className="badge bad" title={r.outcome.reason}>
                    ✗ {truncate(r.outcome.reason, 20)}
                  </span>
                )}
              </td>
              <td className="mono">{r.source}</td>
              <td className="mono" title={r.receipt?.actor ? `${r.receipt.actor.agent} / ${r.receipt.actor.user}` : undefined}>
                {r.receipt?.actor ? (
                  <>
                    {r.receipt.actor.agent}
                    <span className="muted"> / {r.receipt.actor.user}</span>
                  </>
                ) : (
                  "—"
                )}
              </td>
              <td className="mono strong">{r.receipt?.action_id ?? "—"}</td>
              <td className="mono params" title={r.receipt ? JSON.stringify(r.receipt.params) : undefined}>
                {r.receipt ? truncate(JSON.stringify(r.receipt.params), 48) : "—"}
              </td>
              <td>
                {r.receipt ? (
                  <span className={r.receipt.success ? "pill" : "pill warn"}>
                    {r.receipt.success ? "ok" : "failed"}
                  </span>
                ) : (
                  "—"
                )}
              </td>
              <td className="mono">{r.receipt ? formatTs(r.receipt.ts_ms) : "—"}</td>
              <td className="mono" title={r.receipt?.public_key}>
                {r.receipt ? r.receipt.public_key.slice(0, 10) : "—"}
              </td>
              <td className="mono" title={r.receipt?.step_id}>
                {r.receipt ? r.receipt.step_id.slice(0, 8) : `line ${r.lineNo}`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatTs(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return String(ms);
  return d.toISOString().replace("T", " ").slice(0, 19);
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
