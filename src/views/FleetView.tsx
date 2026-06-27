import { useEffect, useState } from "react";
import { fleetCorrelation, type FleetReport } from "../lib/tauri";
import { Icon } from "../components/Icon";

function FleetHead() {
  return (
    <header className="page-head">
      <div>
        <h1>Fleet</h1>
        <p className="page-sub">
          Cross-machine, cross-app correlation of the signed audit trail — generated on-device in
          compiled Rust.
        </p>
      </div>
    </header>
  );
}

/**
 * Fleet correlation (paid, D-018): cross-machine / cross-app rollup of the signed trail, computed in
 * the compiled backend. Groups every receipt by signer (≈ host) and by app, surfaces distinct
 * agents/operators, and flags any log whose hash-chain is broken — the integrity view a single-app
 * viewer can't give you. Only mounted when licensed; the backend re-checks the license anyway.
 */
export function FleetView() {
  const [report, setReport] = useState<FleetReport | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fleetCorrelation().then(setReport).catch((e) => setErr(String(e)));
  }, []);

  if (err) {
    return (
      <div className="view">
        <FleetHead />
        <div className="empty">
          <div className="empty-ico"><Icon name="shield-x" size={22} /></div>
          <p className="empty-title">Couldn’t correlate the trail</p>
          <p className="warn-text">{err}</p>
        </div>
      </div>
    );
  }
  if (!report) {
    return (
      <div className="view">
        <FleetHead />
        <div className="empty">
          <div className="empty-ico"><Icon name="fleet" size={22} /></div>
          <p className="empty-title">Correlating the signed trail…</p>
          <p>Grouping every receipt by signer and app, on-device.</p>
        </div>
      </div>
    );
  }

  const span =
    report.firstMs > 0 && report.lastMs > 0
      ? `${new Date(report.firstMs).toLocaleString()} → ${new Date(report.lastMs).toLocaleString()}`
      : "—";

  return (
    <div className="view">
      <FleetHead />

      <section className="stat-grid">
        <Stat label="Receipts" value={report.totalReceipts} />
        <Stat label="Verified" value={report.verified} tone="ok" />
        <Stat label="Failed / forged" value={report.failed} tone={report.failed ? "bad" : undefined} />
        <Stat label="Signers (≈ hosts)" value={report.distinctSigners} />
        <Stat label="Apps" value={report.distinctApps} />
        <Stat label="Agents" value={report.distinctAgents} />
      </section>

      {report.tamperSignals.length > 0 && (
        <section className="panel bad-panel">
          <h2><Icon name="alert" size={16} /> Integrity alerts</h2>
          {report.tamperSignals.map((t) => (
            <p key={t} className="warn-text small">
              {t}
            </p>
          ))}
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>Signers</h2>
          <span className="muted small">{span}</span>
        </div>
        <table className="audit">
          <thead>
            <tr>
              <th>Fingerprint</th>
              <th>Receipts</th>
              <th>Verified</th>
              <th>Apps</th>
              <th>Agents</th>
              <th>Operators</th>
            </tr>
          </thead>
          <tbody>
            {report.signers.map((s) => (
              <tr key={s.fingerprint}>
                <td>
                  <code>{s.fingerprint}…</code>
                </td>
                <td>{s.receipts}</td>
                <td className={s.failed > 0 ? "warn-text" : "ok-text"}>
                  {s.verified}/{s.receipts}
                </td>
                <td>{s.apps.join(", ") || "—"}</td>
                <td>{s.agents.join(", ") || "—"}</td>
                <td>{s.operators.join(", ") || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Apps</h2>
          <span className="muted small">{report.onDeviceAttestations} on-device attestation(s)</span>
        </div>
        <table className="audit">
          <thead>
            <tr>
              <th>App / source</th>
              <th>Receipts</th>
              <th>Verified</th>
              <th>Destructive</th>
              <th>Chain</th>
            </tr>
          </thead>
          <tbody>
            {report.apps.map((a) => (
              <tr key={a.app}>
                <td>{a.app}</td>
                <td>{a.receipts}</td>
                <td>{a.verified}</td>
                <td>{a.destructive}</td>
                <td>
                  {a.chainBreakLine == null ? (
                    <span className="ok-text">intact</span>
                  ) : (
                    <span className="warn-text">break @ {a.chainBreakLine}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
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
