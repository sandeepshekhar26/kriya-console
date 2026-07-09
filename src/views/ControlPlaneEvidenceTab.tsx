import { useState } from "react";
import { Icon } from "../components/Icon";
import { fleetOrgEvidence, type OrgControlStatus, type OrgEvidence } from "../lib/tauri";

const STATUS_CLASS: Record<OrgControlStatus, string> = { satisfied: "ok", partial: "warn", gap: "bad" };
const STATUS_ICON: Record<OrgControlStatus, string> = { satisfied: "✓", partial: "◐", gap: "✗" };

function download(name: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

/**
 * Org evidence (P5, doc 22 §9) — the fleet-wide, assessor-ready export the per-device Evidence view
 * (`ReportsView`/`exportCompliance`) cannot produce, because kriyad only ever stores signed envelope
 * rollups, never raw receipts (doc 22 §11-B1). Self-contained: by the time this tab renders, the
 * top-level `fleet-console` gate has already passed (same convention as `ControlPlanePolicyTab`).
 */
export function ControlPlaneEvidenceTab() {
  const [org, setOrg] = useState("");
  const [windowDays, setWindowDays] = useState("90");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<OrgEvidence | null>(null);

  async function generate() {
    setBusy(true);
    setErr(null);
    try {
      const days = Number(windowDays.trim());
      const windowMs = Number.isFinite(days) && days > 0 ? days * 24 * 60 * 60 * 1000 : NINETY_DAYS_MS;
      const e = await fleetOrgEvidence(org.trim() || "Fleet", windowMs);
      setEvidence(e);
      download("kriya-fleet-evidence.md", e.markdown, "text/markdown");
      download("kriya-fleet-evidence.json", e.json, "application/json");
    } catch (ex) {
      setErr(String(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <header className="panel-head">
        <h2><Icon name="evidence" size={15} /> Org evidence</h2>
        <p className="muted small">
          Fleet-wide coverage-completeness, AU-family, and configuration-management evidence — computed
          from every device's OWN locally re-verified signed envelopes, never kriyad's serving hints.
          Streamed device-by-device; a device's full history is never held in memory at once.
        </p>
      </header>

      <div className="form-row">
        <label>
          Organization
          <input value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Your organization" />
        </label>
        <label>
          Window (days)
          <input value={windowDays} onChange={(e) => setWindowDays(e.target.value)} style={{ width: 80 }} />
        </label>
        <button className="btn primary" disabled={busy} onClick={() => void generate()}>
          <Icon name="refresh" size={13} /> {busy ? "Generating…" : "Generate & save"}
        </button>
      </div>

      {err && (
        <p className="muted small" style={{ color: "var(--bad-text)" }}>
          {err}
        </p>
      )}

      {evidence && (
        <>
          <section className="stat-grid cp-stats" style={{ marginTop: 16 }}>
            <Stat label="Devices" value={evidence.devicesTotal} />
            <Stat label="Current" value={evidence.devicesCurrent} tone="ok" />
            <Stat label="Behind" value={evidence.devicesBehind} tone={evidence.devicesBehind ? "warn" : undefined} />
            <Stat label="Silent" value={evidence.devicesSilent} tone={evidence.devicesSilent ? "bad" : undefined} />
          </section>

          <p className="muted small" style={{ marginTop: 8 }}>
            Baseline: {evidence.latestBundleVersion != null ? `bundle v${evidence.latestBundleVersion}` : "none published"}
            {" · "}
            Drift exceptions: {evidence.drift.length === 0 ? "none" : evidence.drift.join("; ")}
          </p>

          <table className="tbl" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Framework</th>
                <th>Control</th>
                <th>Status</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {evidence.controls.map((c) => (
                <tr key={`${c.framework}-${c.control}`}>
                  <td>{c.framework}</td>
                  <td>{c.control}</td>
                  <td className={STATUS_CLASS[c.status]}>
                    {STATUS_ICON[c.status]} {c.status}
                  </td>
                  <td className="muted small">{c.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <p className="muted small" style={{ marginTop: 8, fontStyle: "italic" }}>
            Status: ✓ satisfied · ◐ partial · ✗ gap. This report is evidence, not a certification.
          </p>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "ok" | "warn" | "bad" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
