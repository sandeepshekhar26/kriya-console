import { useState } from "react";
import { Icon } from "../components/Icon";
import {
  consoleDrilldown,
  fleetDeviceUnlistedEgressCount,
  fleetOrgEvidence,
  type OrgControlStatus,
  type OrgEvidence,
} from "../lib/tauri";

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
  const [revealed, setRevealed] = useState<Record<string, [number, number] | "loading" | "error">>({});

  async function reveal(devicePub: string) {
    setRevealed((r) => ({ ...r, [devicePub]: "loading" }));
    try {
      // The receipted act of looking happens FIRST — "the surveillance is itself audited" (doc 24
      // §7.5/§6-P9) — then the actual number is fetched.
      await consoleDrilldown(devicePub, "egress-unlisted-count");
      const [count, denied] = await fleetDeviceUnlistedEgressCount(devicePub);
      setRevealed((r) => ({ ...r, [devicePub]: [count, denied] }));
    } catch {
      setRevealed((r) => ({ ...r, [devicePub]: "error" }));
    }
  }

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

          <h3 style={{ marginTop: 20, marginBottom: 4 }}>Fleet egress receipts (kriya.io.*)</h3>
          <p className="muted small">
            Counts-only, envelope-native (doc 24 §4.5) — {evidence.egressTotals.verifiedReceipts.toLocaleString()}{" "}
            verified · {evidence.egressTotals.allow.toLocaleString()} allow ·{" "}
            {evidence.egressTotals.deny.toLocaleString()} deny · {evidence.egressTotals.approve.toLocaleString()} approve
            fleet-wide. A device's own destination host never leaves that device.
          </p>
          <table className="tbl" style={{ marginTop: 8 }}>
            <thead>
              <tr>
                <th>Device</th>
                <th>Verified</th>
                <th>Allow</th>
                <th>Deny</th>
                <th>Approve</th>
              </tr>
            </thead>
            <tbody>
              {evidence.egressReceipts.map((r) => (
                <tr key={r.devicePub}>
                  <td>{r.deviceLabel || r.devicePub.slice(0, 12) + "…"}</td>
                  <td>{r.verifiedReceipts.toLocaleString()}</td>
                  <td>{r.allow.toLocaleString()}</td>
                  <td className={r.deny > 0 ? "warn" : undefined}>{r.deny.toLocaleString()}</td>
                  <td>{r.approve.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {evidence.egressPatterns.some((d) => d.patternEchoActive) && (
            <>
              <h3 style={{ marginTop: 20, marginBottom: 4 }}>Fleet destination patterns (pattern-echo)</h3>
              {evidence.purposeStatement && (
                <p className="muted small">
                  <strong>Purpose:</strong> {evidence.purposeStatement}
                </p>
              )}
              <p className="muted small">
                Pattern-echo (doc 24 §4.5/§7.5): each pattern is an operator-AUTHORED string from the
                signed policy bundle — never a raw observed host. A pattern flagged ⚠ matched fewer
                than a handful of devices fleet-wide (a possible surveillance-shaped signal). Small
                unlisted counts are withheld by default; revealing one signs a
                `kriya.console.drilldown` receipt.
              </p>
              <table className="tbl" style={{ marginTop: 8 }}>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Patterns (count / denied)</th>
                    <th>Unlisted attempts</th>
                  </tr>
                </thead>
                <tbody>
                  {evidence.egressPatterns
                    .filter((d) => d.patternEchoActive)
                    .map((d) => {
                      const rev = revealed[d.devicePub];
                      return (
                        <tr key={d.devicePub}>
                          <td>{d.deviceLabel || d.devicePub.slice(0, 12) + "…"}</td>
                          <td>
                            {d.patterns.length === 0
                              ? "none"
                              : d.patterns.map((p, i) => (
                                  <span key={p.pattern}>
                                    {i > 0 && ", "}
                                    <span className={p.fewDevicePattern ? "warn" : undefined}>
                                      {p.pattern}
                                      {p.fewDevicePattern ? " ⚠" : ""} ({p.count}/{p.denied})
                                    </span>
                                  </span>
                                ))}
                          </td>
                          <td>
                            {d.unlistedCount != null ? (
                              d.unlistedCount
                            ) : rev === "loading" ? (
                              "revealing…"
                            ) : rev === "error" ? (
                              <span className="warn-text">reveal failed</span>
                            ) : Array.isArray(rev) ? (
                              `${rev[0]} (${rev[1]} denied) — revealed`
                            ) : (
                              <>
                                <span className="muted small">withheld</span>{" "}
                                <button className="btn small" onClick={() => void reveal(d.devicePub)}>
                                  Reveal
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </>
          )}

          <table className="tbl" style={{ marginTop: 20 }}>
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
