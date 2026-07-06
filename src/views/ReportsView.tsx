import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import type { Policy } from "../lib/policy";
import { buildEvidence, renderJson, renderMarkdown, type ControlStatus } from "../lib/compliance";
import { exportCompliance, isTauri } from "../lib/tauri";
import { Icon, type IconName } from "../components/Icon";
import type { View } from "../components/Sidebar";

const REPORTS: { key: string; js: string; title: string; scope: string; icon: IconName }[] = [
  { key: "NIST-800-171", js: "NIST 800-171", title: "NIST 800-171 (CMMC L2)", scope: "Audit & accountability — AU family 3.3.1–3.3.9", icon: "shield-check" },
  { key: "EU-AI-Act", js: "EU AI Act", title: "EU AI Act", scope: "Record-keeping, human oversight & traceability — Art. 12–14", icon: "evidence" },
  { key: "SOC2", js: "SOC 2", title: "SOC 2", scope: "Security monitoring & tamper detection — CC7.2", icon: "shield-check" },
  { key: "ISO42001", js: "ISO 42001", title: "ISO 42001", scope: "AI operation controls — A.9", icon: "policy" },
];

const STATUS_CLASS: Record<ControlStatus, string> = { satisfied: "ok", partial: "warn", gap: "bad" };

/**
 * Evidence — the report builder. Configure scope (org), pick a framework, and generate an
 * auditor-ready bundle on-device (compiled Rust when in the desktop app). The cryptographic story —
 * signed, re-verified, attributed — is the deliverable.
 */
export function ReportsView({
  rows,
  policy,
  onNavigate,
}: {
  rows: AuditRow[];
  policy: Policy;
  onNavigate: (v: View) => void;
}) {
  const [org, setOrg] = useState("");
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [gen, setGen] = useState<Record<string, number>>({});
  const [note, setNote] = useState<string | null>(null);

  const bundle = useMemo(
    () => buildEvidence(rows, policy, { generatedAt: Date.now(), organization: org }),
    [rows, policy, org],
  );

  function coverage(jsFw: string) {
    const controls = bundle.controls.filter((c) => c.framework === jsFw);
    return { total: controls.length, satisfied: controls.filter((c) => c.status === "satisfied").length };
  }

  async function generate(key: string, title: string) {
    setBusyKey(key);
    setNote(null);
    try {
      if (isTauri()) {
        const b = await exportCompliance(key);
        download(`kriya-${key}-evidence.md`, b.markdown, "text/markdown");
        download(`kriya-${key}-evidence.json`, b.json, "application/json");
        setNote(`${title}: generated on-device from ${b.totalReceipts} receipt(s) — ${b.verified} verified, integrity ${b.integrityOk ? "intact" : "BROKEN"}.`);
      } else {
        download(`kriya-${key}-evidence.md`, renderMarkdown(bundle), "text/markdown");
        download(`kriya-${key}-evidence.json`, renderJson(bundle), "application/json");
        setNote(`${title}: exported ${bundle.integrity.verified} verified receipt(s) (browser preview — the desktop app generates a per-framework bundle in compiled Rust).`);
      }
      setGen((g) => ({ ...g, [key]: Date.now() }));
    } catch (e) {
      setNote(String(e));
    } finally {
      setBusyKey(null);
    }
  }

  if (rows.length === 0) {
    return (
      <div className="view">
        <header className="page-head">
          <div>
            <h1>Evidence</h1>
            <p className="page-sub">Turn the verified trail into auditor-ready evidence — NIST 800-171 (CMMC), SOC 2, ISO 42001, and EU AI Act controls, mapped to what your agents actually did.</p>
          </div>
        </header>
        <div className="empty">
          <div className="empty-ico"><Icon name="evidence" size={22} /></div>
          <p className="empty-title">No trail to attest yet</p>
          <p>Evidence is derived from your verified signed receipts. Connect a governed app to start the trail, then build a report.</p>
          <div className="page-actions">
            <button className="btn primary" onClick={() => onNavigate("connections")}>Add a connection</button>
            <button className="btn ghost" onClick={() => onNavigate("monitor")}>Go to Monitor</button>
          </div>
        </div>
      </div>
    );
  }

  const integrityOk = bundle.integrity.failed === 0;

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Evidence</h1>
          <p className="page-sub">Auditor-ready bundles derived from {bundle.integrity.verified} verified signed receipt(s). Generated on-device — nothing uploaded.</p>
        </div>
        <div className="page-actions">
          <input className="search" placeholder="Organization (optional)" value={org} onChange={(e) => setOrg(e.target.value)} style={{ minWidth: 220 }} />
        </div>
      </header>

      <section className="stat-grid">
        <Stat label="Receipts" value={bundle.integrity.totalReceipts} />
        <Stat label="Verified" value={bundle.integrity.verified} tone="ok" />
        <Stat label="Integrity" value={integrityOk ? "Intact" : "Broken"} tone={integrityOk ? "ok" : "bad"} />
        <Stat label="Attribution" value={`${bundle.attribution.coveragePct}%`} />
        <Stat label="On-device attests" value={bundle.onDevice.attestations} />
      </section>

      <h2 className="section-head">Reports</h2>
      <div className="conn-list">
        {REPORTS.map((r) => {
          const cov = coverage(r.js);
          const last = gen[r.key];
          return (
            <div className="report-row" key={r.key}>
              <span className="report-ico"><Icon name={r.icon} size={20} /></span>
              <div className="report-main">
                <b>{r.title}</b>
                <span>{r.scope}</span>
                <span className="report-meta">
                  {cov.satisfied}/{cov.total} controls satisfied · {last ? `generated ${fmt(last)}` : "not generated yet"}
                </span>
              </div>
              <div className="report-actions">
                <button className="btn primary" disabled={busyKey === r.key} onClick={() => void generate(r.key, r.title)}>
                  <Icon name="download" size={14} /> {busyKey === r.key ? "Generating…" : "Generate"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
      <p className="prov" style={{ marginTop: 12 }}>
        <Icon name="lock" size={14} />
        {isTauri() ? "Generated in compiled Rust against re-verified receipts." : "On-device per-framework generation runs in the desktop app."} Exports Markdown (report) + JSON (GRC tool).
      </p>
      {note && <p className={`small ${note.includes("BROKEN") ? "bad-text" : "muted"}`} style={{ marginTop: 8 }}>{note}</p>}

      <h2 className="section-head">Control mapping</h2>
      <div className="table-wrap">
        <table className="audit">
          <thead>
            <tr><th>Framework</th><th>Control</th><th>Status</th><th>Evidence</th></tr>
          </thead>
          <tbody>
            {bundle.controls.map((c) => (
              <tr key={`${c.framework}:${c.control}`}>
                <td className="mono">{c.framework}</td>
                <td className="strong">{c.control}</td>
                <td><span className={`badge ${STATUS_CLASS[c.status]}`}>{c.status}</span></td>
                <td className="params" title={c.evidence}>{c.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="section-head">Action inventory</h2>
      <div className="table-wrap">
        <table className="audit">
          <thead>
            <tr><th>Action</th><th>Count</th><th>Policy tier</th><th>Destructive</th></tr>
          </thead>
          <tbody>
            {bundle.actionInventory.map((a) => (
              <tr key={a.action}>
                <td className="mono strong">{a.action}</td>
                <td className="mono">{a.count}</td>
                <td><span className={a.tier === "deny" ? "badge bad" : a.tier === "approval" ? "pill warn" : "pill"}>{a.tier}</span></td>
                <td>{a.destructive ? <span className="badge bad">destructive</span> : <span className="subtle">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: "ok" | "bad" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function fmt(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function download(name: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
