import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import type { Policy } from "../lib/policy";
import {
  buildEvidence,
  renderJson,
  renderMarkdown,
  type ControlStatus,
} from "../lib/compliance";

export function ComplianceView({
  rows,
  policy,
  onNavigate,
  onLoadSample,
}: {
  rows: AuditRow[];
  policy: Policy;
  onNavigate: (v: "audit") => void;
  onLoadSample: () => void;
}) {
  const [org, setOrg] = useState("");

  const bundle = useMemo(
    () => buildEvidence(rows, policy, { generatedAt: Date.now(), organization: org }),
    [rows, policy, org],
  );

  function download(kind: "md" | "json") {
    const text = kind === "md" ? renderMarkdown(bundle) : renderJson(bundle);
    const type = kind === "md" ? "text/markdown" : "application/json";
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `kriya-compliance-evidence.${kind}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (rows.length === 0) {
    return (
      <div className="view">
        <header className="page-head">
          <div>
            <h1>Compliance evidence</h1>
            <p className="page-sub">
              Turn your signed audit trail into auditor-ready evidence — SOC 2, ISO 42001, and EU AI
              Act controls, mapped to what your agents actually did.
            </p>
          </div>
        </header>
        <div className="empty">
          <div className="empty-glyph">▦</div>
          <p>
            Load an audit log first — the evidence is derived from your verified signed receipts.
          </p>
          <div className="page-actions">
            <button className="btn" onClick={onLoadSample}>
              Load sample data
            </button>
            <button className="btn ghost" onClick={() => onNavigate("audit")}>
              Go to Audit log →
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Compliance evidence</h1>
          <p className="page-sub">
            Derived from {bundle.integrity.verified} verified signed receipt(s). Export the bundle as
            Markdown (for a report) or JSON (for a GRC tool).
          </p>
        </div>
        <div className="page-actions">
          <input
            className="search"
            placeholder="Organization (optional)"
            value={org}
            onChange={(e) => setOrg(e.target.value)}
          />
          <button className="btn" onClick={() => download("md")}>
            Export Markdown
          </button>
          <button className="btn ghost" onClick={() => download("json")}>
            Export JSON
          </button>
        </div>
      </header>

      <section className="stat-grid">
        <Stat label="Receipts" value={bundle.integrity.totalReceipts} />
        <Stat label="Verified" value={bundle.integrity.verified} tone="ok" />
        <Stat
          label="Failed / tampered"
          value={bundle.integrity.failed}
          tone={bundle.integrity.failed ? "bad" : undefined}
        />
        <Stat label="Attribution" value={`${bundle.attribution.coveragePct}%`} />
        <Stat label="On-device attests" value={bundle.onDevice.attestations} />
      </section>

      <h2 className="section-head">Control mapping</h2>
      <div className="table-wrap">
        <table className="audit">
          <thead>
            <tr>
              <th>Framework</th>
              <th>Control</th>
              <th>Status</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {bundle.controls.map((c) => (
              <tr key={`${c.framework}:${c.control}`}>
                <td className="mono">{c.framework}</td>
                <td className="mono strong">{c.control}</td>
                <td>
                  <span className={`badge ${STATUS_CLASS[c.status]}`}>{c.status}</span>
                </td>
                <td className="params" title={c.evidence}>
                  {c.evidence}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="section-head">Action inventory</h2>
      <div className="table-wrap">
        <table className="audit">
          <thead>
            <tr>
              <th>Action</th>
              <th>Count</th>
              <th>Policy tier</th>
              <th>Destructive</th>
            </tr>
          </thead>
          <tbody>
            {bundle.actionInventory.map((a) => (
              <tr key={a.action}>
                <td className="mono strong">{a.action}</td>
                <td className="mono">{a.count}</td>
                <td>
                  <span className={a.tier === "deny" ? "badge bad" : a.tier === "approval" ? "pill warn" : "pill"}>
                    {a.tier}
                  </span>
                </td>
                <td>{a.destructive ? <span className="badge bad">destructive</span> : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const STATUS_CLASS: Record<ControlStatus, string> = {
  satisfied: "ok",
  partial: "warn",
  gap: "bad",
};

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: "ok" | "bad" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
