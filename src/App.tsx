import { useEffect, useMemo, useState } from "react";
import { Sidebar, type View } from "./components/Sidebar";
import { OverviewView } from "./views/OverviewView";
import { AuditView } from "./views/AuditView";
import { PolicyView } from "./views/PolicyView";
import { ApprovalsView } from "./views/ApprovalsView";
import { BudgetView } from "./views/BudgetView";
import { IdentityView } from "./views/IdentityView";
import { ComplianceView } from "./views/ComplianceView";
import { SetupView } from "./views/SetupView";
import { FleetView } from "./views/FleetView";
import { LicenseGate } from "./components/LicenseGate";
import { loadAuditLog } from "./lib/receipts";
import { summarizeBudget } from "./lib/budget";
import { defaultRbac, summarizeIdentities, type RbacModel } from "./lib/identity";
import type { AuditRow } from "./lib/types";
import { defaultPolicy, lintPolicy, type Policy } from "./lib/policy";
import {
  decide,
  ingestPending,
  parsePendingApprovals,
  summarize,
  type DecisionKind,
  type QueueState,
} from "./lib/approvals";
import {
  auditLocation,
  exportCompliance,
  isTauri,
  licenseStatus,
  onAuditChanged,
  readAudit,
  type LicenseStatus,
} from "./lib/tauri";
import sampleAudit from "./sample/sample-audit.jsonl?raw";
import sampleApprovals from "./sample/sample-approvals.jsonl?raw";
import sampleCompliance from "./sample/sample-compliance.jsonl?raw";

const QUEUE_KEY = "kriya-console:approvals";
const RBAC_KEY = "kriya-console:rbac";
const THEME_KEY = "kriya-console:theme";
const OPERATOR = "console-operator";

// Live mode = the desktop app (Tauri). In a plain browser the UI falls back to manual import/sample.
const LIVE = isTauri();

function loadQueue(): QueueState {
  try {
    const raw = localStorage.getItem(QUEUE_KEY);
    if (raw) return JSON.parse(raw) as QueueState;
  } catch {
    /* corrupt or unavailable storage → start empty */
  }
  return { pending: [], decided: [] };
}

function loadRbac(): RbacModel {
  let model = defaultRbac();
  try {
    const raw = localStorage.getItem(RBAC_KEY);
    if (raw) model = JSON.parse(raw) as RbacModel;
  } catch {
    /* corrupt or unavailable storage → start with defaults */
  }
  if (!model.assignments[OPERATOR]) {
    model = { ...model, assignments: { ...model.assignments, [OPERATOR]: "admin" } };
  }
  return model;
}

export function App() {
  const [view, setView] = useState<View>("overview");
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [policy, setPolicy] = useState<Policy>(defaultPolicy);
  const [busy, setBusy] = useState(false);
  const [queue, setQueue] = useState<QueueState>(loadQueue);
  const [rbac, setRbac] = useState<RbacModel>(loadRbac);
  const [actingOperator, setActingOperator] = useState<string>(OPERATOR);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [liveDir, setLiveDir] = useState<string>("~/.kriya/audit");
  const [theme, setTheme] = useState<"dark" | "light">(
    () => (localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark"),
  );

  const paid = license?.tier === "pro";

  // Apply + persist the theme (dark/light) across reloads.
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* storage unavailable — non-fatal */
    }
  }, [theme]);

  // Live mode (Tauri): auto-discover + tail ~/.kriya/audit/. Open the app → see governance, no
  // import. The backend verifies every receipt in compiled Rust; we render the rows and refresh on
  // each `audit-changed` event so an agent's actions appear live.
  useEffect(() => {
    if (!LIVE) return;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    const refresh = async () => {
      try {
        const r = await readAudit();
        if (!cancelled) setRows(r);
      } catch {
        /* backend not ready yet — the next event re-reads */
      }
    };
    void refresh();
    void licenseStatus()
      .then((s) => !cancelled && setLicense(s))
      .catch(() => {});
    void auditLocation()
      .then((l) => !cancelled && setLiveDir(l.dir))
      .catch(() => {});
    void onAuditChanged(() => void refresh()).then((u) => {
      if (cancelled) u();
      else unlisten = u;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // Persist the approval queue + RBAC across reloads.
  useEffect(() => {
    try {
      localStorage.setItem(QUEUE_KEY, JSON.stringify(queue));
    } catch {
      /* non-fatal */
    }
  }, [queue]);
  useEffect(() => {
    try {
      localStorage.setItem(RBAC_KEY, JSON.stringify(rbac));
    } catch {
      /* non-fatal */
    }
  }, [rbac]);

  // Manual import (the demoted "open a file" path) + sample loaders for the non-Tauri / web build.
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
  const loadComplianceSample = () => void ingest(sampleCompliance, "sample-compliance.jsonl");

  function ingestApprovals(text: string, source: string) {
    setQueue((q) => ingestPending(q, parsePendingApprovals(text, source)));
  }
  function decideApproval(id: string, kind: DecisionKind, reason: string) {
    setQueue((q) => decide(q, id, kind, reason, actingOperator, Date.now()));
  }
  const loadSampleApprovals = () => ingestApprovals(sampleApprovals, "sample-approvals.jsonl");
  const queueStats = useMemo(() => summarize(queue), [queue]);

  const operators = useMemo(
    () =>
      [
        ...new Set([
          OPERATOR,
          ...summarizeIdentities(rows, "user")
            .map((u) => u.id)
            .filter((u) => u !== "(unattributed)"),
          ...Object.keys(rbac.assignments),
        ]),
      ].sort(),
    [rows, rbac.assignments],
  );

  const observedActions = useMemo(() => {
    const set = new Set<string>();
    for (const r of rows) if (r.receipt) set.add(r.receipt.action_id);
    return Array.from(set).sort();
  }, [rows]);

  const verified = rows.filter((r) => r.outcome.ok).length;
  const warningCount = useMemo(() => lintPolicy(policy).length, [policy]);
  const budgetAtLimit = useMemo(
    () =>
      summarizeBudget(rows, "source", {
        maxActionsPerMinute: policy.maxActionsPerMinute,
        maxApiCallsPerHour: policy.maxApiCallsPerHour,
      }).scopesAtLimit,
    [rows, policy.maxActionsPerMinute, policy.maxApiCallsPerHour],
  );

  return (
    <div className="shell">
      <Sidebar
        view={view}
        onNavigate={setView}
        receiptCount={rows.length}
        failedCount={rows.length - verified}
        warningCount={warningCount}
        pendingApprovals={queueStats.pending}
        highRiskApprovals={queueStats.highRiskPending}
        budgetAtLimit={budgetAtLimit}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
        licensed={paid}
        licenseHolder={license?.holder}
        live={LIVE}
      />
      <main className="main">
        {view === "overview" && (
          <OverviewView
            rows={rows}
            policy={policy}
            observedActions={observedActions}
            onNavigate={setView}
            onLoadSample={loadSample}
            live={LIVE ? liveDir : undefined}
          />
        )}
        {view === "audit" && (
          <AuditView
            rows={rows}
            onIngest={ingest}
            onClear={() => setRows([])}
            onLoadSample={loadSample}
            live={LIVE ? liveDir : undefined}
          />
        )}
        {view === "approvals" && (
          <ApprovalsView
            queue={queue}
            onIngest={ingestApprovals}
            onDecide={decideApproval}
            onClear={() => setQueue({ pending: [], decided: [] })}
            onLoadSample={loadSampleApprovals}
            rbac={rbac}
            actingOperator={actingOperator}
            onActingOperatorChange={setActingOperator}
            operators={operators}
          />
        )}
        {view === "policy" && (
          <PolicyView policy={policy} onChange={setPolicy} observedActions={observedActions} />
        )}
        {view === "budget" && <BudgetView rows={rows} policy={policy} onLoadSample={loadSample} />}
        {view === "identity" && (
          <IdentityView rows={rows} rbac={rbac} onRbacChange={setRbac} onLoadSample={loadComplianceSample} />
        )}
        {view === "compliance" &&
          (paid ? (
            <PaidCompliance
              rows={rows}
              policy={policy}
              onNavigate={setView}
              onLoadSample={loadComplianceSample}
            />
          ) : (
            <LicenseGate
              feature="Compliance evidence export"
              blurb="Turn the verified trail into a SOC 2 / ISO 42001 / EU AI Act evidence bundle — generated on-device in compiled Rust."
              license={license}
              onActivate={() => setView("setup")}
            />
          ))}
        {view === "fleet" &&
          (paid ? (
            <FleetView />
          ) : (
            <LicenseGate
              feature="Fleet correlation"
              blurb="Cross-machine, cross-app correlation of the signed trail — distinct signers, agents, and tamper signals across every governed app."
              license={license}
              onActivate={() => setView("setup")}
            />
          ))}
        {view === "setup" && <SetupView license={license} onLicenseChange={setLicense} />}
      </main>
      {busy && <div className="busy">verifying…</div>}
    </div>
  );
}

/**
 * The paid Compliance surface: the existing interactive preview, plus (in the desktop app) a
 * "generate on-device bundle" action that runs the compiled-Rust `export_compliance` command — the
 * authoritative, license-gated evidence generator — and downloads its Markdown + JSON.
 */
function PaidCompliance({
  rows,
  policy,
  onNavigate,
  onLoadSample,
}: {
  rows: AuditRow[];
  policy: Policy;
  onNavigate: (v: View) => void;
  onLoadSample: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  async function rustExport(framework: string) {
    setBusy(true);
    setNote(null);
    try {
      const bundle = await exportCompliance(framework);
      download(`kriya-${framework}-evidence.md`, bundle.markdown, "text/markdown");
      download(`kriya-${framework}-evidence.json`, bundle.json, "application/json");
      setNote(
        `Generated in Rust from ${bundle.totalReceipts} receipt(s): ${bundle.verified} verified, integrity ${
          bundle.integrityOk ? "intact" : "BROKEN"
        }.`,
      );
    } catch (e) {
      setNote(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {isTauri() && (
        <div className="rust-export-bar">
          <span className="reb-label">On-device signed bundle (generated in compiled Rust):</span>
          <button className="btn small" disabled={busy} onClick={() => void rustExport("SOC2")}>
            SOC 2
          </button>
          <button className="btn small" disabled={busy} onClick={() => void rustExport("ISO42001")}>
            ISO 42001
          </button>
          <button className="btn small" disabled={busy} onClick={() => void rustExport("EU-AI-Act")}>
            EU AI Act
          </button>
          {note && <span className="reb-note">{note}</span>}
        </div>
      )}
      <ComplianceView rows={rows} policy={policy} onNavigate={onNavigate} onLoadSample={onLoadSample} />
    </>
  );
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
