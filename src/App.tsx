import { useEffect, useMemo, useState } from "react";
import { Sidebar, type View } from "./components/Sidebar";
import { CommandPalette, type Command } from "./components/CommandPalette";
import { MonitorView } from "./views/MonitorView";
import { AuditView } from "./views/AuditView";
import { PolicyView } from "./views/PolicyView";
import { ApprovalsView } from "./views/ApprovalsView";
import { BudgetView } from "./views/BudgetView";
import { IdentityView } from "./views/IdentityView";
import { ReportsView } from "./views/ReportsView";
import { ConnectionsView } from "./views/ConnectionsView";
import { SettingsView, type SettingsPane } from "./views/SettingsView";
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
  isTauri,
  licenseStatus,
  onAuditChanged,
  readAudit,
  type LicenseStatus,
} from "./lib/tauri";
const QUEUE_KEY = "kriya-console:approvals";
const RBAC_KEY = "kriya-console:rbac";
const THEME_KEY = "kriya-console:theme";
const OPERATOR = "console-operator";

// Live mode = the desktop app (Tauri). In a plain browser the UI falls back to manual file import.
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
  const [view, setView] = useState<View>("monitor");
  const [settingsPane, setSettingsPane] = useState<SettingsPane>("appearance");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [policy, setPolicy] = useState<Policy>(defaultPolicy);
  const [busy, setBusy] = useState(false);
  const [queue, setQueue] = useState<QueueState>(loadQueue);
  const [rbac, setRbac] = useState<RbacModel>(loadRbac);
  const [actingOperator, setActingOperator] = useState<string>(OPERATOR);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [liveDir, setLiveDir] = useState<string>("~/.kriya/audit");
  const [theme, setTheme] = useState<"dark" | "light">(
    () => (localStorage.getItem(THEME_KEY) === "dark" ? "dark" : "light"),
  );

  const paid = license?.tier === "pro";

  function goSettings(pane: SettingsPane) {
    setSettingsPane(pane);
    setView("settings");
  }

  // Apply + persist the theme (light is the first-class default; only "dark" sets the attribute).
  useEffect(() => {
    if (theme === "dark") document.documentElement.setAttribute("data-theme", "dark");
    else document.documentElement.removeAttribute("data-theme");
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* storage unavailable — non-fatal */
    }
  }, [theme]);

  // ⌘K / Ctrl-K opens the command palette.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

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

  // Manual import — the "open a file" path for loading a real signed trail in the browser build;
  // in the desktop app the live ~/.kriya/audit tail supplies rows with no import.
  async function ingest(text: string, source: string) {
    setBusy(true);
    try {
      const next = await loadAuditLog(text, source);
      setRows((prev) => [...prev, ...next]);
    } finally {
      setBusy(false);
    }
  }

  function ingestApprovals(text: string, source: string) {
    setQueue((q) => ingestPending(q, parsePendingApprovals(text, source)));
  }
  function decideApproval(id: string, kind: DecisionKind, reason: string) {
    setQueue((q) => decide(q, id, kind, reason, actingOperator, Date.now()));
  }
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

  const commands = useMemo<Command[]>(() => {
    const nav: [View, string, Command["icon"]][] = [
      ["monitor", "Monitor", "monitor"],
      ["audit", "Audit log", "list"],
      ["approvals", "Approvals", "approvals"],
      ["policy", "Policy", "policy"],
      ["budget", "Budgets & rate", "gauge"],
      ["identity", "Identity & access", "users"],
      ["evidence", "Evidence", "evidence"],
      ["fleet", "Fleet", "fleet"],
      ["connections", "Connections", "link"],
      ["settings", "Settings", "settings"],
    ];
    const cmds: Command[] = nav.map(([id, label, icon]) => ({
      id: `nav:${id}`,
      group: "Navigate",
      label: `Go to ${label}`,
      icon,
      run: () => setView(id),
    }));
    cmds.push(
      { id: "act:connection", group: "Actions", label: "Add a governed connection", icon: "plus", run: () => setView("connections") },
      { id: "act:evidence", group: "Actions", label: "Generate compliance evidence", icon: "evidence", run: () => setView("evidence") },
      { id: "act:theme", group: "Actions", label: theme === "dark" ? "Switch to light theme" : "Switch to dark theme", icon: theme === "dark" ? "sun" : "moon", run: () => setTheme((t) => (t === "dark" ? "light" : "dark")) },
      { id: "act:license", group: "Actions", label: "Manage license", icon: "key", run: () => goSettings("license") },
    );
    if (queueStats.pending > 0) {
      cmds.push({ id: "appr:review", group: "Approvals", label: `Review ${queueStats.pending} pending approval${queueStats.pending > 1 ? "s" : ""}`, icon: "approvals", hint: queueStats.highRiskPending > 0 ? `${queueStats.highRiskPending} high-risk` : undefined, run: () => setView("approvals") });
    }
    return cmds;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [theme, queueStats.pending, queueStats.highRiskPending]);

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
        liveDir={liveDir}
      />
      <main className="main">
        {view === "monitor" && (
          <MonitorView
            rows={rows}
            policy={policy}
            observedActions={observedActions}
            pendingApprovals={queueStats.pending}
            highRiskApprovals={queueStats.highRiskPending}
            onNavigate={setView}
            live={LIVE ? liveDir : undefined}
          />
        )}
        {view === "audit" && (
          <AuditView
            rows={rows}
            onIngest={ingest}
            onClear={() => setRows([])}
            onNavigate={setView}
            live={LIVE ? liveDir : undefined}
          />
        )}
        {view === "approvals" && (
          <ApprovalsView
            queue={queue}
            onIngest={ingestApprovals}
            onDecide={decideApproval}
            onClear={() => setQueue({ pending: [], decided: [] })}
            rbac={rbac}
            actingOperator={actingOperator}
            onActingOperatorChange={setActingOperator}
            operators={operators}
            onNavigate={setView}
          />
        )}
        {view === "policy" && (
          <PolicyView policy={policy} onChange={setPolicy} observedActions={observedActions} />
        )}
        {view === "budget" && <BudgetView rows={rows} policy={policy} onNavigate={setView} />}
        {view === "identity" && (
          <IdentityView rows={rows} rbac={rbac} onRbacChange={setRbac} onNavigate={setView} />
        )}
        {view === "evidence" &&
          (paid ? (
            <ReportsView
              rows={rows}
              policy={policy}
              onNavigate={setView}
            />
          ) : (
            <LicenseGate
              feature="Compliance evidence"
              blurb="Turn the verified trail into a SOC 2 / ISO 42001 / EU AI Act evidence bundle — generated on-device in compiled Rust."
              license={license}
              onActivate={() => goSettings("license")}
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
              onActivate={() => goSettings("license")}
            />
          ))}
        {view === "connections" && <ConnectionsView onNavigate={setView} onOpenPermissions={() => goSettings("permissions")} />}
        {view === "settings" && (
          <SettingsView
            pane={settingsPane}
            onPaneChange={setSettingsPane}
            theme={theme}
            onThemeChange={setTheme}
            license={license}
            onLicenseChange={setLicense}
          />
        )}
      </main>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
      {busy && (
        <div className="busy">
          <span className="dot live" /> verifying…
        </div>
      )}
    </div>
  );
}
