export type View =
  | "overview"
  | "audit"
  | "policy"
  | "approvals"
  | "budget"
  | "identity"
  | "compliance"
  | "fleet"
  | "setup";

const NAV: { id: View; label: string; icon: string; paid?: boolean }[] = [
  { id: "overview", label: "Overview", icon: "◧" },
  { id: "audit", label: "Audit log", icon: "▤" },
  { id: "approvals", label: "Approvals", icon: "✓" },
  { id: "policy", label: "Policy", icon: "⛨" },
  { id: "budget", label: "Budgets", icon: "◔" },
  { id: "identity", label: "Identity", icon: "⊙" },
  { id: "compliance", label: "Compliance", icon: "▦", paid: true },
  { id: "fleet", label: "Fleet", icon: "⊞", paid: true },
  { id: "setup", label: "Setup", icon: "⚙" },
];

export function Sidebar({
  view,
  onNavigate,
  receiptCount,
  failedCount,
  warningCount,
  pendingApprovals,
  highRiskApprovals,
  budgetAtLimit,
  theme,
  onToggleTheme,
  licensed,
  licenseHolder,
  live,
}: {
  view: View;
  onNavigate: (v: View) => void;
  receiptCount: number;
  failedCount: number;
  warningCount: number;
  pendingApprovals: number;
  highRiskApprovals: number;
  budgetAtLimit: number;
  theme: "dark" | "light";
  onToggleTheme: () => void;
  licensed: boolean;
  licenseHolder?: string | null;
  live: boolean;
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="logo">▣</span>
        <div>
          <div className="brand-name">kriya</div>
          <div className="brand-sub">Console</div>
        </div>
      </div>

      <div className="workspace">
        <div className="ws-label">WORKSPACE</div>
        <div className="ws-name">
          {live ? (
            <span className="live-dot-row">
              <span className="dot live" /> watching ~/.kriya/audit
            </span>
          ) : (
            "Local workspace"
          )}
        </div>
      </div>

      <nav className="nav">
        {NAV.map((n) => (
          <button
            key={n.id}
            className={`nav-item ${view === n.id ? "active" : ""}`}
            onClick={() => onNavigate(n.id)}
          >
            <span className="nav-icon">{n.icon}</span>
            <span className="nav-label">{n.label}</span>
            {n.paid && !licensed && (
              <span className="nav-lock" title="Paid feature">
                🔒
              </span>
            )}
            {n.id === "audit" && failedCount > 0 && <span className="nav-badge bad">{failedCount}</span>}
            {n.id === "audit" && receiptCount > 0 && failedCount === 0 && (
              <span className="nav-badge">{receiptCount}</span>
            )}
            {n.id === "approvals" && highRiskApprovals > 0 && (
              <span className="nav-badge bad">{pendingApprovals}</span>
            )}
            {n.id === "approvals" && pendingApprovals > 0 && highRiskApprovals === 0 && (
              <span className="nav-badge warn">{pendingApprovals}</span>
            )}
            {n.id === "policy" && warningCount > 0 && <span className="nav-badge warn">{warningCount}</span>}
            {n.id === "budget" && budgetAtLimit > 0 && <span className="nav-badge bad">{budgetAtLimit}</span>}
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <button
          className={`license-badge ${licensed ? "pro" : "free"}`}
          onClick={() => onNavigate("setup")}
          title="Manage license"
        >
          <span className="lb-dot" />
          {licensed ? `Pro${licenseHolder ? ` · ${licenseHolder}` : ""}` : "Free tier"}
        </button>
        <div className="foot-row">
          <span className="dot ok" /> verified locally · nothing leaves this machine
        </div>
        <button className="theme-toggle" onClick={onToggleTheme} title="Switch light / dark theme">
          <span className="tt-icon">{theme === "dark" ? "☀" : "☾"}</span>
          <span className="tt-label">{theme === "dark" ? "Light mode" : "Dark mode"}</span>
        </button>
      </div>
    </aside>
  );
}
