export type View = "overview" | "audit" | "policy" | "approvals" | "compliance";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "◧" },
  { id: "audit", label: "Audit log", icon: "▤" },
  { id: "approvals", label: "Approvals", icon: "✓" },
  { id: "policy", label: "Policy", icon: "⛨" },
  { id: "compliance", label: "Compliance", icon: "▦" },
];

const SOON: { label: string; icon: string }[] = [
  { label: "Budgets", icon: "◔" },
  { label: "Identity", icon: "⊙" },
];

export function Sidebar({
  view,
  onNavigate,
  receiptCount,
  failedCount,
  warningCount,
  pendingApprovals,
  highRiskApprovals,
}: {
  view: View;
  onNavigate: (v: View) => void;
  receiptCount: number;
  failedCount: number;
  warningCount: number;
  pendingApprovals: number;
  highRiskApprovals: number;
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
        <div className="ws-name">Local workspace</div>
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
          </button>
        ))}

        <div className="nav-divider">COMING SOON</div>
        {SOON.map((n) => (
          <button key={n.label} className="nav-item soon" disabled>
            <span className="nav-icon">{n.icon}</span>
            <span className="nav-label">{n.label}</span>
            <span className="soon-tag">soon</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div className="foot-row">
          <span className="dot ok" /> verified locally · nothing leaves this machine
        </div>
        <div className="foot-muted">R6 · audit · approvals · policy</div>
      </div>
    </aside>
  );
}
