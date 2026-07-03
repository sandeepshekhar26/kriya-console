import { Icon, type IconName } from "./Icon";

export type View =
  | "getstarted"
  | "monitor"
  | "coverage"
  | "audit"
  | "approvals"
  | "policy"
  | "budget"
  | "identity"
  | "evidence"
  | "fleet"
  | "controlplane"
  | "connections"
  | "settings";

type NavItem = { id: View; label: string; icon: IconName; paid?: boolean };
type NavGroup = { label: string; items: NavItem[] };

const GROUPS: NavGroup[] = [
  {
    label: "Start",
    items: [{ id: "getstarted", label: "Get started", icon: "play" }],
  },
  {
    label: "Monitor",
    items: [
      { id: "monitor", label: "Monitor", icon: "monitor" },
      { id: "coverage", label: "Coverage", icon: "coverage" },
      { id: "audit", label: "Audit log", icon: "list" },
      { id: "approvals", label: "Approvals", icon: "approvals" },
    ],
  },
  {
    label: "Govern",
    items: [
      { id: "policy", label: "Policy", icon: "policy" },
      { id: "budget", label: "Budgets & rate", icon: "gauge" },
      { id: "identity", label: "Identity & access", icon: "users" },
    ],
  },
  {
    label: "Compliance",
    items: [
      { id: "evidence", label: "Evidence", icon: "evidence", paid: true },
      { id: "fleet", label: "Fleet", icon: "fleet", paid: true },
    ],
  },
  {
    label: "Control plane",
    items: [{ id: "controlplane", label: "On-prem aggregator", icon: "server", paid: true }],
  },
  {
    label: "Connect",
    items: [{ id: "connections", label: "Connections", icon: "link" }],
  },
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
  liveDir,
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
  liveDir: string;
}) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark">
          <Icon name="shield-check" size={24} strokeWidth={1.5} />
        </span>
        <div>
          <div className="brand-word">Kriya</div>
          <div className="brand-sub">Console</div>
        </div>
      </div>

      <div className="scope" title={live ? liveDir : "Local workspace"}>
        <span className={`dot ${live ? "live" : "ok"}`} />
        <div className="scope-text">
          <b>{live ? "Live" : "Local workspace"}</b>
          <span className="mono">{live ? liveDir : "no device watcher"}</span>
        </div>
      </div>

      <nav className="nav">
        {GROUPS.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-group-label">{group.label}</div>
            {group.items.map((n) => (
              <NavButton
                key={n.id}
                item={n}
                active={view === n.id}
                locked={!!n.paid && !licensed}
                onClick={() => onNavigate(n.id)}
                count={countFor(n.id, { receiptCount, failedCount, warningCount, pendingApprovals, highRiskApprovals, budgetAtLimit })}
              />
            ))}
          </div>
        ))}
      </nav>

      <div className="nav-foot">
        <NavButton
          item={{ id: "settings", label: "Settings", icon: "settings" }}
          active={view === "settings"}
          locked={false}
          onClick={() => onNavigate("settings")}
          count={null}
        />
        <button
          className={`license-chip ${licensed ? "pro" : ""}`}
          onClick={() => onNavigate("settings")}
          title="Manage license"
        >
          <span className="lc-dot" />
          <span className="lc-tier">{licensed ? "Pro" : "Free"}</span>
          {licensed && licenseHolder && <span className="lc-holder">· {licenseHolder}</span>}
          <span className="spacer" />
          <Icon name="chevron-right" size={14} className="muted" />
        </button>
        <div className="foot-actions">
          <button className="icon-toggle grow" onClick={onToggleTheme} title="Switch theme">
            <Icon name={theme === "dark" ? "sun" : "moon"} size={15} />
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
        <div className="trust-strip">
          <Icon name="lock" size={13} />
          Verified on-device · nothing leaves this machine
        </div>
      </div>
    </aside>
  );
}

function NavButton({
  item,
  active,
  locked,
  onClick,
  count,
}: {
  item: NavItem;
  active: boolean;
  locked: boolean;
  onClick: () => void;
  count: { value: number; tone: "neutral" | "warn" | "bad" } | { dot: "warn" } | null;
}) {
  return (
    <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>
      <span className="nav-ico">
        <Icon name={item.icon} size={16} />
      </span>
      <span className="nav-label">{item.label}</span>
      {locked ? (
        <span className="nav-lock" title="Pro feature">
          <Icon name="lock" size={13} />
        </span>
      ) : count && "dot" in count ? (
        <span className={`nav-dot ${count.dot}`} />
      ) : count && count.value > 0 ? (
        <span className={`nav-count ${count.tone}`}>{count.value}</span>
      ) : null}
    </button>
  );
}

type Counts = {
  receiptCount: number;
  failedCount: number;
  warningCount: number;
  pendingApprovals: number;
  highRiskApprovals: number;
  budgetAtLimit: number;
};

function countFor(id: View, c: Counts): { value: number; tone: "neutral" | "warn" | "bad" } | { dot: "warn" } | null {
  switch (id) {
    case "audit":
      if (c.failedCount > 0) return { value: c.failedCount, tone: "bad" };
      return null;
    case "approvals":
      if (c.highRiskApprovals > 0) return { value: c.pendingApprovals, tone: "bad" };
      if (c.pendingApprovals > 0) return { dot: "warn" };
      return null;
    case "policy":
      if (c.warningCount > 0) return { value: c.warningCount, tone: "warn" };
      return null;
    case "budget":
      if (c.budgetAtLimit > 0) return { value: c.budgetAtLimit, tone: "bad" };
      return null;
    default:
      return null;
  }
}
