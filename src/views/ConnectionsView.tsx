import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  governAll,
  governableSurface,
  governPreview,
  isTauri,
  listCandidateApps,
  onboardingStatus,
  openSettingsPane,
  ungovern,
  wireClaudeConfig,
  type GovernableSurface,
  type GovernPlan,
  type GovernAllReport,
  type GovernTarget,
  type OnboardingStatus,
  type WireRequest,
  type WireResult,
} from "../lib/tauri";
import {
  STATE_BADGE,
  STATE_LABEL,
  groupByAgent,
  isWireable,
  summarize,
  wireableCount,
} from "../lib/govern-view";
import { Icon, type IconName } from "../components/Icon";
import type { View } from "../components/Sidebar";

type ConnType = "kriya" | "proxy" | "desktop";
type DesktopMode = "reach-in" | "computer-use" | "router";

const CATALOG: { type: ConnType; icon: IconName; title: string; tagline: string; fidelity: string }[] = [
  {
    type: "kriya",
    icon: "bolt",
    title: "kriya-native server",
    tagline: "Run a kriya-instrumented MCP server. Its real named actions are governed and signed in-process — the highest-fidelity connection.",
    fidelity: "Named-action policy · in-process signing",
  },
  {
    type: "proxy",
    icon: "server",
    title: "Proxy an MCP server",
    tagline: "Wrap any existing MCP server with the governance gateway. Zero changes to the server — every tool call routes through policy → approval → signed receipt.",
    fidelity: "Named-action policy · proxied",
  },
  {
    type: "desktop",
    icon: "desktop",
    title: "Govern a desktop app",
    tagline: "For an app with no API: reach into its macOS accessibility tree, or drive any app by computer-use. The universal floor.",
    fidelity: "Coverage-bounded · macOS permissions required",
  },
];

// Browser/preview status so the design renders outside the desktop app.
const PREVIEW_STATUS: OnboardingStatus = {
  gatewayPresent: true,
  gatewayPath: "/Applications/Kriya Console.app/Contents/MacOS/kriya-gateway",
  gatewayBundled: true,
  accessibilityTrusted: true,
  claudeConfigPath: "~/Library/Application Support/Claude/claude_desktop_config.json",
  claudeConfigExists: true,
  wiredServers: ["kriya-proxy", "kriya-Numbers"],
  auditDir: "~/.kriya/audit",
  auditLogs: 3,
  policyPresent: true,
};

// Browser/preview surface + plan so the "Govern everything" dashboard renders outside Tauri.
const PREVIEW_SURFACE: GovernableSurface = {
  targets: [
    { id: "claude-code:hook", agent: "claude-code", kind: "hook", seam: "hook", state: "ungoverned", configPath: "~/.claude/settings.json", label: "Claude Code — native tools + attached MCP", detail: "One hook governs the whole local Claude Code lane — native tools and every attached MCP server." },
    { id: "hermes:hook", agent: "hermes", kind: "hook", seam: "hook", state: "ungoverned", configPath: "~/.hermes/config.yaml", label: "Hermes — native tools + attached MCP", detail: "One hook governs the whole local Hermes lane — native tools (terminal, files, computer-use) and every attached MCP server." },
    { id: "claude-desktop:mcp-server:github", agent: "claude-desktop", kind: "mcp-server", seam: "gateway", state: "ungoverned", configPath: "~/Library/Application Support/Claude/claude_desktop_config.json", label: "github (MCP)", detail: "Local stdio server — wrap it with kriya-gateway to sign every tool call." },
    { id: "claude-desktop:mcp-server:filesystem", agent: "claude-desktop", kind: "mcp-server", seam: "gateway", state: "governed", configPath: "~/Library/Application Support/Claude/claude_desktop_config.json", label: "filesystem (MCP)", detail: "Wrapped by kriya-gateway — every tool call is policy-gated and signed." },
    { id: "claude-desktop:mcp-server:linear", agent: "claude-desktop", kind: "mcp-server", seam: "gateway", state: "out-of-scope-cloud", configPath: "~/Library/Application Support/Claude/claude_desktop_config.json", label: "linear (remote MCP)", detail: "Runs off-device (remote/SSE/HTTP) — an on-device receipt is physically impossible." },
    { id: "hermes:mcp-server:fs", agent: "hermes", kind: "mcp-server", seam: "gateway", state: "ungoverned", configPath: "~/.hermes/config.yaml", label: "fs (MCP)", detail: "Local stdio server — wrap it with kriya-gateway to sign every tool call." },
    { id: "desktop:desktop-apps", agent: "desktop", kind: "desktop-apps", seam: "reach-in/computer-use", state: "needs-permission", label: "Desktop apps (no API)", detail: "2 desktop apps detected. Reach-in/computer-use needs macOS Accessibility — grant Kriya Console.app, then govern a specific app in Advanced." },
    // S1: the VS-Code family (Cursor/Cline/GitHub Copilot) + Gemini CLI — MCP-only clients wired through
    // the gateway (Cline left ungoverned so the one-click "Govern" action is visible). Rendered in
    // AGENT_ORDER position, so array order here is irrelevant.
    { id: "cursor:mcp-server:filesystem", agent: "cursor", kind: "mcp-server", seam: "gateway", state: "governed", configPath: "~/.cursor/mcp.json", label: "filesystem (MCP)", detail: "Wrapped by kriya-gateway — every tool call is policy-gated and signed. Cursor's built-in edit/terminal tools bypass MCP (contain via B14)." },
    { id: "cline:mcp-server:github", agent: "cline", kind: "mcp-server", seam: "gateway", state: "ungoverned", configPath: "~/…/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", label: "github (MCP)", detail: "Local stdio server — wrap it with kriya-gateway to sign every tool call." },
    { id: "copilot:mcp-server:playwright", agent: "copilot", kind: "mcp-server", seam: "gateway", state: "governed", configPath: "~/Library/Application Support/Code/User/mcp.json", label: "playwright (MCP)", detail: "Wrapped by kriya-gateway. Copilot's cloud coding agent stays out of scope (locus rule)." },
    { id: "gemini:mcp-server:fetch", agent: "gemini", kind: "mcp-server", seam: "gateway", state: "governed", configPath: "~/.gemini/settings.json", label: "fetch (MCP)", detail: "Wrapped by kriya-gateway — every tool call is policy-gated and signed." },
  ],
  hookAvailable: true,
  gatewayAvailable: true,
  hermesHookAvailable: true,
  axTrusted: false,
  desktopCandidates: ["Numbers", "Notes"],
};
const PREVIEW_PLAN: GovernPlan = {
  wire: [
    { targetId: "claude-code:hook", agent: "claude-code", seam: "hook", action: "install-hook", detail: "Install the kriya-hook block (record-only) so every native tool + attached MCP call signs a receipt." },
    { targetId: "hermes:hook", agent: "hermes", seam: "hook", action: "install-hook", detail: "Install the kriya-hermes-hook block (record-only) so every native tool + attached MCP call signs a receipt." },
    { targetId: "claude-desktop:mcp-server:github", agent: "claude-desktop", seam: "gateway", action: "wrap-mcp-server", serverKey: "github", detail: "Wrap github with kriya-gateway — policy → approval → signed receipt on every tool call." },
    { targetId: "hermes:mcp-server:fs", agent: "hermes", seam: "gateway", action: "wrap-mcp-server", serverKey: "fs", detail: "Wrap fs with kriya-gateway — policy → approval → signed receipt on every tool call." },
    { targetId: "cline:mcp-server:github", agent: "cline", seam: "gateway", action: "wrap-mcp-server", serverKey: "github", detail: "Wrap github with kriya-gateway — policy → approval → signed receipt on every tool call." },
  ],
  needsPermission: [PREVIEW_SURFACE.targets[6]!],
  outOfScopeCloud: [PREVIEW_SURFACE.targets[4]!],
  // filesystem (Claude Desktop) + the S1 governed VS-Code-family/CLI agents (cursor/copilot/gemini).
  alreadyGoverned: [PREVIEW_SURFACE.targets[3]!, PREVIEW_SURFACE.targets[7]!, PREVIEW_SURFACE.targets[9]!, PREVIEW_SURFACE.targets[10]!],
  blocked: [],
  hookAvailable: true,
  gatewayAvailable: true,
  hermesHookAvailable: true,
};

/**
 * Connections — the **Governed surface** dashboard (GA-1, doc 21 Part C). One front door: detect every
 * governable agent on the machine and wire each through its correct seam with a single "Govern
 * everything" action (preview → confirm → apply). The detected list shows per-agent state with a
 * per-item toggle; the old connector catalog is demoted to an "Advanced — add manually" disclosure.
 * Wiring runs in the compiled backend (govern_all); the browser preview renders a static surface.
 */
export function ConnectionsView({
  onNavigate,
  onOpenPermissions,
}: {
  onNavigate: (v: View) => void;
  onOpenPermissions: () => void;
}) {
  const live = isTauri();
  const [surface, setSurface] = useState<GovernableSurface | null>(live ? null : PREVIEW_SURFACE);
  const [status, setStatus] = useState<OnboardingStatus | null>(live ? null : PREVIEW_STATUS);
  const [apps, setApps] = useState<string[]>([]);
  const [draft, setDraft] = useState<ConnType | null>(null);
  const [advanced, setAdvanced] = useState(false);
  // The govern-everything flow: idle → preview (confirm) → applied (report).
  const [flow, setFlow] = useState<"idle" | "preview" | "applied">("idle");
  const [plan, setPlan] = useState<GovernPlan | null>(null);
  const [report, setReport] = useState<GovernAllReport | null>(null);
  const [busy, setBusy] = useState<string | null>(null); // "all" | a target id
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(() => {
    if (!live) return;
    void governableSurface().then(setSurface).catch(() => {});
    void onboardingStatus().then(setStatus).catch(() => {});
    void listCandidateApps().then(setApps).catch(() => setApps([]));
  }, [live]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const summary = useMemo(() => (surface ? summarize(surface) : null), [surface]);
  const toWire = surface ? wireableCount(surface) : 0;
  const groups = useMemo(() => (surface ? groupByAgent(surface.targets) : []), [surface]);

  async function startPreview() {
    setErr(null);
    setReport(null);
    if (!live) {
      setPlan(PREVIEW_PLAN);
      setFlow("preview");
      return;
    }
    setBusy("all");
    try {
      setPlan(await governPreview());
      setFlow("preview");
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function applyGovernAll() {
    setErr(null);
    if (!live) {
      setFlow("applied");
      return;
    }
    setBusy("all");
    try {
      setReport(await governAll());
      setFlow("applied");
      refresh();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function toggleTarget(target: GovernTarget) {
    if (!live) return;
    setErr(null);
    setBusy(target.id);
    try {
      if (target.state === "governed") await ungovern(target.id);
      else await governAll({ only: [target.id] });
      refresh();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Governed surface</h1>
          <p className="page-sub">
            One substrate, many agents. Kriya detects every governable agent on this machine and wires
            each through its seam — the Claude Code hook, or the gateway for local MCP servers. Every
            governed action signs a receipt to <code>~/.kriya/audit/</code>; cloud-executed surfaces stay
            honestly out of scope.
          </p>
        </div>
        <div className="page-actions">
          {summary && (
            <>
              <span className="pill"><span className="dot ok" /> {summary.governed} governed</span>
              {summary.ungoverned > 0 && <span className="pill warn">{summary.ungoverned} ungoverned</span>}
            </>
          )}
          {live && (
            <button className="btn ghost" onClick={refresh}>
              <Icon name="refresh" size={14} /> Refresh
            </button>
          )}
        </div>
      </header>

      {!live && (
        <div className="evidence-bar" style={{ marginBottom: 24 }}>
          <span className="prov">
            <Icon name="info" size={15} />
            Governing runs in the desktop app (it edits your agents' real configs and grants macOS
            permissions). This is a design preview.
          </span>
        </div>
      )}

      {err && <p className="warn-text small" style={{ marginBottom: 16 }}>{err}</p>}

      {/* The headline: Govern everything. */}
      <div className="panel">
        {flow === "idle" && (
          <div className="panel-head" style={{ alignItems: "flex-start" }}>
            <div style={{ minWidth: 0 }}>
              <h2>Govern everything</h2>
              <p className="muted small" style={{ margin: "6px 0 0", maxWidth: 620 }}>
                {toWire > 0
                  ? <>Detected <strong>{toWire}</strong> ungoverned {toWire === 1 ? "surface" : "surfaces"} that can be wired now. You'll see exactly what changes before anything is written.</>
                  : summary && summary.governed > 0
                  ? <>Everything detected is already governed. Re-run any time you add an agent or MCP server.</>
                  : <>No ungoverned surfaces detected yet. kriya governs <strong>Claude Code</strong> &amp; <strong>Hermes</strong> (the whole lane, the moment the CLI is on your PATH) and <strong>Cursor</strong>, <strong>Cline</strong>, <strong>GitHub Copilot</strong> &amp; <strong>Gemini CLI</strong> (via the gateway) — but the last four have no hook, so each one appears here only once it has a <strong>local (stdio) MCP server</strong> in its config (that's the lane kriya governs for them). Install a supported agent, add a local MCP server to it, then re-run — or add a connection manually below.</>}
              </p>
            </div>
            <button
              className="btn primary"
              disabled={busy === "all" || toWire === 0}
              onClick={() => void startPreview()}
            >
              {busy === "all" ? "Detecting…" : "Govern everything"}
            </button>
          </div>
        )}

        {flow === "preview" && plan && (
          <GovernPreviewPanel
            plan={plan}
            busy={busy === "all"}
            onApply={() => void applyGovernAll()}
            onCancel={() => setFlow("idle")}
          />
        )}

        {flow === "applied" && (
          <GovernReportPanel report={report} onDone={() => setFlow("idle")} />
        )}
      </div>

      {/* The detected agents, grouped, each with a per-item toggle. */}
      {groups.length > 0 && (
        <>
          <h2 className="section-head">Detected agents</h2>
          {groups.map((g) => (
            <div key={g.agent} style={{ marginBottom: 18 }}>
              <div className="muted small" style={{ margin: "0 0 6px", fontWeight: 600 }}>{g.label}</div>
              <div className="conn-list">
                {g.targets.map((t) => (
                  <TargetRow
                    key={t.id}
                    target={t}
                    surface={surface!}
                    busy={busy === t.id}
                    live={live}
                    onToggle={() => void toggleTarget(t)}
                    onOpenPermissions={onOpenPermissions}
                  />
                ))}
              </div>
            </div>
          ))}
        </>
      )}

      {/* Advanced — the old catalog, for the rare manual case. */}
      <div style={{ marginTop: 28 }}>
        <button className="link" onClick={() => setAdvanced((v) => !v)}>
          <Icon name={advanced ? "chevron-down" : "chevron-right"} size={13} /> Advanced — add a connection manually
        </button>
        {advanced && (
          <div style={{ marginTop: 14 }}>
            <p className="muted small" style={{ marginBottom: 12 }}>
              Wire one connector by hand. The reach hierarchy goes <strong>kriya-native</strong> (most
              precise) → <strong>proxy</strong> any MCP server → <strong>reach-in / computer-use</strong>{" "}
              (most universal). Desktop permissions live in{" "}
              <button className="link" onClick={onOpenPermissions}>Settings → Permissions</button>.
            </p>
            <div className="conn-catalog">
              {CATALOG.map((c) => (
                <button key={c.type} className="conn-type" onClick={() => setDraft(c.type)}>
                  <span className="conn-type-ico"><Icon name={c.icon} size={20} /></span>
                  <h3>{c.title}</h3>
                  <p>{c.tagline}</p>
                  <span className="fidelity">{c.fidelity}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {draft && (
        <ConnectionDrawer
          type={draft}
          live={live}
          apps={apps}
          status={status}
          onClose={() => {
            refresh();
            setDraft(null);
          }}
          onOpenPermissions={onOpenPermissions}
          onNavigate={onNavigate}
        />
      )}
    </div>
  );
}

/** One detected target row: label + state badge + the per-item govern/ungovern control. */
function TargetRow({
  target,
  surface,
  busy,
  live,
  onToggle,
  onOpenPermissions,
}: {
  target: GovernTarget;
  surface: GovernableSurface;
  busy: boolean;
  live: boolean;
  onToggle: () => void;
  onOpenPermissions: () => void;
}) {
  const icon: IconName = target.kind === "hook" ? "bolt" : target.kind === "desktop-apps" ? "desktop" : "server";
  const control = (() => {
    if (target.state === "governed") {
      return (
        <button className="btn small ghost" disabled={busy || !live} onClick={onToggle}>
          {busy ? "…" : "Ungovern"}
        </button>
      );
    }
    if (target.state === "ungoverned") {
      const canWire = isWireable(target, surface);
      return (
        <button
          className="btn small primary"
          disabled={busy || !live || !canWire}
          title={canWire ? undefined : "The seam binary isn't bundled in this build."}
          onClick={onToggle}
        >
          {busy ? "Governing…" : "Govern"}
        </button>
      );
    }
    if (target.state === "needs-permission") {
      return (
        <button className="btn small ghost" onClick={onOpenPermissions}>Grant…</button>
      );
    }
    return null; // out-of-scope-cloud — no action
  })();

  return (
    <div className="conn-row">
      <span className="conn-row-ico"><Icon name={icon} size={18} /></span>
      <div className="conn-row-main">
        <b>{target.label}</b>
        <span className="mono">{target.detail}</span>
      </div>
      <span className={`badge ${STATE_BADGE[target.state]}`}>{STATE_LABEL[target.state]}</span>
      {control}
    </div>
  );
}

/** The dry-run confirmation: exactly what govern-all will change, plus the honest non-actions. */
function GovernPreviewPanel({
  plan,
  busy,
  onApply,
  onCancel,
}: {
  plan: GovernPlan;
  busy: boolean;
  onApply: () => void;
  onCancel: () => void;
}) {
  return (
    <div>
      <div className="panel-head">
        <h2>Review changes</h2>
        <span className="muted small">{plan.wire.length} {plan.wire.length === 1 ? "change" : "changes"}</span>
      </div>
      {plan.wire.length === 0 ? (
        <p className="muted small" style={{ margin: 0 }}>Nothing to wire — everything detected is already governed or out of scope.</p>
      ) : (
        <ul className="how-steps" style={{ margin: "0 0 4px", paddingLeft: 20, lineHeight: 1.6 }}>
          {plan.wire.map((a) => (
            <li key={a.targetId}>
              <b>{a.action === "install-hook" ? "Install hook" : "Wrap MCP server"}</b>
              {a.configPath ? <> in <code>{a.configPath.split("/").pop()}</code></> : null} — {a.detail}
            </li>
          ))}
        </ul>
      )}
      {(plan.needsPermission.length > 0 || plan.outOfScopeCloud.length > 0) && (
        <p className="panel-note" style={{ background: "transparent", color: "var(--ink-subtle)" }}>
          {plan.needsPermission.length > 0 && <>{plan.needsPermission.length} surface(s) need a macOS grant first (not wired). </>}
          {plan.outOfScopeCloud.length > 0 && <>{plan.outOfScopeCloud.length} cloud-executed surface(s) are out of scope — no on-device receipt is possible.</>}
        </p>
      )}
      <div className="drawer-foot" style={{ padding: "14px 0 0", borderTop: "none" }}>
        <button className="btn ghost" onClick={onCancel}>Cancel</button>
        <button className="btn primary" disabled={busy || plan.wire.length === 0} onClick={onApply}>
          {busy ? "Applying…" : `Apply ${plan.wire.length} change${plan.wire.length === 1 ? "" : "s"}`}
        </button>
      </div>
    </div>
  );
}

/** The result of a govern-all run. */
function GovernReportPanel({ report, onDone }: { report: GovernAllReport | null; onDone: () => void }) {
  const wired = report?.wired.length ?? 0;
  const errors = report?.errors ?? [];
  return (
    <div>
      <div className="panel-head">
        <h2>{errors.length === 0 ? "Governed" : "Governed (with issues)"}</h2>
        <span className="vstat ok"><Icon name="check" size={15} /> {wired} wired</span>
      </div>
      <p className="muted small" style={{ margin: "0 0 6px" }}>
        {report
          ? <>{wired} surface{wired === 1 ? "" : "s"} wired. Drive your agents, then watch the receipts land in the Coverage map.</>
          : <>Governed everything wireable. Drive your agents, then watch the receipts land in the Coverage map.</>}
      </p>
      {errors.length > 0 && (
        <ul className="how-steps warn-text" style={{ margin: "0 0 6px", paddingLeft: 20 }}>
          {errors.map((e) => <li key={e.targetId}>{e.targetId}: {e.message}</li>)}
        </ul>
      )}
      <div className="drawer-foot" style={{ padding: "14px 0 0", borderTop: "none" }}>
        <button className="btn primary" onClick={onDone}>Done</button>
      </div>
    </div>
  );
}

function ConnectionDrawer({
  type,
  live,
  apps,
  status,
  onClose,
  onOpenPermissions,
  onNavigate,
}: {
  type: ConnType;
  live: boolean;
  apps: string[];
  status: OnboardingStatus | null;
  onClose: () => void;
  onOpenPermissions: () => void;
  onNavigate: (v: View) => void;
}) {
  const meta = CATALOG.find((c) => c.type === type)!;
  const drawerRef = useRef<HTMLDivElement>(null);
  const [command, setCommand] = useState("");
  const [name, setName] = useState("");
  const [app, setApp] = useState("");
  const [mode, setMode] = useState<DesktopMode>("reach-in");
  const [result, setResult] = useState<WireResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  // Esc closes the drawer (mirrors the command palette); move focus into it on open.
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", h);
    drawerRef.current?.focus();
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const needsApp = type === "desktop" && (mode === "reach-in" || mode === "router");
  const ready = useMemo(() => {
    if (type === "kriya" || type === "proxy") return command.trim().length > 0;
    if (type === "desktop") return mode === "computer-use" || app.trim().length > 0;
    return false;
  }, [type, command, mode, app]);

  function buildRequest(): WireRequest {
    if (type === "proxy") {
      return { front: "proxy", approval: "gui", downstream: command.trim().split(/\s+/).filter(Boolean) };
    }
    if (type === "kriya") {
      const parts = command.trim().split(/\s+/).filter(Boolean);
      return { front: "kriya", approval: "gui", app: name.trim() || undefined, downstream: parts };
    }
    // desktop
    const req: WireRequest = { front: mode, approval: "gui" };
    if (mode === "reach-in" || mode === "router") req.app = app.trim() || undefined;
    return req;
  }

  async function wire() {
    setErr(null);
    setResult(null);
    if (!live) {
      setErr("Wiring runs in the desktop app — this is a preview.");
      return;
    }
    setWorking(true);
    try {
      setResult(await wireClaudeConfig(buildRequest()));
    } catch (e) {
      setErr(String(e));
    } finally {
      setWorking(false);
    }
  }

  const access = status?.accessibilityTrusted;

  return (
    <div className="drawer-backdrop" onMouseDown={onClose}>
      <div
        className="drawer"
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        aria-label={meta.title}
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="drawer-head">
          <div>
            <h2>{meta.title}</h2>
            <p>{meta.tagline}</p>
          </div>
          <button className="x-btn" onClick={onClose} aria-label="Close"><Icon name="x" size={18} /></button>
        </div>

        <div className="drawer-body">
          <HowItWorks type={type} />
          {type === "kriya" && (
            <>
              <div className="field">
                <label className="field-label">Server command</label>
                <input className="mono" placeholder="kriya-mcp --policy agent-policy.yaml" value={command} onChange={(e) => setCommand(e.target.value)} />
                <span className="field-hint">The kriya-instrumented MCP server to launch. It governs + signs its own named actions in-process — no gateway wrapper needed.</span>
              </div>
              <div className="field">
                <label className="field-label">Display name <span className="subtle">(optional)</span></label>
                <input placeholder="e.g. Ledger" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
            </>
          )}

          {type === "proxy" && (
            <div className="field">
              <label className="field-label">Downstream command</label>
              <input className="mono" placeholder="node actual-mcp-server.js" value={command} onChange={(e) => setCommand(e.target.value)} />
              <span className="field-hint">The existing MCP server to wrap. The gateway launches it and interposes governance — everything after <code>--</code>, passed through untouched.</span>
            </div>
          )}

          {type === "desktop" && (
            <>
              <div className="field">
                <label className="field-label">Reach</label>
                <select value={mode} onChange={(e) => setMode(e.target.value as DesktopMode)}>
                  <option value="reach-in">Reach-in — accessibility tree (named controls)</option>
                  <option value="computer-use">Computer-use — pixels (any app, the floor)</option>
                  <option value="router">Router — computer-use floor + one reach-in app</option>
                </select>
                <span className="field-hint">Reach-in synthesizes typed tools from the macOS accessibility tree; computer-use is the universal pixel floor.</span>
              </div>
              {needsApp && (
                <div className="field">
                  <label className="field-label">Target app</label>
                  <input list="conn-apps" placeholder="e.g. Numbers" value={app} onChange={(e) => setApp(e.target.value)} />
                  <datalist id="conn-apps">{apps.map((a) => <option key={a} value={a} />)}</datalist>
                </div>
              )}

              <div>
                <label className="field-label">macOS permissions</label>
                <PermStep
                  label="Accessibility"
                  need={mode === "reach-in" || mode === "router"}
                  granted={access}
                  onOpen={() => live && void openSettingsPane("accessibility")}
                />
                <PermStep
                  label="Screen Recording"
                  need={mode === "computer-use" || mode === "router"}
                  granted={null}
                  onOpen={() => live && void openSettingsPane("screen-recording")}
                />
                <p className="field-hint" style={{ marginTop: 8 }}>
                  Grant <code>Kriya Console.app</code> — the bundled gateway shares its signing identity. Full walk in{" "}
                  <button className="link" onClick={() => { onClose(); onOpenPermissions(); }}>Settings → Permissions</button>.
                </p>
              </div>
            </>
          )}

          {err && <p className="warn-text small">{err}</p>}
          {result && (
            <div className="field">
              <p className="vstat ok"><Icon name="check" size={15} /> Wired <code>{result.serverKey}</code> into your MCP client.</p>
              <pre className="snippet">{result.snippet}</pre>
              <button className="btn small ghost" onClick={() => void navigator.clipboard.writeText(result.snippet)}>
                <Icon name="copy" size={13} /> Copy snippet
              </button>
              <ol className="how-steps" style={{ margin: "10px 0 0", paddingLeft: 20, lineHeight: 1.5 }}>
                <li>
                  <b>Fully quit and reopen</b> your MCP client — it reads{" "}
                  <code>{result.configPath.split("/").pop()}</code> only at launch.
                </li>
                <li>
                  Drive the connected app, then watch the first signed receipt land in the{" "}
                  <button className="link" onClick={() => onNavigate("monitor")}>Monitor</button>.
                </li>
              </ol>
            </div>
          )}
        </div>

        <div className="drawer-foot">
          <button className="btn ghost" onClick={onClose}>{result ? "Done" : "Cancel"}</button>
          {!result && (
            <button className="btn primary" disabled={!ready || working} onClick={() => void wire()}>
              {working ? "Wiring…" : "Wire connection"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/** Per-connector "How this works" — a short numbered explainer so the connector flow is legible inline. */
function HowItWorks({ type }: { type: ConnType }) {
  const steps: Record<ConnType, ReactNode[]> = {
    kriya: [
      <>Point it at a kriya-instrumented MCP server, e.g. <code>kriya-mcp --policy agent-policy.yaml</code>.</>,
      <>It governs and signs its own real named actions in-process.</>,
      <>Your MCP client launches it directly — no gateway wrapper needed.</>,
    ],
    proxy: [
      <>Paste the existing MCP server's launch command (everything after <code>--</code>).</>,
      <>The bundled gateway wraps it: every tool call routes through policy → approval → signed receipt.</>,
      <>Zero changes to that server.</>,
    ],
    desktop: [
      <><b>Reach-in</b> drives the app's macOS accessibility tree (named controls) — needs Accessibility.</>,
      <><b>Computer-use</b> drives any app by pixels — needs Screen Recording.</>,
      <><b>Router</b> combines the computer-use floor with one reach-in app. Grant the permissions below.</>,
    ],
  };
  return (
    <div className="field">
      <label className="field-label">How this works</label>
      <ol className="how-steps" style={{ margin: "4px 0 0", paddingLeft: 20, lineHeight: 1.5 }}>
        {steps[type].map((s, i) => (
          <li key={i} style={{ marginBottom: 4 }}>{s}</li>
        ))}
      </ol>
    </div>
  );
}

function PermStep({ label, need, granted, onOpen }: { label: string; need: boolean; granted: boolean | null | undefined; onOpen: () => void }) {
  if (!need) {
    return (
      <div className="step-row">
        <span className="step-state subtle"><Icon name="check" size={14} /></span>
        <div className="step-row-main"><b>{label}</b><span>not needed for this reach</span></div>
      </div>
    );
  }
  const ok = granted === true;
  return (
    <div className="step-row">
      <span className={`step-state ${ok ? "ok-text" : "warn-text"}`}>
        <Icon name={ok ? "check" : "clock"} size={15} />
      </span>
      <div className="step-row-main">
        <b>{label}</b>
        <span>{granted == null ? "grant required" : ok ? "granted" : "not granted yet"}</span>
      </div>
      {!ok && <button className="btn small ghost" onClick={onOpen}>Open settings</button>}
    </div>
  );
}
