import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  isTauri,
  listCandidateApps,
  onboardingStatus,
  openSettingsPane,
  wireClaudeConfig,
  type OnboardingStatus,
  type WireRequest,
  type WireResult,
} from "../lib/tauri";
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

const MODE_LABEL: Record<string, string> = {
  "kriya-proxy": "MCP proxy",
  "kriya-computer-use": "Computer-use",
  "kriya-router": "Router",
};
function modeOf(key: string): string {
  if (MODE_LABEL[key]) return MODE_LABEL[key]!;
  if (key.startsWith("kriya-native-")) return "kriya-native";
  return "Reach-in";
}

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

/**
 * Connections — the governed-MCP manager (the activation surface). Add/manage connections across the
 * reach hierarchy: kriya-native (bolt-on) → proxy (wrap any MCP server) → desktop (reach-in /
 * computer-use). Each writes a governed entry into claude_desktop_config.json (via the compiled
 * backend) and walks the macOS permissions a front needs.
 */
export function ConnectionsView({
  onNavigate,
  onOpenPermissions,
}: {
  onNavigate: (v: View) => void;
  onOpenPermissions: () => void;
}) {
  const live = isTauri();
  const [status, setStatus] = useState<OnboardingStatus | null>(live ? null : PREVIEW_STATUS);
  const [apps, setApps] = useState<string[]>([]);
  const [draft, setDraft] = useState<ConnType | null>(null);

  const refresh = useCallback(() => {
    if (!live) return;
    void onboardingStatus().then(setStatus).catch(() => {});
    void listCandidateApps().then(setApps).catch(() => setApps([]));
  }, [live]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const wired = status?.wiredServers ?? [];

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Connections</h1>
          <p className="page-sub">
            Govern every agent connection. Each is wired into your MCP client and signs every action to{" "}
            <code>~/.kriya/audit/</code> — where the Monitor verifies it.
          </p>
        </div>
        <div className="page-actions">
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
            Wiring runs in the desktop app (it edits <code>claude_desktop_config.json</code> and grants macOS permissions). This is a design preview.
          </span>
        </div>
      )}

      {/* Wired connections */}
      {wired.length > 0 && (
        <>
          <h2 className="section-head">Active connections</h2>
          <div className="conn-list">
            {wired.map((key) => (
              <div className="conn-row" key={key}>
                <span className="conn-row-ico"><Icon name={iconForMode(modeOf(key))} size={18} /></span>
                <div className="conn-row-main">
                  <b>{key}</b>
                  <span className="mono">→ kriya-gateway · {status?.claudeConfigPath?.split("/").pop()}</span>
                </div>
                <span className="conn-mode">{modeOf(key)}</span>
                <span className="vstat ok"><span className="dot live" /> governed</span>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Catalog */}
      <h2 className="section-head">{wired.length > 0 ? "Add a connection" : "Add your first connection"}</h2>
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

      <p className="muted small" style={{ marginTop: 16 }}>
        New to this? The reach hierarchy goes <strong>kriya-native</strong> (most precise) →{" "}
        <strong>proxy</strong> → <strong>reach-in / computer-use</strong> (most universal). Permissions
        for desktop apps are managed in <button className="link" onClick={onOpenPermissions}>Settings → Permissions</button>.
        {wired.length === 0 && (
          <> Prefer a guided walkthrough? <button className="link" onClick={() => onNavigate("getstarted")}>Open Get started</button>.</>
        )}
      </p>

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

function iconForMode(mode: string): IconName {
  if (mode === "MCP proxy") return "server";
  if (mode === "kriya-native") return "bolt";
  return "desktop";
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
