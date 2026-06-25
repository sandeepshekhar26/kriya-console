import { useCallback, useEffect, useState } from "react";
import {
  installLicense,
  isTauri,
  listCandidateApps,
  onboardingStatus,
  openSettingsPane,
  removeLicense,
  wireClaudeConfig,
  type LicenseStatus,
  type OnboardingStatus,
  type WireRequest,
  type WireResult,
} from "../lib/tauri";

type Front = WireRequest["front"];

/**
 * First-run onboarding (D-018): get from a clean machine to live governance — locate the bundled
 * gateway, grant the macOS privacy panes a front needs, wire the MCP client config, and activate a
 * license. Every action calls the compiled backend; the gateway ships inside this app.
 */
export function SetupView({
  license,
  onLicenseChange,
}: {
  license: LicenseStatus | null;
  onLicenseChange: (s: LicenseStatus) => void;
}) {
  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  const [apps, setApps] = useState<string[]>([]);
  const [front, setFront] = useState<Front>("reach-in");
  const [app, setApp] = useState("");
  const [downstream, setDownstream] = useState("");
  const [wire, setWire] = useState<WireResult | null>(null);
  const [wireErr, setWireErr] = useState<string | null>(null);
  const [token, setToken] = useState("");
  const [licErr, setLicErr] = useState<string | null>(null);

  const refresh = useCallback(() => {
    if (!isTauri()) return;
    void onboardingStatus().then(setStatus);
    void listCandidateApps().then(setApps).catch(() => setApps([]));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (!isTauri()) {
    return (
      <div className="view">
        <header className="page-head">
          <h1>Setup</h1>
        </header>
        <section className="panel">
          <p className="muted">
            Onboarding runs inside the desktop app. Launch the Kriya Console app (<code>npm run tauri dev</code>)
            to grant permissions, wire the MCP client, and activate a license.
          </p>
        </section>
      </div>
    );
  }

  async function doWire() {
    setWireErr(null);
    setWire(null);
    const req: WireRequest = { front, approval: "gui" };
    if (front === "reach-in" || front === "router") req.app = app.trim() || undefined;
    if (front === "proxy") {
      const parts = downstream.trim().split(/\s+/).filter(Boolean);
      req.downstream = parts.length ? parts : undefined;
    }
    try {
      setWire(await wireClaudeConfig(req));
      refresh();
    } catch (e) {
      setWireErr(String(e));
    }
  }

  async function activate() {
    setLicErr(null);
    try {
      const s = await installLicense(token.trim());
      onLicenseChange(s);
      setToken("");
    } catch (e) {
      setLicErr(String(e));
    }
  }

  async function deactivate() {
    onLicenseChange(await removeLicense());
  }

  const access = status?.accessibilityTrusted;

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Setup</h1>
          <p className="page-sub">
            From a clean Mac to live, signed governance — grant the gateway what it needs and wire your
            MCP client. The gateway ships inside this app.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn ghost" onClick={refresh}>
            Refresh
          </button>
        </div>
      </header>

      {/* 1 — Gateway */}
      <section className="panel setup-step">
        <div className="step-head">
          <span className={`step-dot ${status?.gatewayPresent ? "ok" : "bad"}`} />
          <h2>1 · Gateway</h2>
        </div>
        {status?.gatewayPresent ? (
          <p className="muted small">
            Bundled gateway found{status.gatewayBundled ? " (inside the app bundle)" : ""}:{" "}
            <code>{status.gatewayPath}</code>
          </p>
        ) : (
          <p className="warn-text small">Gateway binary not found — rebuild the app bundle.</p>
        )}
      </section>

      {/* 2 — Permissions */}
      <section className="panel setup-step">
        <div className="step-head">
          <span className={`step-dot ${access ? "ok" : access === false ? "warn" : ""}`} />
          <h2>2 · Permissions (macOS)</h2>
        </div>
        <p className="muted small">
          Reach-in needs <strong>Accessibility</strong>; computer-use also needs{" "}
          <strong>Screen Recording</strong>. Grant <code>Kriya Console.app</code> in the pane, then
          Refresh.
        </p>
        <p className="kv-line">
          Accessibility:{" "}
          {access == null ? (
            <span className="muted">unknown</span>
          ) : access ? (
            <span className="ok-text">✓ trusted</span>
          ) : (
            <span className="warn-text">not granted</span>
          )}
        </p>
        <div className="btn-row">
          <button className="btn" onClick={() => void openSettingsPane("accessibility")}>
            Open Accessibility settings
          </button>
          <button className="btn ghost" onClick={() => void openSettingsPane("screen-recording")}>
            Open Screen Recording settings
          </button>
        </div>
      </section>

      {/* 3 — Wire the MCP client */}
      <section className="panel setup-step">
        <div className="step-head">
          <span className={`step-dot ${status && status.wiredServers.length > 0 ? "ok" : ""}`} />
          <h2>3 · Connect an app to your agent</h2>
        </div>
        <p className="muted small">
          Writes a governed front into your MCP client config (
          <code>{status?.claudeConfigPath ?? "claude_desktop_config.json"}</code>), pointed at the
          bundled gateway. Restart the client to pick it up.
        </p>
        <div className="form-row">
          <label>
            Front
            <select value={front} onChange={(e) => setFront(e.target.value as Front)}>
              <option value="reach-in">reach-in (uninstrumented app via accessibility)</option>
              <option value="computer-use">computer-use (any app, pixels — the floor)</option>
              <option value="router">router (computer-use floor + a reach-in app)</option>
              <option value="proxy">proxy (an app that already speaks MCP)</option>
            </select>
          </label>
          {(front === "reach-in" || front === "router") && (
            <label>
              App
              <input
                list="candidate-apps"
                value={app}
                placeholder="e.g. Numbers"
                onChange={(e) => setApp(e.target.value)}
              />
              <datalist id="candidate-apps">
                {apps.map((a) => (
                  <option key={a} value={a} />
                ))}
              </datalist>
            </label>
          )}
          {front === "proxy" && (
            <label className="grow">
              Downstream command
              <input
                value={downstream}
                placeholder="node actual-mcp-server.js"
                onChange={(e) => setDownstream(e.target.value)}
              />
            </label>
          )}
        </div>
        <div className="btn-row">
          <button className="btn primary" onClick={() => void doWire()}>
            Wire it into Claude Desktop
          </button>
        </div>
        {wireErr && <p className="warn-text small">{wireErr}</p>}
        {wire && (
          <div className="wire-result">
            <p className="ok-text small">
              ✓ Wired <code>{wire.serverKey}</code> into <code>{wire.configPath}</code>
            </p>
            <pre className="snippet">{wire.snippet}</pre>
            <button
              className="btn ghost small"
              onClick={() => void navigator.clipboard.writeText(wire.snippet)}
            >
              Copy snippet
            </button>
          </div>
        )}
        {status && status.wiredServers.length > 0 && (
          <p className="muted small">
            Already wired: {status.wiredServers.map((s) => <code key={s}>{s}</code>)}
          </p>
        )}
      </section>

      {/* 4 — Live audit */}
      <section className="panel setup-step">
        <div className="step-head">
          <span className={`step-dot ${status && status.auditLogs > 0 ? "ok" : ""}`} />
          <h2>4 · Watch governance live</h2>
        </div>
        <p className="muted small">
          The Console auto-discovers and tails <code>{status?.auditDir ?? "~/.kriya/audit/"}</code>.
          {status && status.auditLogs > 0
            ? ` ${status.auditLogs} log file(s) already present — open Overview or Audit log.`
            : " Drive a governed app and receipts appear here live — no import."}
        </p>
      </section>

      {/* 5 — License */}
      <section className="panel setup-step">
        <div className="step-head">
          <span className={`step-dot ${license?.tier === "pro" ? "ok" : ""}`} />
          <h2>5 · License (paid features)</h2>
        </div>
        {license?.tier === "pro" ? (
          <>
            <p className="ok-text small">
              ✓ Pro — licensed to <strong>{license.holder}</strong>
              {license.expiresMs ? ` · expires ${new Date(license.expiresMs).toLocaleDateString()}` : " · perpetual"}
            </p>
            <p className="muted small">Unlocks: {license.features.join(", ")}.</p>
            <button className="btn ghost small" onClick={() => void deactivate()}>
              Remove license (back to free)
            </button>
          </>
        ) : (
          <>
            <p className="muted small">
              Free tier: live monitor, receipt verification, onboarding. Paste a license token to
              unlock compliance export + fleet correlation. Verified offline — nothing is uploaded.
            </p>
            <textarea
              className="license-input"
              value={token}
              placeholder='{ "license": { ... }, "signature": "..." }'
              onChange={(e) => setToken(e.target.value)}
            />
            <div className="btn-row">
              <button className="btn primary" disabled={!token.trim()} onClick={() => void activate()}>
                Activate
              </button>
            </div>
            {licErr && <p className="warn-text small">{licErr}</p>}
          </>
        )}
      </section>
    </div>
  );
}
