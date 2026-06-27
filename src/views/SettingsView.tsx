import { useCallback, useEffect, useState } from "react";
import {
  installLicense,
  isTauri,
  onboardingStatus,
  openSettingsPane,
  removeLicense,
  type LicenseStatus,
  type OnboardingStatus,
} from "../lib/tauri";
import { Icon, type IconName } from "../components/Icon";

export type SettingsPane = "appearance" | "shortcuts" | "license" | "permissions" | "advanced";

const RAIL: { label: string; items: { id: SettingsPane; label: string; icon: IconName }[] }[] = [
  {
    label: "Preferences",
    items: [
      { id: "appearance", label: "Appearance", icon: "sun" },
      { id: "shortcuts", label: "Shortcuts", icon: "monitor" },
    ],
  },
  { label: "Account", items: [{ id: "license", label: "License", icon: "key" }] },
  {
    label: "Developer",
    items: [
      { id: "permissions", label: "Permissions", icon: "lock" },
      { id: "advanced", label: "Advanced", icon: "folder" },
    ],
  },
];

export function SettingsView({
  pane,
  onPaneChange,
  theme,
  onThemeChange,
  license,
  onLicenseChange,
}: {
  pane: SettingsPane;
  onPaneChange: (p: SettingsPane) => void;
  theme: "dark" | "light";
  onThemeChange: (t: "dark" | "light") => void;
  license: LicenseStatus | null;
  onLicenseChange: (s: LicenseStatus) => void;
}) {
  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="page-sub">Preferences, license, and the developer plumbing — connections and permissions for the governed fronts.</p>
        </div>
      </header>

      <div className="settings-shell">
        <nav className="settings-rail">
          {RAIL.map((g) => (
            <div key={g.label}>
              <div className="settings-rail-label">{g.label}</div>
              {g.items.map((it) => (
                <button
                  key={it.id}
                  className={`settings-rail-item ${pane === it.id ? "active" : ""}`}
                  onClick={() => onPaneChange(it.id)}
                >
                  <Icon name={it.icon} size={15} />
                  {it.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="settings-pane">
          {pane === "appearance" && <AppearancePane theme={theme} onThemeChange={onThemeChange} />}
          {pane === "shortcuts" && <ShortcutsPane />}
          {pane === "license" && <LicensePane license={license} onLicenseChange={onLicenseChange} />}
          {pane === "permissions" && <PermissionsPane />}
          {pane === "advanced" && <AdvancedPane />}
        </div>
      </div>
    </div>
  );
}

function AppearancePane({ theme, onThemeChange }: { theme: "dark" | "light"; onThemeChange: (t: "dark" | "light") => void }) {
  return (
    <section className="set-section">
      <h2>Appearance</h2>
      <p>Light is the first-class theme; dark is a faithful token swap.</p>
      <div className="set-row">
        <div className="set-row-main">
          <b>Theme</b>
          <span>Applies instantly and persists across launches.</span>
        </div>
        <div className="set-row-control">
          <div className="segmented">
            <button className={theme === "light" ? "active" : ""} onClick={() => onThemeChange("light")}>
              <Icon name="sun" size={14} /> Light
            </button>
            <button className={theme === "dark" ? "active" : ""} onClick={() => onThemeChange("dark")}>
              <Icon name="moon" size={14} /> Dark
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

function ShortcutsPane() {
  const rows: [string, string[]][] = [
    ["Open command palette", ["⌘", "K"]],
    ["Navigate / run command", ["↑", "↓", "↵"]],
    ["Close palette / dialog", ["Esc"]],
  ];
  return (
    <section className="set-section">
      <h2>Keyboard</h2>
      <p>The command palette is the fastest way to move and act across the console.</p>
      {rows.map(([label, keys]) => (
        <div className="set-row" key={label}>
          <div className="set-row-main"><b>{label}</b></div>
          <div className="set-row-control cmdk-shortcut">
            {keys.map((k) => <span className="kbd" key={k}>{k}</span>)}
          </div>
        </div>
      ))}
    </section>
  );
}

function LicensePane({ license, onLicenseChange }: { license: LicenseStatus | null; onLicenseChange: (s: LicenseStatus) => void }) {
  const live = isTauri();
  const [token, setToken] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const pro = license?.tier === "pro";

  async function activate() {
    setErr(null);
    try {
      const s = await installLicense(token.trim());
      onLicenseChange(s);
      setToken("");
    } catch (e) {
      setErr(String(e));
    }
  }
  async function deactivate() {
    onLicenseChange(await removeLicense());
  }

  return (
    <section className="set-section">
      <h2>License</h2>
      <p>The free tier is the live monitor, on-device verification, and guided setup. A license unlocks the compliance tier — verified offline, nothing uploaded.</p>

      {pro ? (
        <>
          <div className="set-row">
            <div className="set-row-main">
              <b>Pro · {license?.holder}</b>
              <span>
                {license?.expiresMs ? `Expires ${new Date(license.expiresMs).toLocaleDateString()}` : "Perpetual"} · unlocks {license?.features.join(", ")}.
              </span>
            </div>
            <div className="set-row-control"><span className="badge ok"><Icon name="check" size={13} /> Active</span></div>
          </div>
          <div className="set-row">
            <div className="set-row-main"><b>Remove license</b><span>Return to the free tier on this machine.</span></div>
            <div className="set-row-control"><button className="btn ghost" onClick={() => void deactivate()}>Remove</button></div>
          </div>
        </>
      ) : (
        <>
          <div className="set-row" style={{ display: "block" }}>
            <div className="set-row-main" style={{ marginBottom: 10 }}>
              <b>Activate a license</b>
              <span>Paste a license token to unlock Evidence export + Fleet correlation.</span>
            </div>
            {!live ? (
              <p className="muted small">Activation runs in the desktop app — the token is verified offline in the compiled backend.</p>
            ) : (
              <>
                <textarea
                  className="mono"
                  style={{ width: "100%", minHeight: 110, resize: "vertical" }}
                  value={token}
                  placeholder='{ "license": { ... }, "signature": "..." }'
                  onChange={(e) => setToken(e.target.value)}
                />
                <div className="page-actions" style={{ marginTop: 10 }}>
                  <button className="btn primary" disabled={!token.trim()} onClick={() => void activate()}>Activate</button>
                </div>
              </>
            )}
            {err && <p className="warn-text small">{err}</p>}
            {license?.reason && <p className="warn-text small">Installed license rejected: {license.reason}</p>}
          </div>
        </>
      )}
    </section>
  );
}

function PermissionsPane() {
  const live = isTauri();
  const [status, setStatus] = useState<OnboardingStatus | null>(null);

  const refresh = useCallback(() => {
    if (live) void onboardingStatus().then(setStatus).catch(() => {});
  }, [live]);
  useEffect(() => { refresh(); }, [refresh]);

  const access = status?.accessibilityTrusted;

  return (
    <section className="set-section">
      <h2>macOS permissions</h2>
      <p>Reach-in needs Accessibility; computer-use also needs Screen Recording. Grant <code>Kriya Console.app</code> — the bundled gateway shares its signing identity.</p>

      {!live && <p className="muted small">Permission state and the privacy-pane shortcuts are available in the desktop app.</p>}

      <div className="set-row">
        <div className="set-row-main">
          <b>Accessibility</b>
          <span>Required for reach-in (named controls from the accessibility tree).</span>
        </div>
        <div className="set-row-control">
          {live && (access == null ? <span className="badge">unknown</span> : access ? <span className="badge ok"><Icon name="check" size={13} /> granted</span> : <span className="badge warn">not granted</span>)}
          <button className="btn ghost" disabled={!live} onClick={() => void openSettingsPane("accessibility")}>Open</button>
        </div>
      </div>
      <div className="set-row">
        <div className="set-row-main">
          <b>Screen Recording</b>
          <span>Required for computer-use (the universal pixel floor).</span>
        </div>
        <div className="set-row-control">
          <button className="btn ghost" disabled={!live} onClick={() => void openSettingsPane("screen-recording")}>Open</button>
        </div>
      </div>
      {live && (
        <div className="page-actions" style={{ marginTop: 14 }}>
          <button className="btn ghost" onClick={refresh}><Icon name="refresh" size={14} /> Re-check</button>
        </div>
      )}
    </section>
  );
}

function AdvancedPane() {
  const live = isTauri();
  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  useEffect(() => {
    if (live) void onboardingStatus().then(setStatus).catch(() => {});
  }, [live]);

  const rows: [string, string | number | undefined][] = [
    ["Audit directory", status?.auditDir ?? "~/.kriya/audit"],
    ["Audit logs present", status?.auditLogs],
    ["MCP client config", status?.claudeConfigPath ?? "~/Library/Application Support/Claude/claude_desktop_config.json"],
    ["Bundled gateway", status?.gatewayPath ?? "inside the app bundle"],
    ["Wired servers", status?.wiredServers?.join(", ") || "—"],
  ];

  return (
    <section className="set-section">
      <h2>Advanced</h2>
      <p>The on-device locations the console reads and writes. Everything stays on this machine.</p>
      {!live && <p className="muted small">Live paths are resolved by the desktop backend.</p>}
      {rows.map(([k, v]) => (
        <div className="set-row" key={k}>
          <div className="set-row-main"><b>{k}</b></div>
          <div className="set-row-control"><span className="mono small muted" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v ?? "—"}</span></div>
        </div>
      ))}
    </section>
  );
}
