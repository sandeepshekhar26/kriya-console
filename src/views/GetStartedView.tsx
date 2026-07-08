import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Icon } from "../components/Icon";
import {
  governableSurface,
  isTauri,
  licenseStatus,
  onboardingStatus,
  type GovernableSurface,
  type LicenseStatus,
  type OnboardingStatus,
} from "../lib/tauri";
import type { View } from "../components/Sidebar";
import type { SettingsPane } from "./SettingsView";

export const ONBOARDED_KEY = "kriya-console:onboarded";

// Browser/preview status so the checklist renders outside the desktop app (a fresh, nothing-done state).
const PREVIEW_STATUS: OnboardingStatus = {
  gatewayPresent: true,
  gatewayPath: null,
  gatewayBundled: true,
  accessibilityTrusted: false,
  claudeConfigPath: "~/Library/Application Support/Claude/claude_desktop_config.json",
  claudeConfigExists: false,
  wiredServers: [],
  auditDir: "~/.kriya/audit",
  auditLogs: 0,
  policyPresent: false,
};

type Step = {
  n: number;
  title: string;
  body: ReactNode;
  done: boolean;
  ctaLabel: string;
  onCta: () => void;
  optional?: boolean;
};

/**
 * Get Started — the first-run checklist that turns "downloaded the app" into "governing live." It reads
 * the real backend state (onboardingStatus + licenseStatus) and ticks each step as it's completed, with a
 * CTA that deep-links into the surface that does it. Required steps 1–3 (permissions → connector → first
 * rule) mark the user onboarded; the license step is optional (the free tier is fully usable).
 */
export function GetStartedView({
  onNavigate,
  goSettings,
}: {
  onNavigate: (v: View) => void;
  goSettings: (pane: SettingsPane) => void;
}) {
  const live = isTauri();
  const [status, setStatus] = useState<OnboardingStatus | null>(live ? null : PREVIEW_STATUS);
  const [surface, setSurface] = useState<GovernableSurface | null>(null);
  const [license, setLicense] = useState<LicenseStatus | null>(null);

  const refresh = useCallback(() => {
    if (!live) return;
    void onboardingStatus().then(setStatus).catch(() => {});
    void governableSurface().then(setSurface).catch(() => {});
    void licenseStatus().then(setLicense).catch(() => {});
  }, [live]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const access = status?.accessibilityTrusted === true;
  // Step 2 is "at least one lane governed" (GA-1): a Claude Code hook, a wrapped MCP server, or any
  // governed target across agents — not just the legacy gateway-wrapped Claude Desktop servers.
  const hasConnector =
    (surface?.targets.some((t) => t.state === "governed") ?? false) ||
    (status?.wiredServers?.length ?? 0) > 0;
  const hasPolicy = status?.policyPresent === true;
  const isPro = license?.tier === "pro";
  const requiredDone = access && hasConnector && hasPolicy;

  // Once the required steps are green, remember it so the app stops auto-opening here (SETUP-3).
  useEffect(() => {
    if (!requiredDone) return;
    try {
      localStorage.setItem(ONBOARDED_KEY, "1");
    } catch {
      /* storage unavailable — non-fatal */
    }
  }, [requiredDone]);

  const steps: Step[] = [
    {
      n: 1,
      title: "Grant macOS permissions",
      done: access,
      ctaLabel: access ? "Re-check" : "Open permissions",
      onCta: () => goSettings("permissions"),
      body: (
        <>
          Governing a desktop app needs macOS access: <strong>reach-in</strong> needs Accessibility, and{" "}
          <strong>computer-use</strong> also needs Screen Recording. Grant <code>Kriya Console.app</code> —
          the bundled gateway shares its signing identity — then come back and press{" "}
          <strong>Re-check</strong>. Screen Recording can't be auto-detected, so re-check after granting it.
        </>
      ),
    },
    {
      n: 2,
      title: "Govern everything (one click)",
      done: hasConnector,
      ctaLabel: "Govern everything",
      onCta: () => onNavigate("connections"),
      body: (
        <>
          Kriya detects every governable agent on this machine — Claude Code (the hook), Claude Desktop and
          Hermes (local MCP servers) — and wires each through its seam in one click. You'll preview exactly
          what changes first; nothing is written until you confirm, and every step is reversible. Then watch
          the first signed receipts land in the Monitor.
        </>
      ),
    },
    {
      n: 3,
      title: "Author your first policy rule",
      done: hasPolicy,
      ctaLabel: "Open Policy",
      onCta: () => onNavigate("policy"),
      body: (
        <>
          Author the <code>agent-policy.yaml</code> the runtime enforces — ordered{" "}
          <strong>allow / require-approval / deny</strong> rules, first match wins, no match = deny. Until
          you add one, everything is denied by default.
        </>
      ),
    },
    {
      n: 4,
      optional: true,
      title: "Activate a license",
      done: isPro,
      ctaLabel: isPro ? "Manage license" : "Activate a license",
      onCta: () => goSettings("license"),
      body: (
        <>
          Optional — the free tier is fully usable (live monitor, offline verification, connections, this
          guide). A license adds <strong>Evidence export</strong> and <strong>Fleet correlation</strong>.
          Nothing leaves your machine either way.
        </>
      ),
    },
  ];

  const requiredSteps = steps.filter((s) => !s.optional);
  const doneCount = requiredSteps.filter((s) => s.done).length;

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Get started</h1>
          <p className="page-sub">
            {requiredDone
              ? "You're governing live. Re-run any step below, or jump to the Monitor."
              : "Three steps to live, signed governance — everything stays on this machine."}
          </p>
        </div>
        <div className="page-actions">
          {live && (
            <button className="btn ghost" onClick={refresh}>
              <Icon name="refresh" size={14} /> Re-check
            </button>
          )}
          <button className="btn ghost" onClick={() => onNavigate("monitor")}>
            Go to Monitor
          </button>
        </div>
      </header>

      {!live && (
        <div className="evidence-bar" style={{ marginBottom: 24 }}>
          <span className="prov">
            <Icon name="info" size={15} />
            Setup runs in the desktop app (it grants macOS permissions and wires your MCP client). This is
            a design preview.
          </span>
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <h2>Setup checklist</h2>
          <span className="muted small">{doneCount} of {requiredSteps.length} required steps complete</span>
        </div>
        {steps.map((s) => (
          <div className="step-row" key={s.n}>
            <span className={`step-state ${s.done ? "ok-text" : s.optional ? "subtle" : "warn-text"}`}>
              <Icon name={s.done ? "check" : "clock"} size={16} />
            </span>
            <div className="step-row-main">
              <b>
                {s.n}. {s.title}
                {s.optional && <span className="subtle"> · optional</span>}
                {s.done && <span className="badge ok" style={{ marginLeft: 8 }}>done</span>}
              </b>
              <span>{s.body}</span>
            </div>
            <button className="btn small ghost" onClick={s.onCta}>
              {s.ctaLabel}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
