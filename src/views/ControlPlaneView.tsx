import { useEffect, useMemo, useState, type ComponentType } from "react";
import { Icon } from "../components/Icon";
import { ControlPlaneDrillIn } from "./ControlPlaneDrillIn";
import { ControlPlanePolicyTab } from "./ControlPlanePolicyTab";
import { bundleHash } from "../lib/policyBundle";
import {
  computeDriftVerdict,
  driftSummaryLine,
  parsePolicyState,
  type DriftVerdict,
  type Json,
} from "../lib/policyDrift";
import {
  fleetConnect,
  fleetCoverage,
  fleetDeviceEvidence,
  fleetPolicyPreview,
  isTauri,
  licenseStatus,
  type DeviceAgentInfo,
  type DeviceCoverageRow,
  type DeviceInfo,
  type LicenseStatus,
} from "../lib/tauri";

/**
 * Control plane — the on-prem kriyad aggregator view (paid tier). Three states, doc 22 §8 BC-3:
 *
 *  (a) no `fleet-console` license flag  → the ORIGINAL "no aggregator connected" empty state,
 *      byte-for-byte unchanged. This is the default for every existing pro user; it must never move.
 *  (b) flag present, no saved connection → a connect form (server URL + CA/cert/key paths) that calls
 *      `fleet_connect`, surfacing its error verbatim.
 *  (c) flag present + connected          → the real fleet table, drill-in included.
 *
 * The `__KRIYA_DEMO__` seeded dashboard (ControlPlaneDemo.tsx) is untouched and still short-circuits
 * first, exactly as before — demo builds never reach the states below.
 */
export function ControlPlaneView() {
  const [Demo, setDemo] = useState<ComponentType | null>(null);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [licenseLoaded, setLicenseLoaded] = useState(false);

  useEffect(() => {
    if (!__KRIYA_DEMO__) return;
    let cancelled = false;
    void import("./ControlPlaneDemo").then((m) => {
      if (!cancelled) setDemo(() => m.default);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // License lookup only matters outside the demo build (state a/b/c below) — the demo build never
  // reads it (it always renders ControlPlaneDemo, matching the pre-P2 behavior exactly).
  useEffect(() => {
    if (__KRIYA_DEMO__) return;
    if (!isTauri()) {
      setLicenseLoaded(true);
      return;
    }
    let cancelled = false;
    licenseStatus()
      .then((s) => !cancelled && setLicense(s))
      .catch(() => {})
      .finally(() => !cancelled && setLicenseLoaded(true));
    return () => {
      cancelled = true;
    };
  }, []);

  if (__KRIYA_DEMO__) {
    return Demo ? <Demo /> : <div className="view" />;
  }

  const hasFleetConsole = !!license?.features?.includes("fleet-console");

  // State (a): no flag (or license not yet resolved in a non-Tauri/dev context) — the original empty
  // state, unchanged. Also the correct fallback while `licenseStatus()` is still in flight, so nothing
  // ever flashes a connect form before we actually know the flag is present.
  if (!licenseLoaded || !hasFleetConsole) {
    return <ControlPlaneEmpty />;
  }

  return <ControlPlaneCockpit />;
}

function ControlPlaneEmpty() {
  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>
            Control plane <span className="cp-tag"><Icon name="server" size={13} /> on-prem aggregator</span>
          </h1>
          <p className="page-sub">
            Your fleet's signed evidence, aggregated and re-verified on a box <b>you</b> control — inside
            your boundary, no egress. The engine is open; this cockpit is the paid tier.
          </p>
        </div>
      </header>

      <div className="empty" style={{ margin: "40px auto" }}>
        <div className="empty-ico"><Icon name="server" size={22} /></div>
        <p className="empty-title">No aggregator connected</p>
        <p>
          Point this Console at your on-prem <code>kriyad</code> (mTLS, no egress) to aggregate and
          re-verify your fleet's signed evidence across machines — trusting neither the devices nor the
          server. Nothing leaves your boundary.
        </p>
        <p className="muted small">
          Standing up an aggregator is part of the control-plane tier — see the kriyaD deploy guide.
        </p>
      </div>
    </div>
  );
}

// ── State (b)/(c): the real cockpit ──────────────────────────────────────────────────────────────────

type ConnState = "checking" | "disconnected" | "connected";

function ControlPlaneCockpit() {
  const [state, setState] = useState<ConnState>("checking");
  const [rows, setRows] = useState<DeviceCoverageRow[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  // Probe the saved connection by trying to pull coverage. No dedicated "am I connected" command
  // exists yet, so `fleet_coverage()` doubles as the probe: success ⇒ connected; failure ⇒ show the
  // connect form (the same form re-used whether there was never a connection or it just broke).
  const probe = useMemo(
    () => () => {
      setState("checking");
      setLoadErr(null);
      fleetCoverage()
        .then((r) => {
          setRows(r);
          setState("connected");
        })
        .catch((e) => {
          setLoadErr(String(e));
          setState("disconnected");
        });
    },
    [],
  );

  useEffect(() => {
    probe();
  }, [probe]);

  if (state === "checking") {
    return (
      <div className="view">
        <CockpitHeader />
        <div className="cp-line running" style={{ margin: "24px 0" }}>
          <span className="dot live" /> checking for a saved aggregator connection…
        </div>
      </div>
    );
  }

  if (state === "disconnected") {
    return <ConnectForm lastError={loadErr} onConnected={probe} />;
  }

  return <FleetCockpit initialRows={rows ?? []} onReconnectNeeded={probe} />;
}

function CockpitHeader() {
  return (
    <header className="page-head">
      <div>
        <h1>
          Control plane <span className="cp-tag"><Icon name="server" size={13} /> on-prem aggregator</span>
        </h1>
        <p className="page-sub">
          Your fleet's signed evidence, aggregated and re-verified on a box <b>you</b> control — inside
          your boundary, no egress. The engine is open; this cockpit is the paid tier.
        </p>
      </div>
    </header>
  );
}

// ── State (b): connect form ──────────────────────────────────────────────────────────────────────────

function ConnectForm({ lastError, onConnected }: { lastError: string | null; onConnected: () => void }) {
  const [url, setUrl] = useState("https://");
  const [ca, setCa] = useState("");
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const canSubmit = url.trim() && ca.trim() && cert.trim() && key.trim() && !busy;

  async function submit() {
    setBusy(true);
    setErr(null);
    try {
      await fleetConnect(url.trim(), ca.trim(), cert.trim(), key.trim());
      onConnected();
    } catch (e) {
      // Surface verbatim — never paraphrase, never a generic "connection failed" (doc 22 §8).
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="view">
      <CockpitHeader />

      <section className="panel" style={{ maxWidth: 560 }}>
        <div className="panel-head">
          <h2>Connect to your aggregator</h2>
        </div>
        <p className="muted small" style={{ margin: "0 0 14px" }}>
          mTLS only. Point this Console at the on-prem <code>kriyad</code> you control — no other route
          exists.
        </p>

        {(err || lastError) && (
          <div className="cp-line bad" style={{ marginBottom: 14 }}>
            <Icon name="x" size={15} />
            <div>
              <div className="cp-line-label">Connection failed</div>
              <div className="cp-line-detail">{err ?? lastError}</div>
            </div>
          </div>
        )}

        <div className="field" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="cp-url">Server URL</label>
          <input
            id="cp-url"
            type="text"
            placeholder="https://kriyad.internal:8443"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </div>

        <div className="field" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="cp-ca">CA certificate (PEM path)</label>
          <input
            id="cp-ca"
            type="text"
            placeholder="/path/to/ca.pem"
            value={ca}
            onChange={(e) => setCa(e.target.value)}
          />
        </div>

        <div className="field" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="cp-cert">Client certificate path</label>
          <input
            id="cp-cert"
            type="text"
            placeholder="/path/to/client-cert.pem"
            value={cert}
            onChange={(e) => setCert(e.target.value)}
          />
        </div>

        <div className="field" style={{ marginBottom: 16 }}>
          <label className="field-label" htmlFor="cp-key">Client key path</label>
          <input
            id="cp-key"
            type="text"
            placeholder="/path/to/client-key.pem"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
          <span className="field-hint">
            Paths are read directly on this machine — nothing here is uploaded anywhere.
          </span>
        </div>

        <button className="btn primary" disabled={!canSubmit} onClick={() => void submit()}>
          <Icon name="link" size={14} /> {busy ? "Connecting…" : "Connect"}
        </button>
      </section>
    </div>
  );
}

// ── State (c): the fleet table + drill-in ────────────────────────────────────────────────────────────

const STATUS_MAP = { current: "ok", behind: "warn", silent: "bad" } as const;
const STATUS_LABEL = { current: "current", behind: "behind", silent: "silent" } as const;

function FleetCockpit({
  initialRows,
  onReconnectNeeded,
}: {
  initialRows: DeviceCoverageRow[];
  onReconnectNeeded: () => void;
}) {
  const [rows, setRows] = useState<DeviceCoverageRow[]>(initialRows);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshErr, setRefreshErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<DeviceCoverageRow | null>(null);
  const [tab, setTab] = useState<"fleet" | "policy">("fleet");
  const [drift, setDrift] = useState<{
    latest: { version: number; bundle_hash: string } | null;
    verdicts: Record<string, DriftVerdict>;
    loading: boolean;
  }>({ latest: null, verdicts: {}, loading: true });

  useEffect(() => setRows(initialRows), [initialRows]);

  // P4 (doc 22 §9-CM) — the trust rule: every drift verdict is computed from RE-VERIFIED envelope data,
  // never from kriyad's `applied_policy_version`/`applied_bundle_hash` hint directly. Re-runs whenever
  // `rows` changes (initial load + every "Refresh").
  useEffect(() => {
    let cancelled = false;
    setDrift((d) => ({ ...d, loading: true }));

    async function computeAll() {
      // The fleet-wide "latest", locally hashed from the operator's own preview fetch — never trust
      // kriyad's `latest_bundle_version` hint alone for the actual comparison.
      let latest: { version: number; bundle_hash: string } | null = null;
      try {
        const preview = await fleetPolicyPreview();
        if (preview) {
          const hash = await bundleHash(preview.bundle as unknown as Record<string, Json>);
          latest = { version: preview.bundle.version, bundle_hash: hash };
        }
      } catch {
        // No reachable preview — every row falls back to "nothing to compare against" (grey).
      }

      const entries = await Promise.all(
        rows.map(async (d) => {
          let verifiedApplied: { version: number; bundle_hash: string } | null = null;
          if (d.last_seq > 0) {
            try {
              const evidence = await fleetDeviceEvidence(d.device_pub, d.last_seq, d.last_seq);
              const top = evidence.envelopes[evidence.envelopes.length - 1];
              if (top?.verified) {
                const ps = parsePolicyState(top.raw);
                if (ps) verifiedApplied = { version: ps.version, bundle_hash: ps.bundle_hash };
              }
              // An unverified/absent top envelope leaves verifiedApplied null — rendered as "never
              // applied"/grey rather than silently trusting kriyad's own hint instead.
            } catch {
              // Non-fatal — this row renders as if no verified data exists yet.
            }
          }
          const verdict = computeDriftVerdict({
            liveness: d.status,
            verifiedApplied,
            verifiedLatest: latest,
            hintAppliedVersion: d.applied_policy_version ?? null,
          });
          return [d.device_pub, verdict] as const;
        }),
      );

      if (!cancelled) {
        setDrift({ latest, verdicts: Object.fromEntries(entries), loading: false });
      }
    }

    void computeAll();
    return () => {
      cancelled = true;
    };
  }, [rows]);

  async function refresh() {
    setRefreshing(true);
    setRefreshErr(null);
    try {
      setRows(await fleetCoverage());
    } catch (e) {
      setRefreshErr(String(e));
    } finally {
      setRefreshing(false);
    }
  }

  const maxConsoleVersion = maxVersion(rows.map((r) => r.console_version));
  const maxRuntimeVersion = maxVersion(rows.map((r) => r.runtime_version));

  const counts = { current: 0, behind: 0, silent: 0 } as Record<string, number>;
  for (const r of rows) counts[r.status] = (counts[r.status] ?? 0) + 1;

  return (
    <div className="view">
      <CockpitHeader />

      <div className="segmented" style={{ marginBottom: 16 }}>
        <button className={tab === "fleet" ? "active" : undefined} onClick={() => setTab("fleet")}>
          <Icon name="fleet" size={13} /> Fleet
        </button>
        <button className={tab === "policy" ? "active" : undefined} onClick={() => setTab("policy")}>
          <Icon name="policy" size={13} /> Policy
        </button>
      </div>

      {tab === "policy" ? (
        <ControlPlanePolicyTab />
      ) : (
        <>
          <div className="cp-conn">
            <span className="dot live" />
            <code>kriyad</code>
            <span className="pill"><Icon name="lock" size={12} /> mTLS</span>
            <span className="pill">single-tenant</span>
            <span className="pill"><Icon name="shield-check" size={12} /> no egress</span>
            <span className="spacer" />
            {refreshErr && <span className="muted small" style={{ color: "var(--bad-text)" }}>{refreshErr}</span>}
            <button className="btn ghost small" onClick={() => void refresh()} disabled={refreshing}>
              <Icon name="refresh" size={13} /> {refreshing ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          <section className="stat-grid cp-stats">
            <Stat label="Devices" value={rows.length} />
            <Stat label="Current" value={counts.current ?? 0} tone="ok" />
            <Stat label="Behind" value={counts.behind ?? 0} tone={counts.behind ? "warn" : undefined} />
            <Stat label="Silent" value={counts.silent ?? 0} tone={counts.silent ? "bad" : undefined} />
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Fleet</h2>
              <span className="muted small">click a device for its signed evidence + inventory</span>
            </div>
            <p className="muted small" style={{ margin: "0 0 12px" }}>
              {drift.loading ? (
                <span className="cp-line running" style={{ padding: 0, border: "none", background: "none" }}>
                  <span className="dot live" /> re-verifying policy drift locally…
                </span>
              ) : (
                driftSummaryLine(drift.latest?.version ?? null, Object.values(drift.verdicts))
              )}
            </p>
            <div style={{ overflowX: "auto" }}>
              <table className="audit cp-cover">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Org / BU</th>
                    <th>Liveness</th>
                    <th>Console</th>
                    <th>Runtime</th>
                    <th>Agents</th>
                    <th>Policy</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((d) => (
                    <tr
                      key={d.device_pub}
                      onClick={() => setSelected(d)}
                      style={{ cursor: "pointer" }}
                    >
                      <td>
                        <div className="cp-dev">
                          <Icon name="desktop" size={14} className="muted" />
                          <span>{d.device_label || shortPub(d.device_pub)}</span>
                        </div>
                        <code className="cp-pub">{shortPub(d.device_pub)}</code>
                      </td>
                      <td>{orgBu(d)}</td>
                      <td><LivenessBadge status={d.status} /></td>
                      <td><VersionCell version={d.console_version} max={maxConsoleVersion} /></td>
                      <td><VersionCell version={d.runtime_version} max={maxRuntimeVersion} /></td>
                      <td><AgentsCell agents={d.agents} /></td>
                      <td>
                        <PolicyDriftCell verdict={drift.verdicts[d.device_pub]} loading={drift.loading} />
                      </td>
                      <td className="muted">{ago(d.last_seen_ms)}</td>
                    </tr>
                  ))}
                  {rows.length === 0 && (
                    <tr>
                      <td colSpan={8} className="muted small" style={{ textAlign: "center", padding: "24px 0" }}>
                        No devices have reported coverage to this aggregator yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          {selected && (
            <ControlPlaneDrillIn
              device={selected}
              info={coverageRowToDeviceInfo(selected)}
              verdict={drift.verdicts[selected.device_pub]}
              onClose={() => setSelected(null)}
            />
          )}

          {refreshErr && refreshErr.toLowerCase().includes("fleet-console") && (
            // A license/connection state change mid-session (e.g. license removed) — bounce back to
            // the connect/empty flow rather than keep showing stale rows.
            <ReconnectNudge onReconnectNeeded={onReconnectNeeded} />
          )}
        </>
      )}
    </div>
  );
}

function ReconnectNudge({ onReconnectNeeded }: { onReconnectNeeded: () => void }) {
  useEffect(() => {
    onReconnectNeeded();
  }, [onReconnectNeeded]);
  return null;
}

function LivenessBadge({ status }: { status: string }) {
  const tone = STATUS_MAP[status as keyof typeof STATUS_MAP];
  const label = STATUS_LABEL[status as keyof typeof STATUS_LABEL] ?? status;
  if (!tone) {
    return <span className="badge">{label}</span>;
  }
  return (
    <span className={`badge ${tone}`}>
      <Icon name={status === "current" ? "check" : status === "behind" ? "clock" : "alert"} size={12} />
      {label}
    </span>
  );
}

function VersionCell({ version, max }: { version?: string; max: string | null }) {
  if (!version) {
    return <span className="muted small">inventory: n/a</span>;
  }
  const outdated = max !== null && version !== max && compareVersions(version, max) < 0;
  return (
    <span>
      <code>{version}</code>
      {outdated && (
        <span className="badge warn" style={{ marginLeft: 6 }} title={`newest seen in this fleet: ${max}`}>
          update available
        </span>
      )}
    </span>
  );
}

/** P4 (doc 22 §9-CM) — renders the LOCALLY re-verified drift verdict (never kriyad's raw hint alone).
 *  `verdict` is `undefined` while still being computed (per-device evidence fetch in flight). */
function PolicyDriftCell({ verdict, loading }: { verdict?: DriftVerdict; loading: boolean }) {
  if (!verdict) {
    return (
      <span className="muted small">{loading ? "verifying…" : "inventory: n/a"}</span>
    );
  }
  if (verdict.tone === "grey") {
    return <span className="muted small" title={verdict.detail}>{verdict.label}</span>;
  }
  return (
    <span>
      <span className={`badge ${verdict.tone}`} title={verdict.detail}>
        <Icon name={verdict.tone === "ok" ? "check" : verdict.tone === "warn" ? "clock" : "alert"} size={12} />
        {verdict.label}
      </span>
      {verdict.mismatch && (
        <span
          className="badge bad"
          style={{ marginLeft: 6 }}
          title="kriyad's own served hint disagrees with this device's locally re-verified signed envelope — investigate."
        >
          <Icon name="alert" size={12} /> mismatch
        </span>
      )}
    </span>
  );
}

function AgentsCell({ agents }: { agents?: DeviceAgentInfo[] }) {
  if (!agents || agents.length === 0) {
    return <span className="muted small">inventory: n/a</span>;
  }
  return (
    <div className="chips" style={{ marginTop: 0 }}>
      {agents.map((a, i) => {
        const wired = a.wired !== false;
        const name = a.id || "unknown";
        const label = a.version ? `${name} v${a.version}` : name;
        return (
          <span
            key={i}
            className={`chip ${wired ? "" : "warn"}`}
            title={wired ? undefined : `${name} detected but not wired to a governance seam — ungoverned`}
          >
            {label}
          </span>
        );
      })}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "ok" | "warn" | "bad" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

// ── helpers ───────────────────────────────────────────────────────────────────────────────────────────

function orgBu(d: DeviceCoverageRow): string {
  const org = d.org_id ?? undefined;
  const bu = d.business_unit ?? undefined;
  if (org && bu) return `${org} / ${bu}`;
  return org || bu || "—";
}

function shortPub(pub: string): string {
  return pub.length > 16 ? `${pub.slice(0, 8)}…${pub.slice(-6)}` : pub;
}

function ago(ms?: number): string {
  if (!ms) return "never";
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 48 * 3600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

/** Loose semver-ish compare: `1.2.10` > `1.2.9`. Falls back to string compare on parse failure —
 *  good enough for an "update available" hint, never a security-relevant decision. */
function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/).map((n) => parseInt(n, 10));
  const pb = b.split(/[.+-]/).map((n) => parseInt(n, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (Number.isNaN(na) || Number.isNaN(nb)) return a.localeCompare(b);
    if (na !== nb) return na - nb;
  }
  return 0;
}

function maxVersion(versions: (string | undefined)[]): string | null {
  let max: string | null = null;
  for (const v of versions) {
    if (!v) continue;
    if (max === null || compareVersions(v, max) > 0) max = v;
  }
  return max;
}

/** The drill-in wants a `DeviceInfo`-shaped object; `DeviceCoverageRow` carries the same P1 fields
 *  flattened onto the coverage row instead of nested — reassembled into the nested `DeviceInfo` shape
 *  here so the drill-in panel and this table can share one honest "inventory: n/a" rule for whichever
 *  fields a given device hasn't beaconed yet (a pre-P1 device, or one that just hasn't reported). */
function coverageRowToDeviceInfo(d: DeviceCoverageRow): DeviceInfo | undefined {
  const hasAny =
    d.console_version !== undefined ||
    d.runtime_version !== undefined ||
    d.verify_crate_version !== undefined ||
    d.os_platform !== undefined ||
    d.os_version !== undefined ||
    d.os_arch !== undefined ||
    d.policy_applied_version !== undefined ||
    d.policy_bundle_hash !== undefined ||
    d.outbox_pending !== undefined ||
    d.enrolled_ms !== undefined ||
    d.device_label !== undefined ||
    (d.agents && d.agents.length > 0);
  if (!hasAny) return undefined;
  return {
    console_version: d.console_version,
    runtime_version: d.runtime_version,
    verify_crate_version: d.verify_crate_version,
    os: d.os_platform || d.os_version || d.os_arch
      ? { platform: d.os_platform, version: d.os_version, arch: d.os_arch }
      : undefined,
    agents: d.agents,
    policy:
      d.policy_applied_version !== undefined || d.policy_bundle_hash !== undefined
        ? { applied_version: d.policy_applied_version, bundle_hash: d.policy_bundle_hash }
        : undefined,
    outbox_pending: d.outbox_pending,
    enrolled_ms: d.enrolled_ms,
    device_label: d.device_label,
  };
}
