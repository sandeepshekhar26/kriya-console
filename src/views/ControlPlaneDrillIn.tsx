import { useEffect, useState } from "react";
import { Icon } from "../components/Icon";
import {
  fleetDeviceEvidence,
  type DeviceCoverageRow,
  type DeviceEvidence,
  type DeviceInfo,
  type VerifiedEnvelope,
} from "../lib/tauri";

/**
 * Per-device drill-in — the signed evidence stream (doc 22 §6): envelope rollups, chain continuity,
 * tamper status. Never raw payloads. Every "verified" badge below reflects
 * `fleet_device_evidence`'s real per-envelope `verified: boolean` (re-checked on-device against
 * `kriya-verify` by the Rust command before this ever resolves, BC-5) — this component never
 * hardcodes or infers a verified state itself.
 */
export function ControlPlaneDrillIn({
  device,
  info,
  onClose,
}: {
  device: DeviceCoverageRow;
  /** The device's full DeviceInfo, if it has ever beaconed one (BC-4: absent on old/pre-P1 devices). */
  info?: DeviceInfo;
  onClose: () => void;
}) {
  const [evidence, setEvidence] = useState<DeviceEvidence | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setErr(null);
    setEvidence(null);
    const from = Math.max(1, device.last_seq - 19);
    fleetDeviceEvidence(device.device_pub, from, device.max_seq_seen || device.last_seq)
      .then((r) => {
        if (!cancelled) setEvidence(r);
      })
      .catch((e) => {
        if (!cancelled) setErr(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [device.device_pub, device.last_seq, device.max_seq_seen]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const label = device.device_label || shortPub(device.device_pub);

  return (
    <div className="drawer-backdrop" onMouseDown={onClose}>
      <div
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`Device evidence — ${label}`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="drawer-head">
          <div>
            <h2>{label}</h2>
            <p>
              <code className="cp-pub">{device.device_pub}</code>
            </p>
          </div>
          <button className="x-btn" onClick={onClose} aria-label="Close">
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="drawer-body">
          <section>
            <h2 style={{ fontSize: 14, fontWeight: 600, letterSpacing: "-0.1px", margin: "0 0 10px" }}>
              Envelope chain
            </h2>
            <p className="muted small" style={{ margin: "0 0 10px" }}>
              Signed evidence rollups, re-verified locally against the exact bytes kriyad returned —
              never raw payloads.
            </p>

            {loading && (
              <div className="cp-line running">
                <span className="dot live" /> pulling &amp; re-verifying evidence…
              </div>
            )}
            {err && (
              <div className="cp-line bad">
                <Icon name="x" size={15} />
                <div>
                  <div className="cp-line-label">Could not load evidence</div>
                  <div className="cp-line-detail">{err}</div>
                </div>
              </div>
            )}
            {!loading && !err && evidence && (
              <EnvelopeChain evidence={evidence} />
            )}
          </section>

          <section>
            <h2 style={{ fontSize: 14, fontWeight: 600, letterSpacing: "-0.1px", margin: "0 0 10px" }}>
              Device info
            </h2>
            {info ? (
              <DeviceInfoPanel info={info} />
            ) : (
              <p className="muted small">
                inventory: n/a — this device hasn't posted a <code>DeviceInfo</code> beacon (older
                build, or no beacon since upgrading). Not an error.
              </p>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function EnvelopeChain({ evidence }: { evidence: DeviceEvidence }) {
  const rows = evidence.envelopes.map((v) => ({ v, parsed: parseEnvelope(v.raw) }));
  const chainIntact = isChainIntact(rows.map((r) => r.parsed));
  const windowFrom = rows[0]?.parsed?.window_from;
  const windowTo = rows[rows.length - 1]?.parsed?.window_to;

  return (
    <>
      <div className="stat-grid cp-stats" style={{ marginTop: 0, marginBottom: 14 }}>
        <Stat label="Envelopes" value={rows.length} />
        <Stat
          label="Chain"
          value={chainIntact ? "intact" : "broken"}
          tone={rows.length < 2 ? undefined : chainIntact ? "ok" : "bad"}
        />
        <Stat label="Window" value={windowFmt(windowFrom, windowTo)} />
        {evidence.heartbeat && (
          <Stat
            label="Heartbeat"
            value={evidence.heartbeat.verified ? "verified" : "FAILED"}
            tone={evidence.heartbeat.verified ? "ok" : "bad"}
          />
        )}
      </div>

      <div className="cp-proof">
        {rows.length === 0 && (
          <div className="cp-proof-empty">
            <Icon name="shield-check" size={20} />
            <span>No envelopes in this window yet.</span>
          </div>
        )}
        {rows.map(({ v, parsed }, i) => (
          <EnvelopeLine key={i} v={v} parsed={parsed} />
        ))}
      </div>
    </>
  );
}

function EnvelopeLine({ v, parsed }: { v: VerifiedEnvelope; parsed: ParsedEnvelope | null }) {
  return (
    <div className={`cp-line ${v.verified ? "ok" : "bad"}`}>
      <Icon name={v.verified ? "shield-check" : "shield-x"} size={15} />
      <div style={{ flex: 1 }}>
        <div className="cp-line-label">
          {parsed?.seq !== undefined ? `envelope seq ${parsed.seq}` : "envelope"}
          {parsed?.merkle_root && (
            <code className="cp-pub" style={{ marginLeft: 8 }}>
              merkle {String(parsed.merkle_root).slice(0, 12)}…
            </code>
          )}
        </div>
        <div className="cp-line-detail">
          {parsed && (parsed.window_from !== undefined || parsed.window_to !== undefined) && (
            <>window {windowFmt(parsed.window_from, parsed.window_to)} · </>
          )}
          {v.verified ? "verified locally" : v.error || "verification failed"}
        </div>
      </div>
      <span className={`badge ${v.verified ? "ok" : "bad"}`}>
        <Icon name={v.verified ? "check" : "x"} size={12} />
        {v.verified ? "verified-locally" : "FAILED"}
      </span>
    </div>
  );
}

function DeviceInfoPanel({ info }: { info: DeviceInfo }) {
  return (
    <div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <Field label="Console version" value={info.console_version} />
        <Field label="Runtime version" value={info.runtime_version} />
        <Field label="Verifier crate" value={info.verify_crate_version} />
        <Field
          label="OS"
          value={info.os ? [info.os.platform, info.os.version, info.os.arch].filter(Boolean).join(" · ") : undefined}
        />
        <Field label="Device label" value={info.device_label ?? undefined} />
        <Field
          label="Policy applied"
          value={info.policy?.applied_version !== undefined ? `v${info.policy.applied_version}` : undefined}
        />
        <Field label="Policy bundle hash" value={info.policy?.bundle_hash} />
        <Field label="Outbox pending" value={info.outbox_pending !== undefined ? String(info.outbox_pending) : undefined} />
        <Field label="Enrolled" value={info.enrolled_ms ? new Date(info.enrolled_ms).toLocaleString() : undefined} />
      </div>

      <h3 style={{ fontSize: 12, fontWeight: 500, color: "var(--ink)", margin: "14px 0 0" }}>Agents</h3>
      {info.agents && info.agents.length > 0 ? (
        <div className="chips">
          {info.agents.map((a, i) => (
            <AgentChip key={i} agent={a} />
          ))}
        </div>
      ) : (
        <p className="muted small">inventory: n/a — no agents detected on this beacon.</p>
      )}
    </div>
  );
}

function AgentChip({ agent }: { agent: { id?: string; version?: string; wired?: boolean } }) {
  const name = agent.id || "unknown agent";
  const wired = agent.wired !== false;
  const label = agent.version ? `${name} v${agent.version}` : name;
  return (
    <span
      className={`chip ${wired ? "" : "warn"}`}
      title={wired ? undefined : `${name} was detected but is not wired to a governance seam — ungoverned, a coverage gap`}
    >
      {label}
    </span>
  );
}

function Field({ label, value }: { label: string; value?: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, fontSize: 12.5 }}>
      <span className="muted">{label}</span>
      {value ? <code>{value}</code> : <span className="muted small">inventory: n/a</span>}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: "ok" | "warn" | "bad" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

// ── envelope parsing (display-only; verification truth comes from `verified: boolean` above) ────────

interface ParsedEnvelope {
  seq?: number;
  window_from?: number;
  window_to?: number;
  merkle_root?: string;
  prev_envelope_hash?: string;
}

function parseEnvelope(raw: string): ParsedEnvelope | null {
  try {
    const j = JSON.parse(raw) as { envelope?: Record<string, unknown> } & Record<string, unknown>;
    const e = (j.envelope ?? j) as Record<string, unknown>;
    return {
      seq: typeof e.seq === "number" ? e.seq : undefined,
      window_from: typeof e.window_from === "number" ? e.window_from : undefined,
      window_to: typeof e.window_to === "number" ? e.window_to : undefined,
      merkle_root: typeof e.merkle_root === "string" ? e.merkle_root : undefined,
      prev_envelope_hash: typeof e.prev_envelope_hash === "string" ? e.prev_envelope_hash : undefined,
    };
  } catch {
    return null;
  }
}

/** Display-only continuity check: each envelope's declared seq is one more than the previous.
 *  Real signature/chain-hash proof happens in the Rust `verified` bool above (BC-5) — this is just
 *  a rendering aid, not a security claim. */
function isChainIntact(rows: (ParsedEnvelope | null)[]): boolean {
  if (rows.length < 2) return true;
  for (let i = 1; i < rows.length; i++) {
    const prev = rows[i - 1]?.seq;
    const cur = rows[i]?.seq;
    if (prev === undefined || cur === undefined) continue;
    if (cur !== prev + 1) return false;
  }
  return true;
}

function windowFmt(from?: number, to?: number): string {
  if (from === undefined && to === undefined) return "—";
  const f = from !== undefined ? new Date(from).toLocaleTimeString() : "?";
  const t = to !== undefined ? new Date(to).toLocaleTimeString() : "?";
  return `${f} – ${t}`;
}

function shortPub(pub: string): string {
  return pub.length > 16 ? `${pub.slice(0, 8)}…${pub.slice(-6)}` : pub;
}
