import { useState } from "react";
import { Icon } from "../components/Icon";
import {
  canonicalJsonString,
  sha256Hex,
  verifyEnvelope,
  type SignedEnvelope,
} from "../lib/envelope";
import { DEVICE_PUB, ENVELOPES, HEARTBEAT, FLEET, FLEET_STATS, type FleetDevice } from "../demo/seed";

type Line = { label: string; ok: boolean; detail?: string };
type Mode = "reprove" | "forge" | "tamper" | "hide";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const seqOf = (e: SignedEnvelope) => Number(e.envelope.seq);

/**
 * Control plane — the on-prem kriyad aggregator dashboard (the paid upsell). Shows the fleet's coverage
 * and lets an auditor RE-PROVE a device's signed evidence offline, trusting neither the device nor this
 * server. The re-proof + adversarial catches run the SAME in-browser Ed25519 verifier the trust spine
 * parity-tests against Rust — so the green checks and red catches are real cryptography, not theatre.
 */
export function ControlPlaneView() {
  const [lines, setLines] = useState<Line[]>([]);
  const [running, setRunning] = useState<Mode | null>(null);
  const [done, setDone] = useState<Mode | null>(null);

  async function run(mode: Mode) {
    setRunning(mode);
    setDone(null);
    setLines([]);
    const out: Line[] = [];
    const push = async (l: Line) => {
      out.push(l);
      setLines([...out]);
      await sleep(360);
    };

    // Work on a copy so the adversary mutates evidence the device really signed.
    const envs: SignedEnvelope[] = ENVELOPES.map((e) => JSON.parse(JSON.stringify(e)));
    let seqSeen = HEARTBEAT.heartbeat.seq_seen;

    if (mode === "forge" && envs[0]) {
      envs[0].envelope.org_id = "evil-corp"; // change a field AFTER signing
    } else if (mode === "tamper" && envs[0]) {
      const s = envs[0].signature; // flip one hex char of the signature
      envs[0].signature = (s[0] === "f" ? "0" : "f") + s.slice(1);
    } else if (mode === "hide") {
      envs.pop(); // a malicious server drops the newest envelope (seq 2)
    }

    // 1) re-verify each envelope's Ed25519 signature on the exact returned bytes
    for (const e of envs) {
      const r = await verifyEnvelope(e);
      await push({
        label: `envelope seq ${seqOf(e)} · Ed25519 signature`,
        ok: r.ok,
        detail: r.ok ? "re-derived canonical bytes · signature matches" : r.reason,
      });
    }

    // 2) hash-chain continuity (real: sha256 of the prior signed envelope's canonical bytes)
    const first = envs[0];
    const second = envs[1];
    if (first && second) {
      const expect = await sha256Hex(canonicalJsonString(first));
      const chainOk = second.envelope.prev_envelope_hash === expect;
      await push({
        label: "hash-chain · prev_envelope_hash links seq 2 → seq 1",
        ok: chainOk,
        detail: chainOk ? "no envelope deleted between them" : "chain broken — an envelope was altered or dropped",
      });
    }

    // 3) tail-truncation anchor: the device's signed heartbeat pins the highest seq it emitted
    const top = envs.length ? Math.max(...envs.map(seqOf)) : 0;
    const tailOk = top >= seqSeen;
    await push({
      label: `tail-truncation anchor · device signed seq_seen ${seqSeen}`,
      ok: tailOk,
      detail: tailOk
        ? `server returned through seq ${top} — it withheld nothing the device attested to`
        : `server returned only seq ${top} — it hid seq ${seqSeen}, which the signed heartbeat proves existed`,
    });

    setRunning(null);
    setDone(mode);
  }

  const allOk = lines.length > 0 && lines.every((l) => l.ok);

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

      <div className="cp-conn">
        <span className="dot live" />
        <code>kriyad</code> @ <code>aggregator.acme.internal:8443</code>
        <span className="pill"><Icon name="lock" size={12} /> mTLS</span>
        <span className="pill">single-tenant</span>
        <span className="pill"><Icon name="shield-check" size={12} /> no egress</span>
        <span className="spacer" />
        <span className="muted small">SQLite · append-only · backup = copy one file</span>
      </div>

      <section className="stat-grid cp-stats">
        <Stat label="Devices" value={FLEET_STATS.devices} />
        <Stat label="Current" value={FLEET_STATS.current} tone="ok" />
        <Stat label="Behind" value={FLEET_STATS.behind} tone={FLEET_STATS.behind ? "warn" : undefined} />
        <Stat label="Silent" value={FLEET_STATS.silent} tone={FLEET_STATS.silent ? "bad" : undefined} />
        <Stat label="Envelopes ingested" value={FLEET_STATS.envelopes} />
        <Stat label="Forged · rejected" value={FLEET_STATS.rejected} tone="bad" />
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Coverage</h2>
          <span className="muted small">
            silent ⇒ unseen &gt; 3×heartbeat · behind ⇒ a signed heartbeat claims a higher seq than is stored
          </span>
        </div>
        <table className="audit cp-cover">
          <thead>
            <tr>
              <th>Device</th>
              <th>Business unit</th>
              <th>Status</th>
              <th>Last seq</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {FLEET.map((d) => (
              <tr key={d.id} className={d.real ? "cp-focus" : ""}>
                <td>
                  <div className="cp-dev">
                    <Icon name={d.real ? "desktop" : "desktop"} size={14} className="muted" />
                    <span>{d.id}</span>
                    {d.real && <span className="cp-real">live · re-provable</span>}
                  </div>
                  <code className="cp-pub">{d.pub}</code>
                </td>
                <td>{d.bu}</td>
                <td><CoverageBadge d={d} /></td>
                <td>
                  <code>{d.lastSeq}</code>
                  {d.status === "behind" && <span className="muted small"> / {d.maxSeqSeen} claimed</span>}
                </td>
                <td className="muted">{d.lastSeen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel cp-verify">
        <div className="panel-head">
          <h2>Trustless re-verification</h2>
          <span className="muted small">device <code>{DEVICE_PUB.slice(0, 12)}…</code> · build-host-07</span>
        </div>
        <p className="cp-lede">
          Pull the <b>exact bytes</b> the device signed (<code>GET /v1/verify</code>) and re-prove them
          offline — trusting neither the device nor this server. Then let an adversary try to cheat:
        </p>

        <div className="cp-actions">
          <button className="btn primary" onClick={() => run("reprove")} disabled={running !== null}>
            <Icon name="shield-check" size={15} /> Re-prove offline
          </button>
          <span className="cp-sep">attack it:</span>
          <button className="btn danger small" onClick={() => run("forge")} disabled={running !== null}>
            <Icon name="bolt" size={14} /> Forge a field
          </button>
          <button className="btn danger small" onClick={() => run("tamper")} disabled={running !== null}>
            <Icon name="bolt" size={14} /> Flip a byte
          </button>
          <button className="btn danger small" onClick={() => run("hide")} disabled={running !== null}>
            <Icon name="bolt" size={14} /> Hide newest
          </button>
        </div>

        <div className="cp-proof">
          {lines.length === 0 && running === null && (
            <div className="cp-proof-empty">
              <Icon name="shield-check" size={20} />
              <span>Re-prove the device's signed envelopes, or stage an attack and watch it get caught.</span>
            </div>
          )}
          {lines.map((l, i) => (
            <div key={i} className={`cp-line ${l.ok ? "ok" : "bad"}`}>
              <Icon name={l.ok ? "check" : "x"} size={15} />
              <div>
                <div className="cp-line-label">{l.label}</div>
                {l.detail && <div className="cp-line-detail">{l.detail}</div>}
              </div>
            </div>
          ))}
          {running && (
            <div className="cp-line running">
              <span className="dot live" /> re-verifying on-device…
            </div>
          )}
          {done && running === null && (
            <div className={`cp-verdict ${allOk ? "ok" : "bad"}`}>
              {allOk ? (
                <><Icon name="shield-check" size={16} /> Re-proved — signed at the source, unaltered, nothing hidden.</>
              ) : (
                <><Icon name="shield-x" size={16} /> Caught. The tampered evidence cannot pass an independent re-proof.</>
              )}
            </div>
          )}
        </div>
        <p className="cp-foot muted small">
          Tamper-<b>evidence</b>, not action approval: this proves the record wasn't altered after signing —
          not that the action was safe. The guarantee starts at the device's signing key.
        </p>
      </section>
    </div>
  );
}

function CoverageBadge({ d }: { d: FleetDevice }) {
  const map = { current: "ok", behind: "warn", silent: "bad" } as const;
  const label = { current: "current", behind: "behind", silent: "silent" } as const;
  return (
    <span className={`badge ${map[d.status]}`}>
      <Icon name={d.status === "current" ? "check" : d.status === "behind" ? "clock" : "alert"} size={12} />
      {label[d.status]}
    </span>
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
