import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import { decide, lintPolicy, TIER_LABEL, type Policy } from "../lib/policy";
import type { View } from "../components/Sidebar";
import { Icon } from "../components/Icon";

const TAIL_LIMIT = 14;

/**
 * Monitor — the home surface. Live, on-device governance: an auto-tailing stream of signed receipts
 * (re-verified in the Rust backend), posture at a glance, and attestation continuity per app. This is
 * the flagship; everything else is a deeper view over the same signed-receipt corpus.
 */
export function MonitorView({
  rows,
  policy,
  observedActions,
  pendingApprovals,
  highRiskApprovals,
  onNavigate,
  live,
}: {
  rows: AuditRow[];
  policy: Policy;
  observedActions: string[];
  pendingApprovals: number;
  highRiskApprovals: number;
  onNavigate: (v: View) => void;
  /** In the desktop app: the audit dir being tailed. */
  live?: string;
}) {
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<AuditRow[]>([]);

  const stats = useMemo(() => {
    const verified = rows.filter((r) => r.outcome.ok).length;
    const signers = new Set(rows.map((r) => r.receipt?.public_key).filter(Boolean)).size;
    const apps = new Set(rows.map((r) => r.source)).size;
    return { total: rows.length, verified, failed: rows.length - verified, signers, apps };
  }, [rows]);

  const warnings = useMemo(() => lintPolicy(policy), [policy]);
  const catchAll = policy.rules.find((r) => r.action === "*");

  const coverage = useMemo(() => {
    const ungoverned: string[] = [];
    let governed = 0;
    for (const action of observedActions) {
      const { matchedIndex } = decide(policy, action);
      const rule = matchedIndex !== null ? policy.rules[matchedIndex] : undefined;
      if (rule && rule.action !== "*") governed++;
      else ungoverned.push(action);
    }
    return { governed, ungoverned };
  }, [observedActions, policy]);

  // Per-source attestation continuity (a band per receipt, in time order).
  const ribbons = useMemo(() => {
    const bySource = new Map<string, AuditRow[]>();
    for (const r of rows) {
      const list = bySource.get(r.source) ?? [];
      list.push(r);
      bySource.set(r.source, list);
    }
    return [...bySource.entries()]
      .map(([source, list]) => ({
        source,
        total: list.length,
        failed: list.filter((r) => !r.outcome.ok).length,
        bands: list.map((r) => r.outcome.ok),
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 6);
  }, [rows]);

  const recent = useMemo(() => [...rows].slice(-TAIL_LIMIT).reverse(), [rows]);
  const tail = paused ? frozen : recent;

  function togglePause() {
    setPaused((p) => {
      if (!p) setFrozen(recent);
      return !p;
    });
  }

  return (
    <div className="view view-wide">
      <header className="page-head">
        <div>
          <h1>Monitor</h1>
          <p className="page-sub">Live, on-device governance across every connected app — every action a signed receipt, re-verified here.</p>
        </div>
        <div className="page-actions">
          {live ? (
            <span className="live-pill" title={live}>
              <span className="dot live" /> Live · {live}
            </span>
          ) : (
            rows.length === 0 && (
              <button className="btn primary" onClick={() => onNavigate("connections")}>
                <Icon name="link" size={15} /> Add a connection
              </button>
            )
          )}
        </div>
      </header>

      <section className="stat-grid">
        <Stat label="Receipts" value={stats.total} />
        <Stat label="Verified" value={stats.verified} tone={stats.total > 0 ? "ok" : undefined} />
        <Stat label="Unverified" value={stats.failed} tone={stats.failed ? "bad" : undefined} />
        <Stat label="Apps / sources" value={stats.apps} />
        <Stat label="Distinct signers" value={stats.signers} />
      </section>

      {/* Live activity tail */}
      <div className="tail-toolbar">
        <span className="vstat ok" style={{ fontWeight: 600 }}>
          <Icon name="monitor" size={15} /> {live ? "Live activity" : "Recent activity"}
        </span>
        {live && rows.length > 0 && (
          <button className="btn small ghost" onClick={togglePause}>
            <Icon name={paused ? "play" : "pause"} size={13} /> {paused ? "Resume" : "Pause"}
          </button>
        )}
        {paused && <span className="badge warn">Paused</span>}
        <span className="count">{rows.length} receipt{rows.length === 1 ? "" : "s"}</span>
      </div>
      <div className="tail-wrap">
        {tail.length === 0 ? (
          <div className="empty" style={{ margin: "40px auto" }}>
            <div className="empty-ico"><Icon name="shield-check" size={22} /></div>
            {live ? (
              <>
                <p className="empty-title">On-device verifier idle</p>
                <p>Watching <code>{live}</code> · 0 unverified. Drive a governed app and signed receipts appear here live — each re-verified against its embedded key.</p>
                <div className="page-actions">
                  <button className="btn ghost" onClick={() => onNavigate("connections")}>Add a connection</button>
                </div>
              </>
            ) : (
              <>
                <p className="empty-title">No receipts yet</p>
                <p>Connect a governed app — every action it takes appears here as a signed receipt, verified and tamper-evident. Or open a signed trail from the Audit log.</p>
                <div className="page-actions"><button className="btn primary" onClick={() => onNavigate("connections")}>Add a connection</button></div>
              </>
            )}
          </div>
        ) : (
          <div className="tail" role="log" aria-live="polite" aria-relevant="additions" aria-label="Live signed-receipt activity">
            {tail.map((r) => (
              <TailRow key={`${r.source}:${r.lineNo}`} row={r} policy={policy} />
            ))}
          </div>
        )}
      </div>

      {rows.length > 0 && (
        <>
          <h2 className="section-head">Posture</h2>
          <section className="panel-grid">
            <article className="panel">
              <div className="panel-head">
                <h2>Governance posture</h2>
                <button className="link" onClick={() => onNavigate("policy")}>
                  Edit policy <Icon name="arrow-right" size={13} />
                </button>
              </div>
              <dl className="kv">
                <div>
                  <dt>Rules</dt>
                  <dd className="tnum">{policy.rules.length}</dd>
                </div>
                <div>
                  <dt>Default (catch-all)</dt>
                  <dd>{catchAll ? TIER_LABEL[catchAll.tier] : <span className="warn-text">implicit deny</span>}</dd>
                </div>
                <div>
                  <dt>Action cap</dt>
                  <dd className="tnum">
                    {policy.maxActionsPerMinute !== null ? `${policy.maxActionsPerMinute} / min` : <span className="warn-text">none</span>}
                  </dd>
                </div>
                <div>
                  <dt>Pending approvals</dt>
                  <dd className="tnum">
                    {pendingApprovals === 0 ? (
                      <span className="ok-text">clear</span>
                    ) : (
                      <span className={highRiskApprovals > 0 ? "bad-text" : "warn-text"}>{pendingApprovals}</span>
                    )}
                  </dd>
                </div>
              </dl>
              {warnings.length > 0 && <p className="panel-note">{warnings[0]!.message}</p>}
            </article>

            <article className="panel">
              <div className="panel-head">
                <h2>Policy coverage</h2>
                <button className="link" onClick={() => onNavigate("policy")}>
                  Govern actions <Icon name="arrow-right" size={13} />
                </button>
              </div>
              {observedActions.length === 0 ? (
                <p className="muted">No actions observed yet — once an agent runs, this shows which of its actions have an explicit rule.</p>
              ) : (
                <>
                  <p className="coverage-line">
                    <strong>{coverage.governed}</strong> of <strong>{observedActions.length}</strong> observed action{observedActions.length > 1 ? "s" : ""} have an explicit rule.
                  </p>
                  {coverage.ungoverned.length > 0 ? (
                    <>
                      <p className="muted small">Caught only by the catch-all (not explicitly governed):</p>
                      <div className="chips">
                        {coverage.ungoverned.map((a) => (
                          <button key={a} className="chip warn" onClick={() => onNavigate("policy")}>{a}</button>
                        ))}
                      </div>
                    </>
                  ) : (
                    <p className="ok-text"><Icon name="check" size={14} /> Every observed action has an explicit policy rule.</p>
                  )}
                </>
              )}
            </article>
          </section>

          {ribbons.length > 0 && (
            <article className="panel" style={{ marginTop: 16 }}>
              <div className="panel-head">
                <h2>Attestation continuity</h2>
                <span className="muted small">per app · a band per receipt, in order</span>
              </div>
              <div className="ribbon-wrap">
                {ribbons.map((rb) => (
                  <div className="ribbon-row" key={rb.source}>
                    <span className="ribbon-label mono" title={rb.source}>{rb.source}</span>
                    <span className="ribbon">
                      {rb.bands.map((ok, i) => (
                        <span key={i} className={ok ? "ok" : "bad"} style={{ flex: 1 }} />
                      ))}
                    </span>
                    <span className="ribbon-meta">
                      {rb.failed > 0 ? <span className="bad-text">{rb.failed} failed</span> : <span className="ok-text">intact</span>} · {rb.total}
                    </span>
                  </div>
                ))}
              </div>
            </article>
          )}
        </>
      )}
    </div>
  );
}

function TailRow({ row, policy }: { row: AuditRow; policy: Policy }) {
  const ok = row.outcome.ok;
  const r = row.receipt;
  const tier = r ? decide(policy, r.action_id).decision : null;
  return (
    <div className={`tail-row ${ok ? "" : "bad"}`} title={ok ? undefined : row.outcome.reason}>
      <span className="tail-time">{r ? fmtTime(r.ts_ms) : `line ${row.lineNo}`}</span>
      <span className={`vstat ${ok ? "ok" : "bad"}`}>
        <Icon name={ok ? "check" : "shield-x"} size={15} />
      </span>
      <span className="tail-main">
        <span className="tail-action">{r?.action_id ?? "—"}</span>
        <span className="tail-actor">
          {r?.actor ? `${r.actor.agent} / ${r.actor.user}` : row.source}
        </span>
      </span>
      <span className="tail-acc">
        {tier && <span className="tail-tag">{TIER_LABEL[tier]}</span>}
        {r && <span className="tail-sig" title={r.public_key}>{r.public_key.slice(0, 8)}</span>}
      </span>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "ok" | "bad" }) {
  return (
    <div className={`stat ${tone ?? ""}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function fmtTime(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return String(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
