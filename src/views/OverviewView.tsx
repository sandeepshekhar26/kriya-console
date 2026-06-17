import { useMemo } from "react";
import type { AuditRow } from "../lib/types";
import { decide, lintPolicy, TIER_LABEL, type Policy } from "../lib/policy";
import type { View } from "../components/Sidebar";

export function OverviewView({
  rows,
  policy,
  observedActions,
  onNavigate,
  onLoadSample,
}: {
  rows: AuditRow[];
  policy: Policy;
  observedActions: string[];
  onNavigate: (v: View) => void;
  onLoadSample: () => void;
}) {
  const stats = useMemo(() => {
    const verified = rows.filter((r) => r.outcome.ok).length;
    const signers = new Set(rows.map((r) => r.receipt?.public_key).filter(Boolean)).size;
    const apps = new Set(rows.map((r) => r.source)).size;
    return { total: rows.length, verified, failed: rows.length - verified, signers, apps };
  }, [rows]);

  const warnings = useMemo(() => lintPolicy(policy), [policy]);

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

  const catchAll = policy.rules.find((r) => r.action === "*");

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="page-sub">Governed-agent activity and posture across your apps.</p>
        </div>
        <div className="page-actions">
          {rows.length === 0 && (
            <button className="btn" onClick={onLoadSample}>
              Load sample data
            </button>
          )}
        </div>
      </header>

      <section className="stat-grid">
        <Stat label="Receipts" value={stats.total} />
        <Stat label="Verified" value={stats.verified} tone="ok" />
        <Stat label="Failed / tampered" value={stats.failed} tone={stats.failed ? "bad" : undefined} />
        <Stat label="Apps / sources" value={stats.apps} />
        <Stat label="Distinct signers" value={stats.signers} />
      </section>

      <section className="panel-grid">
        <article className="panel">
          <div className="panel-head">
            <h2>Governance posture</h2>
            <button className="link" onClick={() => onNavigate("policy")}>
              Edit policy →
            </button>
          </div>
          <dl className="kv">
            <div>
              <dt>Rules</dt>
              <dd>{policy.rules.length}</dd>
            </div>
            <div>
              <dt>Default (catch-all)</dt>
              <dd>{catchAll ? TIER_LABEL[catchAll.tier] : <span className="warn-text">implicit deny</span>}</dd>
            </div>
            <div>
              <dt>Budget cap</dt>
              <dd>
                {policy.maxActionsPerMinute !== null ? (
                  `${policy.maxActionsPerMinute} / min`
                ) : (
                  <span className="warn-text">none</span>
                )}
              </dd>
            </div>
            <div>
              <dt>Lint</dt>
              <dd>
                {warnings.length === 0 ? (
                  <span className="ok-text">✓ clean</span>
                ) : (
                  <span className="warn-text">{warnings.length} warning{warnings.length > 1 ? "s" : ""}</span>
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
              Govern actions →
            </button>
          </div>
          {observedActions.length === 0 ? (
            <p className="muted">
              Load an audit log to see which of your actions the agent has used — and which ones
              still fall through to the catch-all.
            </p>
          ) : (
            <>
              <p className="coverage-line">
                <strong>{coverage.governed}</strong> of <strong>{observedActions.length}</strong> observed
                action{observedActions.length > 1 ? "s" : ""} have an explicit rule.
              </p>
              {coverage.ungoverned.length > 0 ? (
                <>
                  <p className="muted small">Caught only by the catch-all (not explicitly governed):</p>
                  <div className="chips">
                    {coverage.ungoverned.map((a) => (
                      <span key={a} className="chip warn" onClick={() => onNavigate("policy")}>
                        {a}
                      </span>
                    ))}
                  </div>
                </>
              ) : (
                <p className="ok-text">✓ Every observed action has an explicit policy rule.</p>
              )}
            </>
          )}
        </article>
      </section>
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
