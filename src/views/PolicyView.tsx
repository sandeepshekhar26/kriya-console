import { useMemo, useState } from "react";
import { Icon } from "../components/Icon";
import {
  decide,
  defaultPolicy,
  lintPolicy,
  parsePolicyYaml,
  policyToYaml,
  TIER_LABEL,
  type Policy,
  type Tier,
} from "../lib/policy";

const TIERS: Tier[] = ["allow", "approval", "deny"];

export function PolicyView({
  policy,
  onChange,
  observedActions,
}: {
  policy: Policy;
  onChange: (p: Policy) => void;
  observedActions: string[];
}) {
  const [importing, setImporting] = useState(false);
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<string | null>(null);
  const [testAction, setTestAction] = useState("");
  const [copied, setCopied] = useState(false);

  const yaml = useMemo(() => policyToYaml(policy), [policy]);
  const warnings = useMemo(() => lintPolicy(policy), [policy]);

  const ungoverned = useMemo(
    () =>
      observedActions.filter((a) => {
        const { matchedIndex } = decide(policy, a);
        const rule = matchedIndex !== null ? policy.rules[matchedIndex] : undefined;
        return !(rule && rule.action !== "*");
      }),
    [observedActions, policy],
  );

  function setRule(i: number, patch: Partial<{ action: string; tier: Tier }>) {
    onChange({ ...policy, rules: policy.rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r)) });
  }
  function removeRule(i: number) {
    onChange({ ...policy, rules: policy.rules.filter((_, idx) => idx !== i) });
  }
  function moveRule(i: number, dir: -1 | 1) {
    const j = i + dir;
    if (j < 0 || j >= policy.rules.length) return;
    const next = policy.rules.slice();
    [next[i], next[j]] = [next[j]!, next[i]!];
    onChange({ ...policy, rules: next });
  }
  function addRule(action = "", tier: Tier = "allow") {
    const idx = policy.rules.findIndex((r) => r.action === "*");
    const next = policy.rules.slice();
    if (idx === -1) next.push({ action, tier });
    else next.splice(idx, 0, { action, tier });
    onChange({ ...policy, rules: next });
  }
  function doImport() {
    try {
      const p = parsePolicyYaml(importText);
      if (p.rules.length === 0) throw new Error("no rules found in that YAML");
      onChange(p);
      setImporting(false);
      setImportText("");
      setImportError(null);
    } catch (e) {
      setImportError(e instanceof Error ? e.message : String(e));
    }
  }
  function download() {
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "agent-policy.yaml";
    a.click();
    URL.revokeObjectURL(url);
  }
  async function copyYaml() {
    try {
      await navigator.clipboard.writeText(yaml);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — the YAML is visible to copy manually */
    }
  }

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Policy</h1>
          <p className="page-sub">
            The rules the host enforces on every agent action — first match wins, no match = deny.
            Edits here produce the <code>agent-policy.yaml</code> the runtime loads.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn ghost" onClick={() => setImporting((v) => !v)}>
            Import YAML
          </button>
          <button className="btn ghost" onClick={() => onChange(defaultPolicy())}>
            Reset to default
          </button>
          <button className="btn" onClick={download}>
            Download agent-policy.yaml
          </button>
        </div>
      </header>

      {importing && (
        <div className="import-panel">
          <textarea
            className="import-text mono"
            placeholder="Paste an existing agent-policy.yaml…"
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            rows={8}
          />
          {importError && <p className="warn-text small">Could not parse: {importError}</p>}
          <div className="import-actions">
            <button className="btn" onClick={doImport}>
              Load policy
            </button>
            <button
              className="btn ghost"
              onClick={() => {
                setImporting(false);
                setImportError(null);
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="policy-grid">
        <section className="panel">
          <div className="panel-head">
            <h2>Rules</h2>
            <span className="muted small">evaluated top → bottom</span>
          </div>

          <div className="rules">
            <div className="rule-head">
              <span>Order</span>
              <span>Action pattern</span>
              <span>Decision</span>
              <span />
            </div>
            {policy.rules.map((r, i) => (
              <div className={`rule ${r.action === "*" ? "catch-all" : ""}`} key={i}>
                <div className="rule-order">
                  <button className="icon-btn" disabled={i === 0} onClick={() => moveRule(i, -1)} title="Move up" aria-label="Move rule up">
                    <Icon name="chevron-up" size={11} />
                  </button>
                  <button
                    className="icon-btn"
                    disabled={i === policy.rules.length - 1}
                    onClick={() => moveRule(i, 1)}
                    title="Move down"
                    aria-label="Move rule down"
                  >
                    <Icon name="chevron-down" size={11} />
                  </button>
                </div>
                <input
                  className="rule-action mono"
                  value={r.action}
                  onChange={(e) => setRule(i, { action: e.target.value })}
                  placeholder="action_id or prefix_*"
                />
                <select
                  className={`tier-select tier-${r.tier}`}
                  value={r.tier}
                  onChange={(e) => setRule(i, { tier: e.target.value as Tier })}
                >
                  {TIERS.map((t) => (
                    <option key={t} value={t}>
                      {TIER_LABEL[t]}
                    </option>
                  ))}
                </select>
                <button className="icon-btn danger" onClick={() => removeRule(i)} title="Remove rule" aria-label="Remove rule">
                  <Icon name="x" size={12} />
                </button>
              </div>
            ))}
          </div>

          <button className="btn ghost add-rule" onClick={() => addRule()}>
            + Add rule
          </button>

          {ungoverned.length > 0 && (
            <div className="suggestions">
              <p className="muted small">
                Observed in your audit logs, not explicitly governed — click to add a rule:
              </p>
              <div className="chips">
                {ungoverned.map((a) => (
                  <button key={a} className="chip add" onClick={() => addRule(a, "allow")}>
                    + {a}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="budget">
            <h3>Budget</h3>
            <label className="budget-row">
              <input
                type="checkbox"
                checked={policy.maxActionsPerMinute !== null}
                onChange={(e) => onChange({ ...policy, maxActionsPerMinute: e.target.checked ? 60 : null })}
              />
              Cap actions per minute
            </label>
            {policy.maxActionsPerMinute !== null && (
              <input
                type="number"
                min={1}
                className="budget-input"
                value={policy.maxActionsPerMinute}
                onChange={(e) =>
                  onChange({ ...policy, maxActionsPerMinute: Math.max(1, Number(e.target.value) || 1) })
                }
              />
            )}
            <label className="budget-row">
              <input
                type="checkbox"
                checked={policy.maxApiCallsPerHour !== null}
                onChange={(e) => onChange({ ...policy, maxApiCallsPerHour: e.target.checked ? 500 : null })}
              />
              Cap inference/API calls per hour
            </label>
            {policy.maxApiCallsPerHour !== null && (
              <input
                type="number"
                min={1}
                className="budget-input"
                value={policy.maxApiCallsPerHour}
                onChange={(e) =>
                  onChange({ ...policy, maxApiCallsPerHour: Math.max(1, Number(e.target.value) || 1) })
                }
              />
            )}
          </div>
        </section>

        <section className="inspector">
          <article className="panel">
            <div className="panel-head">
              <h2>Lint</h2>
            </div>
            {warnings.length === 0 ? (
              <p className="ok-text"><Icon name="check" size={14} /> Policy looks clean.</p>
            ) : (
              <ul className="lint">
                {warnings.map((w, i) => (
                  <li key={i} className={`lint-item ${w.severity}`}>
                    <span className="lint-dot" />
                    {w.message}
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h2>Decision preview</h2>
            </div>
            <div className="test-row">
              <input
                className="mono"
                placeholder="Test an action id…"
                value={testAction}
                onChange={(e) => setTestAction(e.target.value)}
              />
              {testAction.trim() && <DecisionBadge policy={policy} action={testAction.trim()} />}
            </div>
            {observedActions.length > 0 ? (
              <table className="decision-table">
                <tbody>
                  {observedActions.map((a) => (
                    <tr key={a}>
                      <td className="mono">{a}</td>
                      <td>
                        <DecisionBadge policy={policy} action={a} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="muted small">Load an audit log to preview decisions against real actions.</p>
            )}
          </article>

          <article className="panel">
            <div className="panel-head">
              <h2>agent-policy.yaml</h2>
              <button className="link" onClick={copyYaml}>
                {copied ? (<><Icon name="check" size={12} /> copied</>) : "copy"}
              </button>
            </div>
            <pre className="well yaml">{yaml}</pre>
          </article>
        </section>
      </div>
    </div>
  );
}

function DecisionBadge({ policy, action }: { policy: Policy; action: string }) {
  const { decision, matchedIndex } = decide(policy, action);
  const where =
    matchedIndex === null
      ? "implicit deny"
      : policy.rules[matchedIndex]!.action === "*"
        ? "catch-all"
        : `rule ${matchedIndex + 1}`;
  return (
    <span className={`decision-badge tier-${decision}`} title={`matched: ${where}`}>
      {TIER_LABEL[decision]}
    </span>
  );
}
