import { useMemo, useState } from "react";
import { Icon } from "../components/Icon";
import {
  decide,
  defaultPolicy,
  emptyEgressPolicy,
  emptyDetectionPolicy,
  defaultDnsExfilPolicy,
  defaultSsrfGuardPolicy,
  defaultSecretPiiPolicy,
  defaultConnectorRegistryPolicy,
  defaultMcpResponsePolicy,
  emptySecretsPolicy,
  lintPolicy,
  parsePolicyYaml,
  policyToYaml,
  TIER_LABEL,
  UNLISTED_LABEL,
  ALERT_OR_DENY_LABEL,
  REDACT_OR_DENY_LABEL,
  TRUST_CLASS_LABEL,
  type EgressRule,
  type Policy,
  type Tier,
  type UnlistedPosture,
  type AlertOrDeny,
  type RedactOrDeny,
  type TrustClass,
  type OperationRail,
  type ApprovedConnectorTool,
  type SecretAlias,
} from "../lib/policy";

const TIERS: Tier[] = ["allow", "approval", "deny"];
const UNLISTED_POSTURES: UnlistedPosture[] = ["allow", "deny", "defer"];
const ALERT_OR_DENY: AlertOrDeny[] = ["alert", "deny"];
const REDACT_OR_DENY: RedactOrDeny[] = ["redact", "deny"];
const TRUST_CLASSES: TrustClass[] = ["trusted", "scan", "block"];

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
  // First-run: the policy still has only the catch-all (no author-added rule yet).
  const noCustomRules = policy.rules.every((r) => r.action === "*");

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
  function setEgressRule(i: number, patch: Partial<EgressRule>) {
    if (!policy.egress) return;
    const rules = policy.egress.rules.map((r, idx) => (idx === i ? { ...r, ...patch } : r));
    onChange({ ...policy, egress: { ...policy.egress, rules } });
  }
  function removeEgressRule(i: number) {
    if (!policy.egress) return;
    onChange({ ...policy, egress: { ...policy.egress, rules: policy.egress.rules.filter((_, idx) => idx !== i) } });
  }
  function addEgressRule() {
    const egress = policy.egress ?? emptyEgressPolicy();
    const rules = [...egress.rules, { host: "", tier: "allow" as Tier, budgetWindowSecs: null, budgetMaxBytes: null }];
    onChange({ ...policy, egress: { ...egress, rules } });
  }

  // Detection pack (doc 24 §11 B5–B12 / EG-P). Every sub-detector below is independently nullable —
  // toggling the pack on never activates a sub-detector the operator hasn't explicitly turned on.
  function setDetection(patch: Partial<NonNullable<Policy["detection"]>>) {
    const detection = policy.detection ?? emptyDetectionPolicy();
    onChange({ ...policy, detection: { ...detection, ...patch } });
  }
  function setRail(i: number, patch: Partial<OperationRail>) {
    if (!policy.detection) return;
    const operationRails = policy.detection.operationRails.map((r, idx) => (idx === i ? { ...r, ...patch } : r));
    setDetection({ operationRails });
  }
  function removeRail(i: number) {
    if (!policy.detection) return;
    setDetection({ operationRails: policy.detection.operationRails.filter((_, idx) => idx !== i) });
  }
  function addRail() {
    const rails = policy.detection?.operationRails ?? [];
    setDetection({
      operationRails: [...rails, { host: "*", method: "*", path: "", graphqlMutation: null, tier: "allow" as Tier }],
    });
  }
  function setCanaryToken(i: number, value: string) {
    if (!policy.detection) return;
    setDetection({ canaryTokens: policy.detection.canaryTokens.map((t, idx) => (idx === i ? value : t)) });
  }
  function removeCanaryToken(i: number) {
    if (!policy.detection) return;
    setDetection({ canaryTokens: policy.detection.canaryTokens.filter((_, idx) => idx !== i) });
  }
  function addCanaryToken() {
    setDetection({ canaryTokens: [...(policy.detection?.canaryTokens ?? []), ""] });
  }
  function setReadOnlyEntry(i: number, value: string) {
    if (!policy.detection) return;
    setDetection({ readOnly: policy.detection.readOnly.map((r, idx) => (idx === i ? value : r)) });
  }
  function removeReadOnlyEntry(i: number) {
    if (!policy.detection) return;
    setDetection({ readOnly: policy.detection.readOnly.filter((_, idx) => idx !== i) });
  }
  function addReadOnlyEntry() {
    setDetection({ readOnly: [...(policy.detection?.readOnly ?? []), ""] });
  }
  function setApprovedTool(i: number, patch: Partial<ApprovedConnectorTool>) {
    if (!policy.detection?.connectorRegistry) return;
    const approved = policy.detection.connectorRegistry.approved.map((a, idx) => (idx === i ? { ...a, ...patch } : a));
    setDetection({ connectorRegistry: { ...policy.detection.connectorRegistry, approved } });
  }
  function removeApprovedTool(i: number) {
    if (!policy.detection?.connectorRegistry) return;
    const registry = policy.detection.connectorRegistry;
    setDetection({ connectorRegistry: { ...registry, approved: registry.approved.filter((_, idx) => idx !== i) } });
  }
  function addApprovedTool() {
    const registry = policy.detection?.connectorRegistry ?? defaultConnectorRegistryPolicy();
    setDetection({
      connectorRegistry: { ...registry, approved: [...registry.approved, { upstream: "", tool: "", descriptionHash: "" }] },
    });
  }
  function setPerServerTrust(server: string, cls: TrustClass) {
    if (!policy.detection?.mcpResponse) return;
    setDetection({ mcpResponse: { ...policy.detection.mcpResponse, perServer: { ...policy.detection.mcpResponse.perServer, [server]: cls } } });
  }
  function renamePerServerTrust(oldName: string, newName: string) {
    if (!policy.detection?.mcpResponse) return;
    const perServer = { ...policy.detection.mcpResponse.perServer };
    const cls = perServer[oldName] ?? "scan";
    delete perServer[oldName];
    perServer[newName] = cls;
    setDetection({ mcpResponse: { ...policy.detection.mcpResponse, perServer } });
  }
  function removePerServerTrust(server: string) {
    if (!policy.detection?.mcpResponse) return;
    const perServer = { ...policy.detection.mcpResponse.perServer };
    delete perServer[server];
    setDetection({ mcpResponse: { ...policy.detection.mcpResponse, perServer } });
  }
  function addPerServerTrust() {
    const mcpResponse = policy.detection?.mcpResponse ?? defaultMcpResponsePolicy();
    let key = "server";
    let n = 1;
    while (key in mcpResponse.perServer) key = `server${++n}`;
    setDetection({ mcpResponse: { ...mcpResponse, perServer: { ...mcpResponse.perServer, [key]: "scan" } } });
  }

  // Credential brokering (doc 24 §11 B13 / EG-B). NEVER a value field anywhere below — only a
  // Keychain reference (service + account) per alias; the runtime resolves the real secret at
  // substitution time, from OS Keychain, never from this policy.
  function setAlias(i: number, patch: Partial<SecretAlias>) {
    if (!policy.secrets) return;
    const aliases = policy.secrets.aliases.map((a, idx) => (idx === i ? { ...a, ...patch } : a));
    onChange({ ...policy, secrets: { ...policy.secrets, aliases } });
  }
  function removeAlias(i: number) {
    if (!policy.secrets) return;
    onChange({ ...policy, secrets: { ...policy.secrets, aliases: policy.secrets.aliases.filter((_, idx) => idx !== i) } });
  }
  function addAlias() {
    const secrets = policy.secrets ?? emptySecretsPolicy();
    const aliases = [...secrets.aliases, { alias: "", keychainService: "kriya", keychainAccount: "", allowedHosts: [] as string[] }];
    onChange({ ...policy, secrets: { ...secrets, aliases } });
  }
  function setAliasHosts(i: number, hostsText: string) {
    setAlias(i, { allowedHosts: hostsText.split(",").map((h) => h.trim()).filter(Boolean) });
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

          {noCustomRules && (
            <div className="suggestions" style={{ marginBottom: 12 }}>
              <p className="muted small">
                No rules yet, so every action is denied by default. Add rules top-to-bottom —{" "}
                <b>first match wins</b> — and pick <b>allow</b> / <b>require-approval</b> / <b>deny</b> per
                action pattern (an exact <code>action_id</code> or a <code>prefix_*</code>).
              </p>
              <button className="btn ghost add-rule" onClick={() => addRule()}>
                + Add your first rule
              </button>
            </div>
          )}

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
                These ran but aren't governed yet — click to add a rule:
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
            <p className="field-hint" style={{ marginTop: 8 }}>
              Download this file and point the runtime at it —{" "}
              <code>kriya-mcp --policy agent-policy.yaml</code> (or place it where your host reads it). The
              editor authors the policy; the runtime enforces it.
            </p>
          </article>
        </section>
      </div>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>Egress destinations</h2>
          <label className="budget-row" style={{ margin: 0 }}>
            <input
              type="checkbox"
              checked={policy.egress !== null}
              onChange={(e) => onChange({ ...policy, egress: e.target.checked ? emptyEgressPolicy() : null })}
            />
            Govern egress
          </label>
        </div>
        {policy.egress === null ? (
          <p className="muted small">
            Off — governed-lane egress (MCP connectors, WebFetch) runs unrestricted, and no{" "}
            <code>egress:</code> section is written to <code>agent-policy.yaml</code>. Every call still
            produces a signed evidence receipt when the runtime supports it; this only adds allow /
            require-approval / deny control by destination host.
          </p>
        ) : (
          <>
            <p className="muted small" style={{ marginBottom: 12 }}>
              Host patterns are matched top → bottom against the destination the agent's governed call
              reaches — <code>*.vendor.com</code> matches the domain and its subdomains, <code>*</code>{" "}
              matches any host. A destination matching no rule falls to the posture below.
            </p>
            <div className="rules">
              <div className="rule-head rule-head--egress">
                <span>Host pattern</span>
                <span>Decision</span>
                <span />
              </div>
              {policy.egress.rules.map((r, i) => (
                <div key={i}>
                  <div className="rule rule--egress">
                    <input
                      className="rule-action mono"
                      value={r.host}
                      onChange={(e) => setEgressRule(i, { host: e.target.value })}
                      placeholder="*.vendor.com or an exact host"
                    />
                    <select
                      className={`tier-select tier-${r.tier}`}
                      value={r.tier}
                      onChange={(e) => setEgressRule(i, { tier: e.target.value as Tier })}
                    >
                      {TIERS.map((t) => (
                        <option key={t} value={t}>
                          {TIER_LABEL[t]}
                        </option>
                      ))}
                    </select>
                    <button className="icon-btn danger" onClick={() => removeEgressRule(i)} title="Remove rule" aria-label="Remove egress rule">
                      <Icon name="x" size={12} />
                    </button>
                  </div>
                  <div className="egress-budget-row">
                    <label className="budget-row" style={{ fontSize: 12 }}>
                      <input
                        type="checkbox"
                        checked={r.budgetWindowSecs !== null && r.budgetMaxBytes !== null}
                        onChange={(e) =>
                          setEgressRule(i, e.target.checked ? { budgetWindowSecs: 60, budgetMaxBytes: 1_000_000 } : { budgetWindowSecs: null, budgetMaxBytes: null })
                        }
                      />
                      Byte budget (B2, anti slow-drip exfil)
                    </label>
                    {r.budgetWindowSecs !== null && (
                      <>
                        <input
                          type="number"
                          min={1}
                          value={r.budgetWindowSecs}
                          onChange={(e) => setEgressRule(i, { budgetWindowSecs: Math.max(1, Number(e.target.value) || 1) })}
                          title="Window (seconds)"
                        />
                        <span>secs /</span>
                        <input
                          type="number"
                          min={1}
                          value={r.budgetMaxBytes ?? 0}
                          onChange={(e) => setEgressRule(i, { budgetMaxBytes: Math.max(1, Number(e.target.value) || 1) })}
                          title="Max bytes"
                        />
                      </>
                    )}
                  </div>
                </div>
              ))}
            </div>
            <button className="btn ghost add-rule" onClick={addEgressRule}>
              + Add destination
            </button>

            <div className="budget" style={{ marginTop: 16 }}>
              <h3>Unlisted destinations</h3>
              <label className="budget-row">
                Posture for a host no rule matches:
                <select
                  className="tier-select"
                  value={policy.egress.unlisted}
                  onChange={(e) => onChange({ ...policy, egress: { ...policy.egress!, unlisted: e.target.value as UnlistedPosture } })}
                >
                  {UNLISTED_POSTURES.map((u) => (
                    <option key={u} value={u}>
                      {UNLISTED_LABEL[u]}
                    </option>
                  ))}
                </select>
              </label>
              <p className="field-hint">
                <b>Deny (deny-by-default)</b> also arms the broker's startup allowlist check: a remote
                MCP upstream on a denied host refuses to connect at all, receipted at boot.
              </p>
              <label className="budget-row">
                <input
                  type="checkbox"
                  checked={policy.egress.failClosed}
                  onChange={(e) => onChange({ ...policy, egress: { ...policy.egress!, failClosed: e.target.checked } })}
                />
                Fail closed — deny an egress if its signed receipt can't be written
              </label>
              <label className="budget-row">
                <input
                  type="checkbox"
                  checked={policy.egress.recordIngress}
                  onChange={(e) => onChange({ ...policy, egress: { ...policy.egress!, recordIngress: e.target.checked } })}
                />
                Record ingress digests (keyed hash of responses; off by default)
              </label>
            </div>
          </>
        )}
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>Detection pack</h2>
          <label className="budget-row" style={{ margin: 0 }}>
            <input
              type="checkbox"
              checked={policy.detection !== null}
              onChange={(e) => onChange({ ...policy, detection: e.target.checked ? emptyDetectionPolicy() : null })}
            />
            Enable
          </label>
        </div>
        {policy.detection === null ? (
          <p className="muted small">
            Off — no <code>detection:</code> section is written to <code>agent-policy.yaml</code>. Each
            detector below is its OWN independent switch: turning the pack on here never activates any
            of them — every one stays off until you opt it in individually (doc 24 §11's "never
            auto-block silently by default").
          </p>
        ) : (
          <>
            <div className="detect-card">
              <div className="detect-card-head">
                <h3>DNS-exfil heuristic (B5)</h3>
                <label className="budget-row" style={{ margin: 0 }}>
                  <input
                    type="checkbox"
                    checked={policy.detection.dnsExfil !== null}
                    onChange={(e) => setDetection({ dnsExfil: e.target.checked ? defaultDnsExfilPolicy() : null })}
                  />
                  On
                </label>
              </div>
              <p className="field-hint">
                Flags a destination whose subdomain label has unusually high character entropy — the
                classic shape of data encoded into a subdomain of an otherwise-allowed wildcard host.
              </p>
              {policy.detection.dnsExfil && (
                <div className="budget-row" style={{ gap: 12 }}>
                  <label className="budget-row" style={{ fontSize: 12 }}>
                    Entropy threshold (bits/char)
                    <input
                      type="number"
                      min={0}
                      step={0.1}
                      className="budget-input"
                      style={{ marginTop: 0 }}
                      value={policy.detection.dnsExfil.entropyThreshold}
                      onChange={(e) =>
                        setDetection({ dnsExfil: { ...policy.detection!.dnsExfil!, entropyThreshold: Number(e.target.value) || 0 } })
                      }
                    />
                  </label>
                  <select
                    className="tier-select"
                    value={policy.detection.dnsExfil.action}
                    onChange={(e) => setDetection({ dnsExfil: { ...policy.detection!.dnsExfil!, action: e.target.value as AlertOrDeny } })}
                  >
                    {ALERT_OR_DENY.map((a) => (
                      <option key={a} value={a}>
                        {ALERT_OR_DENY_LABEL[a]}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="detect-card">
              <div className="detect-card-head">
                <h3>SSRF / rebinding guard (B6)</h3>
                <label className="budget-row" style={{ margin: 0 }}>
                  <input
                    type="checkbox"
                    checked={policy.detection.ssrfGuard !== null}
                    onChange={(e) => setDetection({ ssrfGuard: e.target.checked ? defaultSsrfGuardPolicy() : null })}
                  />
                  On
                </label>
              </div>
              <p className="field-hint">
                Rejects loopback/RFC1918/link-local/cloud-metadata destinations and pins the resolved
                IP for the connection, so a DNS rebind between the check and the connect can't swap in
                a different address. A real security control, not a tunable heuristic — the only dial
                is whether it's on. Gated (not unconditional): a local dev/test upstream on{" "}
                <code>127.0.0.1</code>/<code>localhost</code> is a legitimate target.
              </p>
            </div>

            <div className="detect-card">
              <div className="detect-card-head">
                <h3>Secret + PII scan (B7)</h3>
                <label className="budget-row" style={{ margin: 0 }}>
                  <input
                    type="checkbox"
                    checked={policy.detection.secretPii !== null}
                    onChange={(e) => setDetection({ secretPii: e.target.checked ? defaultSecretPiiPolicy() : null })}
                  />
                  On
                </label>
              </div>
              <p className="field-hint">
                Scans outbound governed bodies for AWS keys, GitHub PATs, JWTs, private-key headers,
                emails, Luhn-valid card numbers, and SSNs. On a match, either flag it (the receipt
                records the TYPE name only — never the matched value) or deny.
              </p>
              {policy.detection.secretPii && (
                <select
                  className="tier-select"
                  value={policy.detection.secretPii.action}
                  onChange={(e) => setDetection({ secretPii: { ...policy.detection!.secretPii!, action: e.target.value as RedactOrDeny } })}
                >
                  {REDACT_OR_DENY.map((a) => (
                    <option key={a} value={a}>
                      {REDACT_OR_DENY_LABEL[a]}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div className="detect-card">
              <h3>Operation rails (B8)</h3>
              <p className="field-hint">
                An allowlist fence narrower than a host rule — per destination, only the listed HTTP
                verb+path globs or GraphQL mutation names may proceed; anything else on a railed host
                is denied, and a call the rail can't parse fails closed.
              </p>
              {policy.detection.operationRails.length > 0 && (
                <div className="rules" style={{ marginTop: 8 }}>
                  <div className="rule-head rule-head--rail">
                    <span>Host</span>
                    <span>Method</span>
                    <span>Path / GraphQL mutation</span>
                    <span>Decision</span>
                    <span />
                  </div>
                  {policy.detection.operationRails.map((r, i) => (
                    <div className="rule rule--rail" key={i}>
                      <input className="rule-action mono" value={r.host} onChange={(e) => setRail(i, { host: e.target.value })} placeholder="*.vendor.com" />
                      <input className="rule-action mono" value={r.method} onChange={(e) => setRail(i, { method: e.target.value })} placeholder="GET / *" />
                      <input
                        className="rule-action mono"
                        value={r.graphqlMutation ?? r.path ?? ""}
                        onChange={(e) => {
                          const v = e.target.value;
                          const looksLikeMutation = /^[A-Za-z_][A-Za-z0-9_]*$/.test(v) && !v.includes("/");
                          setRail(i, looksLikeMutation && v ? { path: null, graphqlMutation: v } : { path: v, graphqlMutation: null });
                        }}
                        placeholder="/v1/* or a mutation name"
                      />
                      <select className={`tier-select tier-${r.tier}`} value={r.tier} onChange={(e) => setRail(i, { tier: e.target.value as Tier })}>
                        {TIERS.map((t) => (
                          <option key={t} value={t}>
                            {TIER_LABEL[t]}
                          </option>
                        ))}
                      </select>
                      <button className="icon-btn danger" onClick={() => removeRail(i)} title="Remove rail" aria-label="Remove operation rail">
                        <Icon name="x" size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
              <button className="btn ghost add-rule" onClick={addRail}>
                + Add operation rail
              </button>
            </div>

            <div className="detect-card">
              <h3>Canary tokens (B9)</h3>
              <p className="field-hint">
                Operator-planted honeytoken strings — bait credentials that should never legitimately
                appear in real traffic. ANY match in an outbound body is always-deny, no soft mode:
                there's no legitimate reason for one to ever cross a governed lane.
              </p>
              {policy.detection.canaryTokens.length > 0 && (
                <div className="rules" style={{ marginTop: 8 }}>
                  <div className="rule-head rule-head--token">
                    <span>Token</span>
                    <span />
                  </div>
                  {policy.detection.canaryTokens.map((t, i) => (
                    <div className="rule rule--token" key={i}>
                      <input className="rule-action mono" value={t} onChange={(e) => setCanaryToken(i, e.target.value)} placeholder="planted-bait-token" />
                      <button className="icon-btn danger" onClick={() => removeCanaryToken(i)} title="Remove token" aria-label="Remove canary token">
                        <Icon name="x" size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
              <button className="btn ghost add-rule" onClick={addCanaryToken}>
                + Add canary token
              </button>
            </div>

            <div className="detect-card">
              <div className="detect-card-head">
                <h3>Connector registry (B10)</h3>
                <label className="budget-row" style={{ margin: 0 }}>
                  <input
                    type="checkbox"
                    checked={policy.detection.connectorRegistry !== null}
                    onChange={(e) => setDetection({ connectorRegistry: e.target.checked ? defaultConnectorRegistryPolicy() : null })}
                  />
                  On
                </label>
              </div>
              <p className="field-hint">
                A discovered MCP tool is disabled-until-approved unless it's listed below with a
                matching live description hash. A hash mismatch against an approved entry is drift —
                the tool-poisoning signal — and disables it again until re-approved.
              </p>
              {policy.detection.connectorRegistry && (
                <>
                  {policy.detection.connectorRegistry.approved.length > 0 && (
                    <div className="rules" style={{ marginTop: 8 }}>
                      <div className="rule-head rule-head--approved">
                        <span>Upstream</span>
                        <span>Tool</span>
                        <span>Description hash</span>
                        <span />
                      </div>
                      {policy.detection.connectorRegistry.approved.map((a, i) => (
                        <div className="rule rule--approved" key={i}>
                          <input className="rule-action mono" value={a.upstream} onChange={(e) => setApprovedTool(i, { upstream: e.target.value })} placeholder="widgets" />
                          <input className="rule-action mono" value={a.tool} onChange={(e) => setApprovedTool(i, { tool: e.target.value })} placeholder="list_widgets" />
                          <input
                            className="rule-action mono"
                            value={a.descriptionHash}
                            onChange={(e) => setApprovedTool(i, { descriptionHash: e.target.value })}
                            placeholder="sha256 hex"
                          />
                          <button className="icon-btn danger" onClick={() => removeApprovedTool(i)} title="Revoke approval" aria-label="Revoke connector tool approval">
                            <Icon name="x" size={12} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  <button className="btn ghost add-rule" onClick={addApprovedTool}>
                    + Approve connector tool
                  </button>
                </>
              )}
            </div>

            <div className="detect-card">
              <h3>Read-only presets (B11)</h3>
              <p className="field-hint">
                Connector NAMESPACE patterns (a bare <code>widgets</code> is equivalent to{" "}
                <code>widgets__*</code>) whose known-mutating tools are denied — a hard override the
                explicit action rules above can never widen back open.
              </p>
              {policy.detection.readOnly.length > 0 && (
                <div className="rules" style={{ marginTop: 8 }}>
                  <div className="rule-head rule-head--token">
                    <span>Connector namespace</span>
                    <span />
                  </div>
                  {policy.detection.readOnly.map((r, i) => (
                    <div className="rule rule--token" key={i}>
                      <input className="rule-action mono" value={r} onChange={(e) => setReadOnlyEntry(i, e.target.value)} placeholder="widgets" />
                      <button className="icon-btn danger" onClick={() => removeReadOnlyEntry(i)} title="Remove preset" aria-label="Remove read-only preset">
                        <Icon name="x" size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
              <button className="btn ghost add-rule" onClick={addReadOnlyEntry}>
                + Add read-only connector
              </button>
            </div>

            <div className="detect-card">
              <div className="detect-card-head">
                <h3>MCP response trust classes (B12)</h3>
                <label className="budget-row" style={{ margin: 0 }}>
                  <input
                    type="checkbox"
                    checked={policy.detection.mcpResponse !== null}
                    onChange={(e) => setDetection({ mcpResponse: e.target.checked ? defaultMcpResponsePolicy() : null })}
                  />
                  On
                </label>
              </div>
              <p className="field-hint">
                Per-server trust class on governed MCP ingress. <b>Trusted</b> passes a response
                through unchanged; <b>scan</b> (default) runs the B7 secret/PII pass over it and flags
                a match without blocking; <b>block</b> denies the response outright regardless of
                content.
              </p>
              {policy.detection.mcpResponse && (
                <>
                  <label className="budget-row">
                    Default class for an unlisted server:
                    <select
                      className="tier-select"
                      value={policy.detection.mcpResponse.defaultClass}
                      onChange={(e) => setDetection({ mcpResponse: { ...policy.detection!.mcpResponse!, defaultClass: e.target.value as TrustClass } })}
                    >
                      {TRUST_CLASSES.map((c) => (
                        <option key={c} value={c}>
                          {TRUST_CLASS_LABEL[c]}
                        </option>
                      ))}
                    </select>
                  </label>
                  {Object.keys(policy.detection.mcpResponse.perServer).length > 0 && (
                    <div className="rules" style={{ marginTop: 8 }}>
                      <div className="rule-head rule-head--trust">
                        <span>Server (upstream namespace)</span>
                        <span>Trust class</span>
                        <span />
                      </div>
                      {Object.entries(policy.detection.mcpResponse.perServer).map(([server, cls], i) => (
                        <div className="rule rule--trust" key={i}>
                          <input className="rule-action mono" value={server} onChange={(e) => renamePerServerTrust(server, e.target.value)} placeholder="widgets" />
                          <select className="tier-select" value={cls} onChange={(e) => setPerServerTrust(server, e.target.value as TrustClass)}>
                            {TRUST_CLASSES.map((c) => (
                              <option key={c} value={c}>
                                {TRUST_CLASS_LABEL[c]}
                              </option>
                            ))}
                          </select>
                          <button className="icon-btn danger" onClick={() => removePerServerTrust(server)} title="Remove override" aria-label="Remove per-server trust override">
                            <Icon name="x" size={12} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  <button className="btn ghost add-rule" onClick={addPerServerTrust}>
                    + Add per-server override
                  </button>
                </>
              )}
            </div>
          </>
        )}
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>Credential brokering</h2>
          <label className="budget-row" style={{ margin: 0 }}>
            <input
              type="checkbox"
              checked={policy.secrets !== null}
              onChange={(e) => onChange({ ...policy, secrets: e.target.checked ? emptySecretsPolicy() : null })}
            />
            Enable
          </label>
        </div>
        {policy.secrets === null ? (
          <p className="muted small">
            Off — no <code>secrets:</code> section is written to <code>agent-policy.yaml</code>. The
            agent never holds a real credential, only a placeholder like{" "}
            <code>{"{{kriya:github_pat}}"}</code>; the runtime substitutes the real value from OS
            Keychain at the moment a call actually leaves the machine, scoped to that one alias's own
            destination allowlist. See <code>docs/THREAT-MODEL-brokering.md</code>.
          </p>
        ) : (
          <>
            <p className="field-hint" style={{ marginBottom: 12 }}>
              Each row below is a <b>reference</b> — a macOS Keychain service + account — never a
              value. Only the runtime, at substitution time, ever reads the real secret from Keychain;
              this policy (and this Console) never sees it. <b>Allowed destinations</b> is this
              alias's own scope, independent of the general egress rules above: a placeholder bound
              for a host not listed here is denied, never substituted.
            </p>
            {policy.secrets.aliases.length > 0 && (
              <div className="rules">
                <div className="rule-head rule-head--secret">
                  <span>Alias (used as {"{{kriya:<alias>}}"})</span>
                  <span>Keychain service</span>
                  <span>Keychain account</span>
                  <span>Allowed destinations</span>
                  <span />
                </div>
                {policy.secrets.aliases.map((a, i) => (
                  <div className="rule rule--secret" key={i}>
                    <input
                      className="rule-action mono"
                      value={a.alias}
                      onChange={(e) => setAlias(i, { alias: e.target.value })}
                      placeholder="github_pat"
                    />
                    <input
                      className="rule-action mono"
                      value={a.keychainService}
                      onChange={(e) => setAlias(i, { keychainService: e.target.value })}
                      placeholder="kriya"
                    />
                    <input
                      className="rule-action mono"
                      value={a.keychainAccount}
                      onChange={(e) => setAlias(i, { keychainAccount: e.target.value })}
                      placeholder="github_pat"
                    />
                    <input
                      className="rule-action mono"
                      value={a.allowedHosts.join(", ")}
                      onChange={(e) => setAliasHosts(i, e.target.value)}
                      placeholder="*.github.com"
                    />
                    <button className="icon-btn danger" onClick={() => removeAlias(i)} title="Remove alias" aria-label="Remove brokered alias">
                      <Icon name="x" size={12} />
                    </button>
                  </div>
                ))}
              </div>
            )}
            <button className="btn ghost add-rule" onClick={addAlias}>
              + Add brokered alias
            </button>
          </>
        )}
      </section>
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
