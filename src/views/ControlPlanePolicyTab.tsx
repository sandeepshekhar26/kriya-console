import { useEffect, useMemo, useState } from "react";
import { Icon } from "../components/Icon";
import { diffLines } from "../lib/textDiff";
import {
  fleetPolicyPreview,
  fleetPublishPolicy,
  orgPolicyKeygen,
  type OrgKeyInfo,
  type PolicyBundleDraft,
  type PublishResult,
} from "../lib/tauri";

const DEFAULT_POLICY_JSON = JSON.stringify({ rules: [{ action: "*", allow: true }] }, null, 2);
const DEFAULT_BUDGETS_JSON = JSON.stringify({ max_actions_per_minute: 60 }, null, 2);

type GovernChoice = "no-change" | "wire" | "unwire";

/** Everything the draft form + the diff/publish steps need, assembled fresh on every render from form
 *  state — kept as one function so "what would be published" and "what's shown in the diff" can never
 *  silently diverge. */
function assembleDraftBundle(form: {
  orgId: string;
  businessUnit: string;
  devicePubsText: string;
  expiresMsText: string;
  policyJson: string;
  budgetsJson: string;
  envelopeVerbosity: string;
  governClaudeCode: GovernChoice;
  governHermes: GovernChoice;
  killSwitch: boolean;
  ioVerbosity: string;
  purposeStatement: string;
}): { ok: true; text: string } | { ok: false; error: string } {
  let policy: unknown;
  let budgets: unknown;
  try {
    policy = JSON.parse(form.policyJson || "{}");
  } catch (e) {
    return { ok: false, error: `Policy JSON: ${e instanceof Error ? e.message : String(e)}` };
  }
  try {
    budgets = JSON.parse(form.budgetsJson || "{}");
  } catch (e) {
    return { ok: false, error: `Budgets JSON: ${e instanceof Error ? e.message : String(e)}` };
  }
  const devicePubs = form.devicePubsText
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const expiresMs = form.expiresMsText.trim() === "" ? null : Number(form.expiresMsText.trim());
  if (expiresMs !== null && !Number.isFinite(expiresMs)) {
    return { ok: false, error: "Expires (ms since epoch) must be a number" };
  }
  const govern: { target: string; action: string }[] = [];
  if (form.governClaudeCode !== "no-change") govern.push({ target: "claude-code", action: form.governClaudeCode });
  if (form.governHermes !== "no-change") govern.push({ target: "hermes", action: form.governHermes });

  const shape = {
    org_id: form.orgId,
    scope: {
      business_unit: form.businessUnit.trim() || null,
      device_pubs: devicePubs.length > 0 ? devicePubs : null,
    },
    expires_ms: expiresMs,
    policy,
    budgets,
    govern,
    envelope_verbosity: form.envelopeVerbosity,
    // Omitted (never a literal `false`) when off — matches the Rust `skip_serializing_if` shape so
    // an off bundle's diff/hash never spuriously differs just because this field exists (see
    // `src/lib/policyBundle.ts`'s `PolicyBundle.kill_switch` doc comment).
    ...(form.killSwitch ? { kill_switch: true } : {}),
    // Same omit-when-default treatment as kill_switch — "off" (io_verbosity) must never appear
    // literally, matching the Rust `is_io_verbosity_off` skip_serializing_if.
    ...(form.ioVerbosity !== "off" ? { io_verbosity: form.ioVerbosity } : {}),
    ...(form.purposeStatement.trim() ? { purpose_statement: form.purposeStatement.trim() } : {}),
  };
  return { ok: true, text: JSON.stringify(shape, null, 2) };
}

/** The same "assembled shape" for an already-published bundle, so the diff compares like with like. */
function assembleLatestText(bundle: PolicyBundleDraft): string {
  return JSON.stringify(
    {
      org_id: bundle.org_id,
      scope: {
        business_unit: bundle.scope.business_unit ?? null,
        device_pubs: bundle.scope.device_pubs ?? null,
      },
      expires_ms: bundle.expires_ms ?? null,
      policy: bundle.policy,
      budgets: bundle.budgets,
      govern: bundle.govern ?? [],
      envelope_verbosity: bundle.envelope_verbosity ?? "standard",
      ...(bundle.kill_switch ? { kill_switch: true } : {}),
      ...(bundle.io_verbosity && bundle.io_verbosity !== "off" ? { io_verbosity: bundle.io_verbosity } : {}),
      ...(bundle.purpose_statement ? { purpose_statement: bundle.purpose_statement } : {}),
    },
    null,
    2,
  );
}

/**
 * The Policy tab (doc 22 §5, P3): author → preview diff vs latest → Sign & Publish. Signing happens
 * Rust-side against the OS-keychain-held org key (`org_policy_keygen`/`sign_with_org_key`) — this view
 * never sees or handles the private key. `version` is likewise computed server-side
 * (`fleet_publish_policy`), never editable here — anti-rollback must not be foilable from the UI.
 */
export function ControlPlanePolicyTab() {
  const [latest, setLatest] = useState<{ bundle: PolicyBundleDraft; signature: string } | null | undefined>(
    undefined,
  );
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const [orgId, setOrgId] = useState("");
  const [businessUnit, setBusinessUnit] = useState("");
  const [devicePubsText, setDevicePubsText] = useState("");
  const [expiresMsText, setExpiresMsText] = useState("");
  const [policyJson, setPolicyJson] = useState(DEFAULT_POLICY_JSON);
  const [budgetsJson, setBudgetsJson] = useState(DEFAULT_BUDGETS_JSON);
  const [envelopeVerbosity, setEnvelopeVerbosity] = useState("standard");
  const [governClaudeCode, setGovernClaudeCode] = useState<GovernChoice>("no-change");
  const [governHermes, setGovernHermes] = useState<GovernChoice>("no-change");
  const [killSwitch, setKillSwitch] = useState(false);
  const [ioVerbosity, setIoVerbosity] = useState("off");
  const [purposeStatement, setPurposeStatement] = useState("");

  const [orgKey, setOrgKey] = useState<OrgKeyInfo | null>(null);
  const [keygenBusy, setKeygenBusy] = useState(false);
  const [keygenErr, setKeygenErr] = useState<string | null>(null);

  const [publishing, setPublishing] = useState(false);
  const [publishErr, setPublishErr] = useState<string | null>(null);
  const [publishResult, setPublishResult] = useState<PublishResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    fleetPolicyPreview()
      .then((r) => {
        if (cancelled) return;
        setLatest(r);
        if (r) {
          setOrgId(r.bundle.org_id);
          setBusinessUnit(r.bundle.scope.business_unit ?? "");
          setDevicePubsText((r.bundle.scope.device_pubs ?? []).join(", "));
          setExpiresMsText(r.bundle.expires_ms != null ? String(r.bundle.expires_ms) : "");
          setPolicyJson(JSON.stringify(r.bundle.policy, null, 2));
          setBudgetsJson(JSON.stringify(r.bundle.budgets, null, 2));
          setEnvelopeVerbosity(r.bundle.envelope_verbosity || "standard");
          setKillSwitch(r.bundle.kill_switch ?? false);
          setIoVerbosity(r.bundle.io_verbosity || "off");
          setPurposeStatement(r.bundle.purpose_statement ?? "");
        }
      })
      .catch((e) => {
        if (cancelled) return;
        setLoadErr(String(e));
        setLatest(null); // clear the loading state — the form still works from defaults
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const draft = useMemo(
    () =>
      assembleDraftBundle({
        orgId,
        businessUnit,
        devicePubsText,
        expiresMsText,
        policyJson,
        budgetsJson,
        envelopeVerbosity,
        governClaudeCode,
        governHermes,
        killSwitch,
        ioVerbosity,
        purposeStatement,
      }),
    [
      orgId,
      businessUnit,
      devicePubsText,
      expiresMsText,
      policyJson,
      budgetsJson,
      envelopeVerbosity,
      governClaudeCode,
      governHermes,
      killSwitch,
      ioVerbosity,
      purposeStatement,
    ],
  );

  const diff = useMemo(() => {
    if (!draft.ok) return null;
    const oldText = latest ? assembleLatestText(latest.bundle) : "// nothing published yet";
    return diffLines(oldText, draft.text);
  }, [draft, latest]);

  async function generateOrgKey() {
    setKeygenBusy(true);
    setKeygenErr(null);
    try {
      setOrgKey(await orgPolicyKeygen());
    } catch (e) {
      setKeygenErr(String(e));
    } finally {
      setKeygenBusy(false);
    }
  }

  async function publish() {
    if (!draft.ok) return;
    setPublishing(true);
    setPublishErr(null);
    setPublishResult(null);
    try {
      const parsed = JSON.parse(draft.text) as { policy: Record<string, unknown>; budgets: Record<string, unknown> };
      const result = await fleetPublishPolicy({
        orgId,
        businessUnit: businessUnit.trim() || null,
        devicePubs: devicePubsText
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        expiresMs: expiresMsText.trim() === "" ? null : Number(expiresMsText.trim()),
        policy: parsed.policy,
        budgets: parsed.budgets,
        govern: [
          ...(governClaudeCode !== "no-change" ? [{ target: "claude-code", action: governClaudeCode }] : []),
          ...(governHermes !== "no-change" ? [{ target: "hermes", action: governHermes }] : []),
        ],
        envelopeVerbosity,
        killSwitch,
        ioVerbosity,
        purposeStatement: purposeStatement.trim() || null,
      });
      setPublishResult(result);
      // Refresh "latest" so a second publish diffs against what just landed.
      const refreshed = await fleetPolicyPreview();
      setLatest(refreshed);
    } catch (e) {
      setPublishErr(String(e));
    } finally {
      setPublishing(false);
    }
  }

  if (latest === undefined) {
    return (
      <div className="cp-line running" style={{ margin: "24px 0" }}>
        <span className="dot live" /> loading the latest published bundle…
      </div>
    );
  }

  return (
    <div>
      {loadErr && (
        <div className="cp-line bad" style={{ marginBottom: 14 }}>
          <Icon name="x" size={15} />
          <div>
            <div className="cp-line-label">Could not load the latest bundle</div>
            <div className="cp-line-detail">{loadErr}</div>
          </div>
        </div>
      )}

      <section className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>Org signing key</h2>
        </div>
        <p className="muted small" style={{ margin: "0 0 12px" }}>
          Every bundle is signed with this Ed25519 key, held in this machine's OS keychain — kriyad
          never sees the private half. Generate it once; devices pin the public half via enrollment/MDM.
        </p>
        {orgKey ? (
          <div className="cp-line ok">
            <Icon name="check" size={15} />
            <div>
              <div className="cp-line-label">
                {orgKey.generated ? "New org key generated" : "Org key already exists"}
              </div>
              <div className="cp-line-detail mono">org_policy_pub: {orgKey.orgPolicyPub}</div>
              <div className="cp-line-detail">Exported to {orgKey.pubPath}</div>
            </div>
          </div>
        ) : (
          <button className="btn" disabled={keygenBusy} onClick={() => void generateOrgKey()}>
            <Icon name="key" size={14} /> {keygenBusy ? "Generating…" : "Generate / show org signing key"}
          </button>
        )}
        {keygenErr && <p className="warn-text small" style={{ marginTop: 8 }}>{keygenErr}</p>}
      </section>

      <section className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>Author</h2>
          <span className="muted small">
            {latest ? `seeded from the latest published bundle (v${latest.bundle.version})` : "no bundle published yet — starting from defaults"}
          </span>
        </div>

        <div className="field" style={{ marginBottom: 12 }}>
          <label className="field-label" htmlFor="pol-org">Org id</label>
          <input id="pol-org" type="text" value={orgId} onChange={(e) => setOrgId(e.target.value)} />
        </div>

        <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
          <div className="field" style={{ flex: 1 }}>
            <label className="field-label" htmlFor="pol-bu">Business unit (scope, blank = all)</label>
            <input id="pol-bu" type="text" placeholder="* or a BU name" value={businessUnit} onChange={(e) => setBusinessUnit(e.target.value)} />
          </div>
          <div className="field" style={{ flex: 1 }}>
            <label className="field-label" htmlFor="pol-devs">Device pubs (scope, comma-separated, blank = all)</label>
            <input id="pol-devs" type="text" value={devicePubsText} onChange={(e) => setDevicePubsText(e.target.value)} />
          </div>
        </div>

        <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
          <div className="field" style={{ flex: 1 }}>
            <label className="field-label" htmlFor="pol-exp">Expires (ms since epoch, blank = never)</label>
            <input id="pol-exp" type="text" value={expiresMsText} onChange={(e) => setExpiresMsText(e.target.value)} />
          </div>
          <div className="field" style={{ flex: 1 }}>
            <label className="field-label" htmlFor="pol-verbosity">Envelope verbosity</label>
            <select id="pol-verbosity" value={envelopeVerbosity} onChange={(e) => setEnvelopeVerbosity(e.target.value)}>
              <option value="standard">standard</option>
              <option value="extended">extended</option>
            </select>
          </div>
        </div>

        <div className="field" style={{ marginBottom: 12 }}>
          <span className="field-label">Govern (doc-21 detect→wire engine)</span>
          <div style={{ display: "flex", gap: 16, marginTop: 4 }}>
            <label className="field-inline">
              Claude Code
              <select value={governClaudeCode} onChange={(e) => setGovernClaudeCode(e.target.value as GovernChoice)}>
                <option value="no-change">no change</option>
                <option value="wire">wire</option>
                <option value="unwire">unwire</option>
              </select>
            </label>
            <label className="field-inline">
              Hermes
              <select value={governHermes} onChange={(e) => setGovernHermes(e.target.value as GovernChoice)}>
                <option value="no-change">no change</option>
                <option value="wire">wire</option>
                <option value="unwire">unwire</option>
              </select>
            </label>
          </div>
        </div>

        <div
          className="field"
          style={{
            marginBottom: 12,
            padding: 10,
            borderRadius: 6,
            border: "1px solid var(--line-strong)",
            background: killSwitch ? "var(--bad-bg)" : undefined,
          }}
        >
          <label className="field-inline" style={{ gap: 8 }}>
            <input
              id="pol-kill-switch"
              type="checkbox"
              checked={killSwitch}
              onChange={(e) => setKillSwitch(e.target.checked)}
            />
            <span className={killSwitch ? "warn-text" : undefined}>
              Kill switch — every device applying this bundle falls back to deny-all, ignoring the
              policy/budgets below
            </span>
          </label>
        </div>

        <div
          className="field"
          style={{
            marginBottom: 12,
            padding: 10,
            borderRadius: 6,
            border: "1px solid var(--line-strong)",
            background: ioVerbosity !== "off" ? "var(--warn-bg)" : undefined,
          }}
        >
          <div style={{ display: "flex", gap: 12, alignItems: "flex-end" }}>
            <div className="field" style={{ flex: 1 }}>
              <label className="field-label" htmlFor="pol-io-verbosity">Fleet destination visibility (pattern-echo)</label>
              <select id="pol-io-verbosity" value={ioVerbosity} onChange={(e) => setIoVerbosity(e.target.value)}>
                <option value="off">off (default)</option>
                <option value="pattern-echo">pattern-echo</option>
              </select>
            </div>
            <div className="field" style={{ flex: 2 }}>
              <label className="field-label" htmlFor="pol-purpose">Purpose statement (echoed in every export)</label>
              <input
                id="pol-purpose"
                type="text"
                placeholder="e.g. compliance/security evidence; never performance evaluation"
                value={purposeStatement}
                onChange={(e) => setPurposeStatement(e.target.value)}
                disabled={ioVerbosity === "off"}
              />
            </div>
          </div>
          {ioVerbosity !== "off" && (
            <p className={"small"} style={{ marginTop: 8 }}>
              <span className="warn-text">
                Devices start echoing which operator-authored destination pattern each egress call
                matched (never a raw host) into their signed envelopes. This is new per-device
                metadata — confirm your works-council/GDPR review is complete before publishing (see
                TRUST.md). Small counts stay withheld in the fleet report until explicitly revealed,
                and every reveal is itself a signed, chained event.
              </span>
            </p>
          )}
        </div>

        <div style={{ display: "flex", gap: 12, marginBottom: 4 }}>
          <div className="field" style={{ flex: 1 }}>
            <label className="field-label" htmlFor="pol-policy">Policy (rules — JSON)</label>
            <textarea
              id="pol-policy"
              className="import-text mono"
              rows={8}
              value={policyJson}
              onChange={(e) => setPolicyJson(e.target.value)}
            />
          </div>
          <div className="field" style={{ flex: 1 }}>
            <label className="field-label" htmlFor="pol-budgets">Budgets (JSON)</label>
            <textarea
              id="pol-budgets"
              className="import-text mono"
              rows={8}
              value={budgetsJson}
              onChange={(e) => setBudgetsJson(e.target.value)}
            />
          </div>
        </div>
      </section>

      <section className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>Preview diff vs latest</h2>
        </div>
        {!draft.ok ? (
          <p className="warn-text small">{draft.error}</p>
        ) : (
          <pre className="well" style={{ whiteSpace: "pre-wrap" }}>
            {diff!.map((l, i) => (
              <div
                key={i}
                className={l.kind === "added" ? "diff-added" : l.kind === "removed" ? "diff-removed" : undefined}
              >
                {l.kind === "added" ? "+ " : l.kind === "removed" ? "- " : "  "}
                {l.text}
              </div>
            ))}
          </pre>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Sign &amp; publish</h2>
        </div>
        <p className="muted small" style={{ margin: "0 0 12px" }}>
          Signs the draft above with the org key (OS keychain) and publishes it to your connected
          kriyad. The version is computed automatically — it is never editable here.
        </p>
        <button
          className="btn primary"
          disabled={!draft.ok || publishing}
          onClick={() => void publish()}
        >
          <Icon name="shield-check" size={14} /> {publishing ? "Publishing…" : "Sign & Publish"}
        </button>

        {publishErr && (
          <div className="cp-line bad" style={{ marginTop: 12 }}>
            <Icon name="x" size={15} />
            <div>
              <div className="cp-line-label">Publish failed</div>
              <div className="cp-line-detail">{publishErr}</div>
            </div>
          </div>
        )}
        {publishResult && (
          <div className="cp-line ok" style={{ marginTop: 12 }}>
            <Icon name="check" size={15} />
            <div>
              <div className="cp-line-label">
                Published version {publishResult.version}
                {publishResult.duplicate ? " (already published — no-op)" : ""}
              </div>
              <div className="cp-line-detail">
                Devices pick this up on their next heartbeat, verify it against their pinned org key, and
                apply it if it supersedes what they already have.
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
