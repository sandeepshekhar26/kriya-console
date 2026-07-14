import { load, dump } from "js-yaml";

/**
 * Policy model — a faithful TypeScript port of `crates/kriya/src/permissions.rs`.
 *
 * The host evaluates rules top-to-bottom; the FIRST matching rule wins, and no match
 * means Deny (deny-by-default). A rule maps an action pattern to a tier:
 *   - allow                → `allow: true`
 *   - require human approval → `allow: true, require_approval: true`
 *   - deny                 → `allow: false`
 * The console edits this model and emits the same YAML the host loads.
 */

export type Tier = "allow" | "approval" | "deny";

export interface PolicyRule {
  /** Exact action id, a `prefix_*` glob, or `*` for all. Order matters (first match wins). */
  action: string;
  tier: Tier;
}

export interface Policy {
  rules: PolicyRule[];
  /** Max actions per trailing 60s window. `null` = no cap. */
  maxActionsPerMinute: number | null;
  /** Max inference/API calls per trailing 60-minute window (R11). `null` = no cap. Independent of
   *  the per-minute action cap: bounds model *cost*, not action bursts. */
  maxApiCallsPerHour: number | null;
  /** The egress destination tier (doc 24 §7.3 / EG-2). `null` = no `egress:` section authored — the
   *  runtime's egress governance is OFF, byte-identical to pre-EG-2 (BC-3: no `egress:` key is ever
   *  written to the YAML for this state, so an unmodified policy round-trips unchanged). */
  egress: EgressPolicy | null;
  /** The detection pack (doc 24 §11 B5–B12 / EG-P). `null` = no `detection:` section authored — same
   *  BC-3 round-trip discipline as `egress`. Each sub-detector inside is ALSO independently nullable
   *  (mirrors `permissions::DetectionPolicy`'s `Option` fields), so authoring the pack at all never
   *  silently turns on a specific detector. */
  detection: DetectionPolicy | null;
  /** Credential brokering (doc 24 §11 B13 / EG-B). `null` = no `secrets:` section authored — same
   *  BC-3 round-trip discipline as `egress`/`detection`. NEVER carries a secret VALUE — only a
   *  reference (Keychain service + account) per alias; the runtime resolves the real value at
   *  substitution time, from OS Keychain, never from this policy. See
   *  `docs/THREAT-MODEL-brokering.md`. */
  secrets: SecretsPolicy | null;
}

/** What happens to an egress destination no rule matches. Mirrors `permissions::UnlistedPosture`. */
export type UnlistedPosture = "allow" | "deny" | "defer";

/** One egress destination rule: a human-readable host pattern → a decision tier. `*.vendor.com`
 *  matches the vendor.com domain (subdomains + the apex); `*` matches any host; anything else is an
 *  exact match. Reuses `Tier` — the egress tier space is the same allow/approval/deny as action rules. */
export interface EgressRule {
  host: string;
  tier: Tier;
  /** Optional per-destination byte budget (B2 — anti slow-drip exfil). `null` = no budget on this rule. */
  budgetWindowSecs: number | null;
  budgetMaxBytes: number | null;
}

export interface EgressPolicy {
  rules: EgressRule[];
  /** The posture for a host no rule matches. Default `allow` (permissive — the runtime ships OFF by
   *  default and every export prints the mode, doc 24 §6-H10). */
  unlisted: UnlistedPosture;
  /** Fail-closed receipt-precondition mode (B3): if the `kriya.io.*` receipt can't be written, the
   *  egress is denied. Default `false` (fail-open, the documented default). */
  failClosed: boolean;
  /** Whether to record ingress digests (keyed HMAC, doc 24 §6-P3). Its OWN switch, default OFF even
   *  when egress is on. */
  recordIngress: boolean;
}

export const UNLISTED_LABEL: Record<UnlistedPosture, string> = {
  allow: "Allow",
  deny: "Deny (deny-by-default)",
  defer: "Defer to approval",
};

// ── Detection pack (doc 24 §11 B5–B12 / EG-P) — mirrors `permissions::DetectionPolicy` ────────
// "observe → flag → deny per policy, never auto-block silently by default": every sub-detector
// below is independently `| null`, matching the Rust `Option<T>` fields — authoring `detection:`
// at all (e.g. to turn on just the SSRF guard) never silently activates any OTHER detector.

/** What a heuristic detector (DNS-exfil) does on a match: flag it but let the call proceed
 *  (default), or block outright. Mirrors `permissions::AlertOrDeny`. */
export type AlertOrDeny = "alert" | "deny";
/** What a content-match detector (secret/PII) does on a match: flag it — type name only, the
 *  matched value is never recorded anywhere — or block outright. Mirrors `RedactOrDeny`. */
export type RedactOrDeny = "redact" | "deny";
/** Per-server trust class for governed MCP ingress (B12). Mirrors `TrustClass`. */
export type TrustClass = "trusted" | "scan" | "block";

export const ALERT_OR_DENY_LABEL: Record<AlertOrDeny, string> = { alert: "Alert only", deny: "Deny" };
export const REDACT_OR_DENY_LABEL: Record<RedactOrDeny, string> = { redact: "Redact (flag only)", deny: "Deny" };
export const TRUST_CLASS_LABEL: Record<TrustClass, string> = { trusted: "Trusted", scan: "Scan", block: "Block" };

/** B5: DNS-exfil / subdomain-entropy heuristic. */
export interface DnsExfilPolicy {
  enabled: boolean;
  /** Shannon-entropy threshold in bits/char above which a subdomain label is flagged. Default 4.0 —
   *  ordinary hostnames score ~2.5–3.5; encoded exfil payloads commonly score 3.8+. */
  entropyThreshold: number;
  action: AlertOrDeny;
}

/** B6: SSRF / private-IP / cloud-metadata / DNS-rebinding guard. The only dial is whether it's on —
 *  gated (not unconditional): a local dev/test upstream on `127.0.0.1`/`localhost` is legitimate. */
export interface SsrfGuardPolicy {
  enabled: boolean;
}

/** B7: secret + PII scan/redact on outbound governed bodies (AWS keys, GitHub PATs, JWTs,
 *  private-key headers, emails, Luhn-valid card numbers, SSNs). */
export interface SecretPiiPolicy {
  enabled: boolean;
  action: RedactOrDeny;
}

/** B8: one operation rail — an allowlist fence narrower than the host-level egress rule. `host` uses
 *  the same pattern syntax as an egress rule (`*` / `*.domain` / exact); `method` is an HTTP verb or
 *  `*`; `path` is an optional glob; `graphqlMutation` optionally matches a mutation NAME instead of
 *  verb+path. An operation this rail can't parse (or that matches no configured rail) is denied —
 *  fail-closed for the rail. Reuses `Tier` — same allow/approval/deny space as an egress rule. */
export interface OperationRail {
  host: string;
  method: string;
  path: string | null;
  graphqlMutation: string | null;
  tier: Tier;
}

/** B10: one approved connector tool — `upstream` is the broker namespace, `tool` the inner
 *  (un-namespaced) name, `descriptionHash` the SHA-256 hex of its canonical description at approval
 *  time. A live hash mismatch is drift (the tool-poisoning signal) and disables the tool again. */
export interface ApprovedConnectorTool {
  upstream: string;
  tool: string;
  descriptionHash: string;
}

/** B10: the connector registry. A discovered MCP tool is disabled-until-approved unless it appears
 *  in `approved` with a matching live hash. */
export interface ConnectorRegistryPolicy {
  enabled: boolean;
  approved: ApprovedConnectorTool[];
}

/** B12: per-server trust class for governed MCP ingress (responses). `trusted` passes through
 *  unchanged; `scan` (default) runs the B7 secret/PII pass over the response and flags a match
 *  without blocking; `block` denies the response outright regardless of content. */
export interface McpResponsePolicy {
  enabled: boolean;
  /** The class an unlisted server gets. Default `scan` (never `block`, the house rule against
   *  silently auto-blocking a server the operator hasn't explicitly classified). */
  defaultClass: TrustClass;
  perServer: Record<string, TrustClass>;
}

export interface DetectionPolicy {
  dnsExfil: DnsExfilPolicy | null;
  ssrfGuard: SsrfGuardPolicy | null;
  secretPii: SecretPiiPolicy | null;
  operationRails: OperationRail[];
  /** B9: canary tokens — operator-planted honeytoken strings. ANY match is always-deny, no
   *  `AlertOrDeny`/`RedactOrDeny` dial — there is no legitimate reason a canary should ever appear
   *  in real traffic, so there's nothing an "alert" mode would be hedging against. */
  canaryTokens: string[];
  connectorRegistry: ConnectorRegistryPolicy | null;
  /** B11: per-connector/per-tool read-only presets — connector NAMESPACE patterns (a bare
   *  `"widgets"` is equivalent to `"widgets__*"`) whose known-mutating tools are denied. A hard
   *  override the explicit action `rules` can never widen back open. */
  readOnly: string[];
  mcpResponse: McpResponsePolicy | null;
}

export function emptyDetectionPolicy(): DetectionPolicy {
  return {
    dnsExfil: null,
    ssrfGuard: null,
    secretPii: null,
    operationRails: [],
    canaryTokens: [],
    connectorRegistry: null,
    readOnly: [],
    mcpResponse: null,
  };
}

export function defaultDnsExfilPolicy(): DnsExfilPolicy {
  return { enabled: true, entropyThreshold: 4.0, action: "alert" };
}
export function defaultSsrfGuardPolicy(): SsrfGuardPolicy {
  return { enabled: true };
}
export function defaultSecretPiiPolicy(): SecretPiiPolicy {
  return { enabled: true, action: "redact" };
}
export function defaultConnectorRegistryPolicy(): ConnectorRegistryPolicy {
  return { enabled: true, approved: [] };
}
export function defaultMcpResponsePolicy(): McpResponsePolicy {
  return { enabled: true, defaultClass: "scan", perServer: {} };
}

// ── Credential brokering (doc 24 §11 B13 / EG-B) — mirrors `secrets::SecretsPolicy` ───────────
// The agent never holds a real credential — only a `{{kriya:<alias>}}` placeholder; the runtime
// substitutes the real value at the egress boundary, from OS Keychain, scoped to that ONE alias's
// own destination allowlist. This model NEVER carries a secret value, only a reference — the schema
// below has no field a value could go in. See `docs/THREAT-MODEL-brokering.md`.

/** One brokered alias. `keychainService`/`keychainAccount` are a REFERENCE (macOS Keychain
 *  generic-password item coordinates) — never the secret itself. */
export interface SecretAlias {
  /** The name inside `{{kriya:<name>}}` — matched exactly, case-sensitively. */
  alias: string;
  keychainService: string;
  keychainAccount: string;
  /** Host patterns (the same syntax as an egress rule) this alias may be substituted INTO — its
   *  OWN scope, independent of (and typically narrower than) the general egress destination tier.
   *  A placeholder bound for a host not listed here is denied, never substituted. */
  allowedHosts: string[];
}

export interface SecretsPolicy {
  aliases: SecretAlias[];
}

export function emptySecretsPolicy(): SecretsPolicy {
  return { aliases: [] };
}

/** An egress policy with no rules and the permissive default posture — the "just turned it on" state. */
export function emptyEgressPolicy(): EgressPolicy {
  return { rules: [], unlisted: "allow", failClosed: false, recordIngress: false };
}

// ── YAML shapes (what the host's serde sees) ──────────────────────────────────
interface YamlRule {
  action: string;
  allow?: boolean;
  require_approval?: boolean;
}
interface YamlEgressRule {
  host: string;
  tier?: Tier;
  budget?: { window_secs?: number; max_bytes?: number } | null;
}
interface YamlEgressPolicy {
  rules?: YamlEgressRule[];
  unlisted?: UnlistedPosture;
  fail_closed?: boolean;
  record_ingress?: boolean;
}
interface YamlDnsExfilPolicy {
  enabled?: boolean;
  entropy_threshold?: number;
  action?: AlertOrDeny;
}
interface YamlSsrfGuardPolicy {
  enabled?: boolean;
}
interface YamlSecretPiiPolicy {
  enabled?: boolean;
  action?: RedactOrDeny;
}
interface YamlOperationRail {
  host?: string;
  method?: string;
  path?: string | null;
  graphql_mutation?: string | null;
  tier: Tier;
}
interface YamlApprovedConnectorTool {
  upstream: string;
  tool: string;
  description_hash: string;
}
interface YamlConnectorRegistryPolicy {
  enabled?: boolean;
  approved?: YamlApprovedConnectorTool[];
}
interface YamlMcpResponsePolicy {
  enabled?: boolean;
  default_class?: TrustClass;
  per_server?: Record<string, TrustClass>;
}
interface YamlDetectionPolicy {
  dns_exfil?: YamlDnsExfilPolicy | null;
  ssrf_guard?: YamlSsrfGuardPolicy | null;
  secret_pii?: YamlSecretPiiPolicy | null;
  operation_rails?: YamlOperationRail[];
  canary_tokens?: string[];
  connector_registry?: YamlConnectorRegistryPolicy | null;
  read_only?: string[];
  mcp_response?: YamlMcpResponsePolicy | null;
}
interface YamlSecretAlias {
  alias: string;
  keychain_service: string;
  keychain_account: string;
  allowed_hosts?: string[];
}
interface YamlSecretsPolicy {
  aliases?: YamlSecretAlias[];
}
interface YamlPolicy {
  rules?: YamlRule[];
  budget?: { max_actions_per_minute?: number | null; max_api_calls_per_hour?: number | null };
  egress?: YamlEgressPolicy;
  detection?: YamlDetectionPolicy;
  secrets?: YamlSecretsPolicy;
}

export function tierFrom(allow: boolean, requireApproval: boolean): Tier {
  if (!allow) return "deny";
  return requireApproval ? "approval" : "allow";
}

export const TIER_LABEL: Record<Tier, string> = {
  allow: "Allow",
  approval: "Require approval",
  deny: "Deny",
};

/** The host's built-in default when no policy file is present (`Policy::default`). */
export function defaultPolicy(): Policy {
  return {
    rules: [
      { action: "create_*", tier: "allow" },
      { action: "edit_*", tier: "allow" },
      { action: "delete_*", tier: "approval" },
      { action: "*", tier: "deny" },
    ],
    maxActionsPerMinute: 60,
    maxApiCallsPerHour: null,
    egress: null,
    detection: null,
    secrets: null,
  };
}

function parseSecrets(doc: YamlSecretsPolicy | undefined): SecretsPolicy | null {
  if (!doc) return null;
  return {
    aliases: (Array.isArray(doc.aliases) ? doc.aliases : [])
      .filter(
        (a): a is YamlSecretAlias =>
          !!a && typeof a.alias === "string" && typeof a.keychain_service === "string" && typeof a.keychain_account === "string",
      )
      .map((a) => ({
        alias: a.alias,
        keychainService: a.keychain_service,
        keychainAccount: a.keychain_account,
        allowedHosts: (Array.isArray(a.allowed_hosts) ? a.allowed_hosts : []).filter(
          (h): h is string => typeof h === "string",
        ),
      })),
  };
}

function parseDetection(doc: YamlDetectionPolicy | undefined): DetectionPolicy | null {
  if (!doc) return null;
  return {
    dnsExfil: doc.dns_exfil
      ? {
          enabled: doc.dns_exfil.enabled !== false,
          entropyThreshold:
            typeof doc.dns_exfil.entropy_threshold === "number" ? doc.dns_exfil.entropy_threshold : 4.0,
          action: doc.dns_exfil.action === "deny" ? "deny" : "alert",
        }
      : null,
    ssrfGuard: doc.ssrf_guard ? { enabled: doc.ssrf_guard.enabled !== false } : null,
    secretPii: doc.secret_pii
      ? {
          enabled: doc.secret_pii.enabled !== false,
          action: doc.secret_pii.action === "deny" ? "deny" : "redact",
        }
      : null,
    operationRails: (Array.isArray(doc.operation_rails) ? doc.operation_rails : [])
      .filter((r): r is YamlOperationRail => !!r && typeof r.tier === "string")
      .map((r) => ({
        host: typeof r.host === "string" ? r.host : "*",
        method: typeof r.method === "string" ? r.method : "*",
        path: typeof r.path === "string" ? r.path : null,
        graphqlMutation: typeof r.graphql_mutation === "string" ? r.graphql_mutation : null,
        tier: r.tier === "approval" || r.tier === "deny" ? r.tier : "allow",
      })),
    canaryTokens: (Array.isArray(doc.canary_tokens) ? doc.canary_tokens : []).filter(
      (t): t is string => typeof t === "string",
    ),
    connectorRegistry: doc.connector_registry
      ? {
          enabled: doc.connector_registry.enabled !== false,
          approved: (Array.isArray(doc.connector_registry.approved) ? doc.connector_registry.approved : [])
            .filter(
              (a): a is YamlApprovedConnectorTool =>
                !!a && typeof a.upstream === "string" && typeof a.tool === "string",
            )
            .map((a) => ({
              upstream: a.upstream,
              tool: a.tool,
              descriptionHash: typeof a.description_hash === "string" ? a.description_hash : "",
            })),
        }
      : null,
    readOnly: (Array.isArray(doc.read_only) ? doc.read_only : []).filter(
      (r): r is string => typeof r === "string",
    ),
    mcpResponse: doc.mcp_response
      ? {
          enabled: doc.mcp_response.enabled !== false,
          defaultClass:
            doc.mcp_response.default_class === "trusted" || doc.mcp_response.default_class === "block"
              ? doc.mcp_response.default_class
              : "scan",
          perServer:
            doc.mcp_response.per_server && typeof doc.mcp_response.per_server === "object"
              ? { ...doc.mcp_response.per_server }
              : {},
        }
      : null,
  };
}

function parseEgress(doc: YamlEgressPolicy | undefined): EgressPolicy | null {
  if (!doc) return null;
  const rules = Array.isArray(doc.rules) ? doc.rules : [];
  return {
    rules: rules
      .filter((r): r is YamlEgressRule => !!r && typeof r.host === "string")
      .map((r) => ({
        host: r.host,
        tier: r.tier === "approval" || r.tier === "deny" ? r.tier : "allow",
        budgetWindowSecs: typeof r.budget?.window_secs === "number" ? r.budget.window_secs : null,
        budgetMaxBytes: typeof r.budget?.max_bytes === "number" ? r.budget.max_bytes : null,
      })),
    unlisted: doc.unlisted === "deny" || doc.unlisted === "defer" ? doc.unlisted : "allow",
    failClosed: Boolean(doc.fail_closed),
    recordIngress: Boolean(doc.record_ingress),
  };
}

export function parsePolicyYaml(text: string): Policy {
  const doc = (load(text) ?? {}) as YamlPolicy;
  const rules = Array.isArray(doc.rules) ? doc.rules : [];
  return {
    rules: rules
      .filter((r): r is YamlRule => !!r && typeof r.action === "string")
      .map((r) => ({ action: r.action, tier: tierFrom(Boolean(r.allow), Boolean(r.require_approval)) })),
    maxActionsPerMinute:
      doc.budget && typeof doc.budget.max_actions_per_minute === "number"
        ? doc.budget.max_actions_per_minute
        : null,
    maxApiCallsPerHour:
      doc.budget && typeof doc.budget.max_api_calls_per_hour === "number"
        ? doc.budget.max_api_calls_per_hour
        : null,
    egress: parseEgress(doc.egress),
    detection: parseDetection(doc.detection),
    secrets: parseSecrets(doc.secrets),
  };
}

const YAML_HEADER = `# kriya governance policy — generated by kriya Console.
# The host (kriya / kriya-mcp) enforces this on every agent action: rules are
# evaluated top-to-bottom, the first match wins, and no match = deny.
`;

export function policyToYaml(p: Policy): string {
  const rules: YamlRule[] = p.rules.map((r) => {
    const o: YamlRule = { action: r.action, allow: r.tier !== "deny" };
    if (r.tier === "approval") o.require_approval = true;
    return o;
  });
  const doc: YamlPolicy = { rules };
  if (p.maxActionsPerMinute !== null || p.maxApiCallsPerHour !== null) {
    doc.budget = {};
    if (p.maxActionsPerMinute !== null) doc.budget.max_actions_per_minute = p.maxActionsPerMinute;
    if (p.maxApiCallsPerHour !== null) doc.budget.max_api_calls_per_hour = p.maxApiCallsPerHour;
  }
  // BC-3: no `egress` key at all when the operator never authored one — a policy that never touched
  // this feature round-trips byte-identically to before EG-2/EG-3 existed.
  if (p.egress !== null) {
    doc.egress = {
      rules: p.egress.rules.map((r) => {
        const yr: YamlEgressRule = { host: r.host, tier: r.tier };
        if (r.budgetWindowSecs !== null && r.budgetMaxBytes !== null) {
          yr.budget = { window_secs: r.budgetWindowSecs, max_bytes: r.budgetMaxBytes };
        }
        return yr;
      }),
      unlisted: p.egress.unlisted,
      fail_closed: p.egress.failClosed,
      record_ingress: p.egress.recordIngress,
    };
  }
  // BC-3, same discipline as `egress` above: no `detection` key at all when never authored, and
  // within it, no sub-detector key when that ONE detector was never configured — authoring the
  // pack never silently activates a detector the operator didn't touch.
  if (p.detection !== null) {
    const d = p.detection;
    const yd: YamlDetectionPolicy = {};
    if (d.dnsExfil) {
      yd.dns_exfil = {
        enabled: d.dnsExfil.enabled,
        entropy_threshold: d.dnsExfil.entropyThreshold,
        action: d.dnsExfil.action,
      };
    }
    if (d.ssrfGuard) yd.ssrf_guard = { enabled: d.ssrfGuard.enabled };
    if (d.secretPii) yd.secret_pii = { enabled: d.secretPii.enabled, action: d.secretPii.action };
    if (d.operationRails.length > 0) {
      yd.operation_rails = d.operationRails.map((r) => {
        const yr: YamlOperationRail = { host: r.host, method: r.method, tier: r.tier };
        if (r.path !== null) yr.path = r.path;
        if (r.graphqlMutation !== null) yr.graphql_mutation = r.graphqlMutation;
        return yr;
      });
    }
    if (d.canaryTokens.length > 0) yd.canary_tokens = d.canaryTokens;
    if (d.connectorRegistry) {
      yd.connector_registry = {
        enabled: d.connectorRegistry.enabled,
        approved: d.connectorRegistry.approved.map((a) => ({
          upstream: a.upstream,
          tool: a.tool,
          description_hash: a.descriptionHash,
        })),
      };
    }
    if (d.readOnly.length > 0) yd.read_only = d.readOnly;
    if (d.mcpResponse) {
      yd.mcp_response = {
        enabled: d.mcpResponse.enabled,
        default_class: d.mcpResponse.defaultClass,
        per_server: d.mcpResponse.perServer,
      };
    }
    doc.detection = yd;
  }
  // BC-3, same discipline again: no `secrets` key at all when never authored. This model never
  // carries a value in the first place — only a Keychain reference — so there is no additional
  // redaction concern here beyond the standard round-trip rule.
  if (p.secrets !== null) {
    doc.secrets = {
      aliases: p.secrets.aliases.map((a) => ({
        alias: a.alias,
        keychain_service: a.keychainService,
        keychain_account: a.keychainAccount,
        allowed_hosts: a.allowedHosts,
      })),
    };
  }
  const body = dump(doc, { lineWidth: -1, quotingType: '"', forceQuotes: true });
  return YAML_HEADER + body;
}

// ── matching + decision (port of `matches` / `check`) ─────────────────────────
export function matchesPattern(pattern: string, actionId: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith("*")) return actionId.startsWith(pattern.slice(0, -1));
  return pattern === actionId;
}

export interface DecisionResult {
  decision: Tier; // reuse Tier as the decision space (allow | approval | deny)
  matchedIndex: number | null; // null = fell through to implicit deny
}

export function decide(policy: Policy, actionId: string): DecisionResult {
  for (let i = 0; i < policy.rules.length; i++) {
    const rule = policy.rules[i]!;
    if (matchesPattern(rule.action, actionId)) {
      return { decision: rule.tier, matchedIndex: i };
    }
  }
  return { decision: "deny", matchedIndex: null };
}

// ── lint (port of `Policy::warnings`) ─────────────────────────────────────────
const DESTRUCTIVE_KEYWORDS = ["delete", "remove", "destroy", "drop", "purge", "wipe"];

function isDestructiveName(pattern: string): boolean {
  const p = pattern.toLowerCase();
  return DESTRUCTIVE_KEYWORDS.some((k) => p.includes(k));
}

export type LintSeverity = "high" | "medium";

export interface LintWarning {
  severity: LintSeverity;
  message: string;
  ruleIndex: number | null;
}

export function lintPolicy(policy: Policy): LintWarning[] {
  const out: LintWarning[] = [];
  const destructive: LintWarning[] = [];

  policy.rules.forEach((rule, i) => {
    const allow = rule.tier !== "deny";
    const requireApproval = rule.tier === "approval";

    if (allow && !requireApproval && isDestructiveName(rule.action)) {
      destructive.push({
        severity: "high",
        ruleIndex: i,
        message: `Rule ${i + 1}: "${rule.action}" is allowed without human approval — destructive-sounding actions usually want approval.`,
      });
    }
    if (rule.action === "*" && allow && !requireApproval) {
      out.push({
        severity: "high",
        ruleIndex: i,
        message: `Rule ${i + 1}: catch-all "*" allows every action without approval — this defeats the deny-by-default model.`,
      });
    }
  });

  out.push(...destructive);

  if (!policy.rules.some((r) => r.action === "*")) {
    out.push({
      severity: "medium",
      ruleIndex: null,
      message: `No explicit catch-all "*" rule — the host falls through to deny, but an explicit "*" → Deny makes the intent obvious.`,
    });
  }
  if (policy.maxActionsPerMinute === null) {
    out.push({
      severity: "medium",
      ruleIndex: null,
      message: `No per-minute budget cap — an agent stuck in a loop can hammer your app indefinitely. Recommend a cap (e.g. 60).`,
    });
  }

  return out;
}
