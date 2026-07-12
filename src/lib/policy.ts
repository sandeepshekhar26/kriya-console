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
interface YamlPolicy {
  rules?: YamlRule[];
  budget?: { max_actions_per_minute?: number | null; max_api_calls_per_hour?: number | null };
  egress?: YamlEgressPolicy;
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
