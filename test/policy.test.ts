import { describe, it, expect } from "vitest";
import {
  defaultPolicy,
  decide,
  lintPolicy,
  parsePolicyYaml,
  policyToYaml,
  emptyDetectionPolicy,
  defaultDnsExfilPolicy,
  defaultSsrfGuardPolicy,
  defaultSecretPiiPolicy,
  defaultConnectorRegistryPolicy,
  defaultMcpResponsePolicy,
  type DetectionPolicy,
  type Policy,
} from "../src/lib/policy";

// These mirror the Rust unit tests in crates/kriya/src/permissions.rs so the console's
// model stays in lockstep with what the host actually enforces.

describe("decide() — parity with permissions.rs check()", () => {
  it("matches the host's default-policy decisions", () => {
    const p = defaultPolicy();
    expect(decide(p, "create_note").decision).toBe("allow");
    expect(decide(p, "edit_note").decision).toBe("allow");
    expect(decide(p, "delete_note").decision).toBe("approval");
    expect(decide(p, "wire_money").decision).toBe("deny");
  });

  it("first matching rule wins (order matters)", () => {
    const p = parsePolicyYaml(`
rules:
  - action: "delete_transaction"
    allow: true
    require_approval: true
  - action: "delete_*"
    allow: false
  - action: "*"
    allow: false
`);
    expect(decide(p, "delete_transaction").decision).toBe("approval"); // specific rule first
    expect(decide(p, "delete_account").decision).toBe("deny"); // falls to delete_* deny
  });

  it("no matching rule = implicit deny", () => {
    const p = parsePolicyYaml(`rules:\n  - action: "list_*"\n    allow: true\n`);
    const r = decide(p, "wire_money");
    expect(r.decision).toBe("deny");
    expect(r.matchedIndex).toBeNull();
  });
});

describe("lintPolicy() — parity with Policy::warnings()", () => {
  it("warns on a wildcard that allows everything", () => {
    const p = parsePolicyYaml(`rules:\n  - action: "*"\n    allow: true\nbudget:\n  max_actions_per_minute: 60\n`);
    expect(lintPolicy(p).some((w) => w.message.includes("catch-all") && w.message.includes("defeats"))).toBe(true);
  });

  it("warns on each destructive-named action allowed without approval", () => {
    const p = parsePolicyYaml(`
rules:
  - action: "delete_note"
    allow: true
  - action: "purge_db"
    allow: true
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 60
`);
    expect(lintPolicy(p).filter((w) => w.message.includes("destructive-sounding")).length).toBe(2);
  });

  it("warns on missing catch-all and missing budget", () => {
    const p = parsePolicyYaml(`rules:\n  - action: "create_*"\n    allow: true\n`);
    const warns = lintPolicy(p);
    expect(warns.some((w) => w.message.includes("catch-all"))).toBe(true);
    expect(warns.some((w) => w.message.includes("budget") || w.message.includes("per-minute"))).toBe(true);
  });

  it("a clean policy emits no warnings", () => {
    const p = parsePolicyYaml(`
rules:
  - action: "create_*"
    allow: true
  - action: "delete_*"
    allow: true
    require_approval: true
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 60
`);
    expect(lintPolicy(p)).toEqual([]);
  });
});

describe("YAML round-trip", () => {
  it("emits YAML the parser reads back identically", () => {
    const p = defaultPolicy();
    const round = parsePolicyYaml(policyToYaml(p));
    expect(round).toEqual(p);
  });

  it("parses the real Actual Budget demo policy shape", () => {
    const p = parsePolicyYaml(`
rules:
  - action: "list_accounts"
    allow: true
  - action: "categorize_transaction"
    allow: true
  - action: "delete_transaction"
    allow: true
    require_approval: true
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 30
`);
    expect(p.rules).toHaveLength(4);
    expect(decide(p, "list_accounts").decision).toBe("allow");
    expect(decide(p, "delete_transaction").decision).toBe("approval");
    expect(decide(p, "close_account").decision).toBe("deny");
    expect(p.maxActionsPerMinute).toBe(30);
  });

  it("round-trips the per-hour api-call cap (R11 parity)", () => {
    const p = parsePolicyYaml(`
rules:
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 30
  max_api_calls_per_hour: 500
`);
    expect(p.maxActionsPerMinute).toBe(30);
    expect(p.maxApiCallsPerHour).toBe(500);
    // emits both caps and reads them back identically
    expect(parsePolicyYaml(policyToYaml(p))).toEqual(p);
  });
});

// Detection pack (doc 24 §11 B5–B12 / EG-P) — mirrors the Rust round-trip discipline: no
// `detection:` key at all when never authored (BC-3), and within it, each sub-detector is its own
// independently-omittable key so authoring the pack never silently activates one the operator never
// touched. These are the console-side companion to `permissions::tests::detection_*` in Rust.
describe("detection pack — YAML round-trip (doc 24 §11 / EG-P)", () => {
  it("defaultPolicy() carries detection: null and round-trips with no `detection:` key at all", () => {
    const p = defaultPolicy();
    expect(p.detection).toBeNull();
    const yaml = policyToYaml(p);
    expect(yaml).not.toContain("detection");
    expect(parsePolicyYaml(yaml)).toEqual(p);
  });

  it("round-trips a FULLY populated detection pack byte-for-byte through parse(serialize(x))", () => {
    const detection: DetectionPolicy = {
      dnsExfil: defaultDnsExfilPolicy(),
      ssrfGuard: defaultSsrfGuardPolicy(),
      secretPii: defaultSecretPiiPolicy(),
      operationRails: [
        { host: "*.vendor.com", method: "GET", path: "/v1/*", graphqlMutation: null, tier: "allow" },
        { host: "api.example.com", method: "*", path: null, graphqlMutation: "deleteUser", tier: "deny" },
      ],
      canaryTokens: ["canary-token-xyz123", "bait-key-abc789"],
      connectorRegistry: {
        enabled: true,
        approved: [{ upstream: "widgets", tool: "list_widgets", descriptionHash: "a".repeat(64) }],
      },
      readOnly: ["widgets", "reports__*"],
      mcpResponse: {
        enabled: true,
        defaultClass: "scan",
        perServer: { widgets: "trusted", scratch: "block" },
      },
    };
    const p: Policy = { ...defaultPolicy(), detection };
    const round = parsePolicyYaml(policyToYaml(p));
    expect(round).toEqual(p);
  });

  it("a partially populated pack (only SOME detectors configured) round-trips with the rest null/empty", () => {
    const detection: DetectionPolicy = {
      ...emptyDetectionPolicy(),
      ssrfGuard: { enabled: true },
      canaryTokens: ["only-this-one"],
    };
    const p: Policy = { ...defaultPolicy(), detection };
    const yaml = policyToYaml(p);
    // Untouched sub-detectors never appear in the emitted YAML at all.
    expect(yaml).not.toContain("dns_exfil");
    expect(yaml).not.toContain("secret_pii");
    expect(yaml).not.toContain("operation_rails");
    expect(yaml).not.toContain("connector_registry");
    expect(yaml).not.toContain("read_only");
    expect(yaml).not.toContain("mcp_response");
    const round = parsePolicyYaml(yaml);
    expect(round.detection).toEqual(detection);
    expect(round).toEqual(p);
  });

  it("parses a hand-authored realistic detection: block (the shape an operator would actually write)", () => {
    const p = parsePolicyYaml(`
rules:
  - action: "*"
    allow: false
budget:
  max_actions_per_minute: 60
detection:
  dns_exfil:
    action: "deny"
  ssrf_guard:
    enabled: true
  secret_pii:
    action: "deny"
  canary_tokens:
    - "planted-bait-001"
  read_only:
    - "reporting"
  mcp_response:
    default_class: "scan"
    per_server:
      analytics: "trusted"
`);
    expect(p.detection).not.toBeNull();
    const d = p.detection!;
    expect(d.dnsExfil).toEqual({ enabled: true, entropyThreshold: 4.0, action: "deny" });
    expect(d.ssrfGuard).toEqual({ enabled: true });
    expect(d.secretPii).toEqual({ enabled: true, action: "deny" });
    expect(d.canaryTokens).toEqual(["planted-bait-001"]);
    expect(d.readOnly).toEqual(["reporting"]);
    expect(d.mcpResponse).toEqual({ enabled: true, defaultClass: "scan", perServer: { analytics: "trusted" } });
    // Untouched sub-detectors stay null/empty — authoring the block never activates them.
    expect(d.operationRails).toEqual([]);
    expect(d.connectorRegistry).toBeNull();
  });

  it("connector registry approve-list round-trips (Console 'approve connector' row source of truth)", () => {
    const registry = defaultConnectorRegistryPolicy();
    registry.approved.push(
      { upstream: "crm", tool: "delete_contact", descriptionHash: "b".repeat(64) },
      { upstream: "crm", tool: "list_contacts", descriptionHash: "c".repeat(64) },
    );
    const p: Policy = { ...defaultPolicy(), detection: { ...emptyDetectionPolicy(), connectorRegistry: registry } };
    const round = parsePolicyYaml(policyToYaml(p));
    expect(round.detection?.connectorRegistry?.approved).toHaveLength(2);
    expect(round).toEqual(p);
  });

  it("MCP-response trust classes round-trip per-server, including 'block'", () => {
    const mcpResponse = defaultMcpResponsePolicy();
    mcpResponse.perServer = { "known-good": "trusted", scratch: "scan", untrusted: "block" };
    const p: Policy = { ...defaultPolicy(), detection: { ...emptyDetectionPolicy(), mcpResponse } };
    const round = parsePolicyYaml(policyToYaml(p));
    expect(round.detection?.mcpResponse?.perServer.untrusted).toBe("block");
    expect(round).toEqual(p);
  });
});
