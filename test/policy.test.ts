import { describe, it, expect } from "vitest";
import {
  defaultPolicy,
  decide,
  lintPolicy,
  parsePolicyYaml,
  policyToYaml,
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
});
