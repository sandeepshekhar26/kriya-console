import { describe, it, expect } from "vitest";
import {
  classifyRisk,
  parsePendingApprovals,
  routeQueue,
  groupBy,
  decide,
  ingestPending,
  summarize,
  type PendingApproval,
  type QueueState,
} from "../src/lib/approvals";

function p(over: Partial<PendingApproval>): PendingApproval {
  return {
    id: "id-1",
    source: "app",
    action_id: "categorize_transaction",
    params: {},
    reasoning: "",
    requested_ms: 1000,
    ...over,
  };
}

describe("classifyRisk", () => {
  it("flags destructive + financial actions as high risk", () => {
    for (const a of ["delete_transaction", "close_account", "wire_money", "send_payment", "purge_db"]) {
      expect(classifyRisk(a)).toBe("high");
    }
  });
  it("treats routine actions as normal", () => {
    for (const a of ["categorize_transaction", "list_transactions", "create_note"]) {
      expect(classifyRisk(a)).toBe("normal");
    }
  });
});

describe("parsePendingApprovals", () => {
  it("parses valid records, keeps the actor, and skips malformed lines", () => {
    const text = [
      JSON.stringify({
        id: "s1",
        source: "budget-app",
        actor: { agent: "claude-desktop", user: "alice" },
        action_id: "delete_transaction",
        params: { id: "t1" },
        reasoning: "stale",
        requested_ms: 5,
      }),
      "not json",
      "",
      JSON.stringify({ id: "s2", action_id: "categorize_transaction" }),
    ].join("\n");
    const out = parsePendingApprovals(text, "fallback");
    expect(out).toHaveLength(2);
    expect(out[0]?.actor).toEqual({ agent: "claude-desktop", user: "alice" });
    // defaults applied; source falls back when absent
    expect(out[1]).toMatchObject({ id: "s2", source: "fallback", params: {}, reasoning: "" });
  });

  it("drops records missing required fields", () => {
    const text = JSON.stringify({ source: "x", action_id: "delete_x" }); // no id
    expect(parsePendingApprovals(text, "x")).toHaveLength(0);
  });
});

describe("routeQueue", () => {
  it("orders high-risk first, then oldest-first within a tier, and computes wait", () => {
    const pending = [
      p({ id: "a", action_id: "categorize_transaction", requested_ms: 1000 }),
      p({ id: "b", action_id: "delete_transaction", requested_ms: 4000 }),
      p({ id: "c", action_id: "wire_money", requested_ms: 2000 }),
    ];
    const routed = routeQueue(pending, 10_000);
    expect(routed.map((r) => r.id)).toEqual(["c", "b", "a"]); // high (oldest first), then normal
    expect(routed[0]?.risk).toBe("high");
    expect(routed[2]?.waitingSeconds).toBe(9); // (10000-1000)/1000
  });
});

describe("groupBy", () => {
  it("groups by source and by agent (unattributed bucket when no actor)", () => {
    const routed = routeQueue(
      [
        p({ id: "a", source: "budget", actor: { agent: "claude-desktop", user: "alice" } }),
        p({ id: "b", source: "crm", actor: { agent: "cursor", user: "bob" } }),
        p({ id: "c", source: "budget" }),
      ],
      2000,
    );
    expect([...groupBy(routed, "source").keys()].sort()).toEqual(["budget", "crm"]);
    const byAgent = groupBy(routed, "agent");
    expect(byAgent.get("claude-desktop")).toHaveLength(1);
    expect(byAgent.get("(unattributed)")).toHaveLength(1);
  });
});

describe("decide", () => {
  const state: QueueState = {
    pending: [p({ id: "a", action_id: "delete_transaction" }), p({ id: "b" })],
    decided: [],
  };

  it("moves an item from pending to decided, immutably, trimming the reason", () => {
    const next = decide(state, "a", "denied", "  too risky  ", "alice", 9999);
    expect(next.pending.map((x) => x.id)).toEqual(["b"]);
    expect(next.decided).toHaveLength(1);
    expect(next.decided[0]).toMatchObject({ id: "a", decision: "denied", reason: "too risky", decidedBy: "alice" });
    // original untouched
    expect(state.pending).toHaveLength(2);
    expect(state.decided).toHaveLength(0);
  });

  it("is a no-op for an unknown id", () => {
    expect(decide(state, "zzz", "approved", "", "alice", 1)).toBe(state);
  });
});

describe("ingestPending", () => {
  it("adds fresh requests but ignores ids already pending or decided", () => {
    const start: QueueState = {
      pending: [p({ id: "a" })],
      decided: [{ ...p({ id: "b" }), decision: "approved", reason: "", decidedBy: "x", decided_ms: 1 }],
    };
    const next = ingestPending(start, [p({ id: "a" }), p({ id: "b" }), p({ id: "c" })]);
    expect(next.pending.map((x) => x.id)).toEqual(["a", "c"]);
  });
});

describe("summarize", () => {
  it("counts pending, high-risk, approved, denied", () => {
    const state: QueueState = {
      pending: [p({ id: "a", action_id: "delete_transaction" }), p({ id: "b", action_id: "categorize_transaction" })],
      decided: [
        { ...p({ id: "c" }), decision: "approved", reason: "", decidedBy: "x", decided_ms: 1 },
        { ...p({ id: "d" }), decision: "denied", reason: "no", decidedBy: "x", decided_ms: 2 },
      ],
    };
    expect(summarize(state)).toEqual({ pending: 2, highRiskPending: 1, approved: 1, denied: 1 });
  });
});
