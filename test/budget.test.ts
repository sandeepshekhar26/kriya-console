import { describe, it, expect } from "vitest";
import type { Actor, AuditRow, SignedReceipt } from "../src/lib/types";
import { peakWindow, usageByScope, atLimitEvents, summarizeBudget } from "../src/lib/budget";

function row(
  source: string,
  tsMs: number,
  opts: { action_id?: string; actor?: Actor; ok?: boolean } = {},
): AuditRow {
  const receipt: SignedReceipt = {
    step_id: "s",
    action_id: opts.action_id ?? "create_note",
    params: {},
    success: true,
    ts_ms: tsMs,
    ...(opts.actor ? { actor: opts.actor } : {}),
    public_key: "pk",
    signature: "sig",
  };
  return {
    source,
    lineNo: 1,
    raw: "",
    receipt,
    outcome: opts.ok === false ? { ok: false, reason: "bad" } : { ok: true },
  };
}

const burst = (source: string, n: number) =>
  Array.from({ length: n }, (_, i) => row(source, i * 1000)); // n actions, 1s apart → all in one minute

describe("peakWindow", () => {
  it("counts a burst inside the trailing 60s window", () => {
    expect(peakWindow([0, 10_000, 20_000, 30_000, 59_000])).toEqual({ peak: 5, atMs: 59_000 });
  });
  it("actions spread >60s apart never share a window", () => {
    expect(peakWindow([0, 61_000, 122_000]).peak).toBe(1);
  });
  it("uses a half-open window — exactly 60s apart is a new window (matches the host's `< WINDOW`)", () => {
    expect(peakWindow([0, 60_000]).peak).toBe(1);
    expect(peakWindow([0, 59_999]).peak).toBe(2);
  });
  it("empty → peak 0", () => {
    expect(peakWindow([])).toEqual({ peak: 0, atMs: null });
  });
});

describe("usageByScope", () => {
  const caps = { maxActionsPerMinute: 10, maxApiCallsPerHour: null };

  it("flags at-limit / approaching / ok vs the per-minute cap, busiest first", () => {
    const rows = [...burst("app-hot", 10), ...burst("app-warm", 8), ...burst("app-cool", 3)];
    const u = usageByScope(rows, "source", caps);
    const by = Object.fromEntries(u.map((x) => [x.scope, x]));
    expect(by["app-hot"]!.status).toBe("at-limit");
    expect(by["app-hot"]!.utilizationPct).toBe(100);
    expect(by["app-warm"]!.status).toBe("approaching"); // 8 == 80% of 10
    expect(by["app-cool"]!.status).toBe("ok");
    expect(u[0]!.scope).toBe("app-hot"); // busiest first
  });

  it("groups by agent and operator via the signed actor", () => {
    const alice: Actor = { agent: "claude-desktop", user: "alice" };
    const bob: Actor = { agent: "cursor", user: "bob" };
    const rows = [
      row("a", 0, { actor: alice }),
      row("a", 1000, { actor: alice }),
      row("a", 2000, { actor: bob }),
    ];
    expect(usageByScope(rows, "agent", caps).find((u) => u.scope === "claude-desktop")!.totalActions).toBe(2);
    expect(usageByScope(rows, "user", caps).find((u) => u.scope === "alice")!.totalActions).toBe(2);
  });

  it("excludes failed-verification rows and the on-device attestation marker", () => {
    const rows = [
      row("a", 0),
      row("a", 1000, { ok: false }), // tampered → excluded
      row("a", 2000, { action_id: "kriya.attestation.on_device" }), // run marker → excluded
    ];
    expect(usageByScope(rows, "source", caps)[0]!.totalActions).toBe(1);
  });

  it("uncapped policy → status ok, utilization null even under heavy use", () => {
    const u = usageByScope(burst("a", 100), "source", { maxActionsPerMinute: null, maxApiCallsPerHour: null });
    expect(u[0]!.status).toBe("ok");
    expect(u[0]!.utilizationPct).toBeNull();
  });
});

describe("atLimitEvents", () => {
  it("records each moment the trailing-60s count reaches the cap, newest first", () => {
    const rows = [row("a", 0), row("a", 1000), row("a", 2000), row("a", 3000)]; // 4 in <60s, cap 3
    const ev = atLimitEvents(rows, "source", 3);
    expect(ev.length).toBe(2); // at the 3rd and 4th action
    expect(ev.every((e) => e.windowCount >= 3)).toBe(true);
    expect(ev[0]!.ts_ms).toBe(3000); // newest first
  });
  it("uncapped → no events", () => {
    expect(atLimitEvents([row("a", 0)], "source", null)).toEqual([]);
  });
});

describe("summarizeBudget", () => {
  it("counts scopes at/approaching the cap and surfaces both caps", () => {
    const caps = { maxActionsPerMinute: 5, maxApiCallsPerHour: 500 };
    const rows = [...burst("hot", 5), ...burst("warm", 4), row("cool", 0)];
    const s = summarizeBudget(rows, "source", caps);
    expect(s.scopesAtLimit).toBe(1); // hot
    expect(s.scopesApproaching).toBe(1); // warm (4 == 80% of 5)
    expect(s.capPerMinute).toBe(5);
    expect(s.capPerHour).toBe(500);
    expect(s.atLimitEvents).toBeGreaterThanOrEqual(1);
  });
});
