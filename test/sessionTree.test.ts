import { describe, it, expect } from "vitest";
import type { AuditRow, Json, SignedReceipt } from "../src/lib/types";
import {
  buildSessionTrees,
  summarizeCorrelation,
  readCorr,
  type RunAction,
} from "../src/lib/sessionTree";

/** Build a verified (or failed) audit row carrying a `kriya.corr` correlation. */
function row(
  stepId: string,
  opts: {
    runId?: string;
    parentStepId?: string;
    agentId?: string;
    actionId?: string;
    ts?: number;
    success?: boolean;
    ok?: boolean;
    source?: string;
    extraParams?: Record<string, Json>;
  } = {},
): AuditRow {
  const corr: Record<string, Json> = {};
  if (opts.runId) corr.run_id = opts.runId;
  if (opts.parentStepId) corr.parent_step_id = opts.parentStepId;
  if (opts.agentId) corr.agent_id = opts.agentId;
  const params: Record<string, Json> = { ...(opts.extraParams ?? {}) };
  if (Object.keys(corr).length) params["kriya.corr"] = corr;
  const receipt: SignedReceipt = {
    step_id: stepId,
    action_id: opts.actionId ?? "claude-code__bash",
    params,
    success: opts.success ?? true,
    ts_ms: opts.ts ?? 1000,
    public_key: "pk",
    signature: "sig",
  };
  return {
    source: opts.source ?? "claude-code.jsonl",
    lineNo: 1,
    raw: "",
    receipt,
    outcome: opts.ok === false ? { ok: false, reason: "bad" } : { ok: true },
  };
}

/** Find a node by stepId anywhere in a forest. */
function find(roots: RunAction[], stepId: string): RunAction | undefined {
  for (const r of roots) {
    if (r.stepId === stepId) return r;
    const hit = find(r.children, stepId);
    if (hit) return hit;
  }
  return undefined;
}

describe("readCorr", () => {
  it("extracts run_id / parent_step_id / agent_id and ignores junk", () => {
    expect(
      readCorr({ "kriya.corr": { run_id: "R", parent_step_id: "P", agent_id: "A" }, x: 1 }),
    ).toEqual({ runId: "R", parentStepId: "P", agentId: "A" });
    expect(readCorr({})).toEqual({});
    expect(readCorr({ "kriya.corr": { run_id: "" } })).toEqual({}); // blank string = absent
    expect(readCorr(null)).toEqual({});
    expect(readCorr("nope" as unknown as Json)).toEqual({});
  });
});

describe("buildSessionTrees", () => {
  it("groups by run_id and only includes verified, correlated receipts", () => {
    const trees = buildSessionTrees([
      row("s1", { runId: "run-A", ts: 100 }),
      row("s2", { runId: "run-A", ts: 200 }),
      row("s3", { runId: "run-B", ts: 150 }),
      row("s4", { ts: 300 }), // no run_id → excluded
      row("s5", { runId: "run-A", ts: 400, ok: false }), // failed verification → excluded
      row("att", { runId: "run-A", actionId: "kriya.attestation.on_device", ts: 500 }), // marker → excluded
    ]);
    expect(trees.map((t) => t.runId)).toEqual(["run-A", "run-B"]); // run-A last-active later
    const a = trees.find((t) => t.runId === "run-A")!;
    expect(a.actionCount).toBe(2); // s1 + s2 only
    expect(a.roots.map((r) => r.stepId).sort()).toEqual(["s1", "s2"]);
  });

  it("nests actions under their parent_step_id (the middleware lineage)", () => {
    const trees = buildSessionTrees([
      row("outer", { runId: "r", ts: 100, actionId: "outer" }),
      row("inner1", { runId: "r", parentStepId: "outer", ts: 200, actionId: "inner1" }),
      row("inner2", { runId: "r", parentStepId: "outer", ts: 150, actionId: "inner2" }),
      row("deep", { runId: "r", parentStepId: "inner1", ts: 300, actionId: "deep" }),
    ]);
    const t = trees[0]!;
    expect(t.roots.map((r) => r.stepId)).toEqual(["outer"]);
    const outer = t.roots[0]!;
    // children ts-sorted: inner2 (150) before inner1 (200)
    expect(outer.children.map((c) => c.stepId)).toEqual(["inner2", "inner1"]);
    expect(find(t.roots, "inner1")!.children.map((c) => c.stepId)).toEqual(["deep"]);
  });

  it("surfaces an orphan (parent_step_id with no matching step) as a re-rooted, flagged node", () => {
    const trees = buildSessionTrees([
      row("a", { runId: "r", ts: 100 }),
      row("b", { runId: "r", parentStepId: "ghost", ts: 200 }), // parent not in the run
    ]);
    const t = trees[0]!;
    expect(t.orphanCount).toBe(1);
    const b = find(t.roots, "b")!;
    expect(b.orphaned).toBe(true);
    expect(t.roots.map((r) => r.stepId)).toEqual(["a", "b"]); // orphan re-rooted, not dropped
  });

  it("groups sub-agents by agent_id (the hook lane, no parent pointer)", () => {
    const trees = buildSessionTrees([
      row("m1", { runId: "sess", ts: 100, actionId: "claude-code__task" }), // main spawns
      row("s1", { runId: "sess", agentId: "sub-A", ts: 200 }),
      row("s2", { runId: "sess", agentId: "sub-A", ts: 300 }),
      row("s3", { runId: "sess", agentId: "sub-B", ts: 400 }),
    ]);
    const t = trees[0]!;
    expect(t.subAgents).toEqual([
      { agentId: "sub-A", actions: 2 },
      { agentId: "sub-B", actions: 1 },
    ]);
    expect(t.spawnCount).toBe(1); // the claude-code__task
    // With no parent pointers, all four are roots (grouping is by agent_id, shown in the view).
    expect(t.roots.length).toBe(4);
  });

  it("keeps interleaved sessions separate", () => {
    const trees = buildSessionTrees([
      row("a1", { runId: "A", ts: 100 }),
      row("b1", { runId: "B", ts: 110 }),
      row("a2", { runId: "A", ts: 120 }),
      row("b2", { runId: "B", ts: 130 }),
    ]);
    expect(trees.map((t) => t.runId)).toEqual(["B", "A"]); // B last-active later
    expect(trees.find((t) => t.runId === "A")!.actionCount).toBe(2);
    expect(trees.find((t) => t.runId === "B")!.actionCount).toBe(2);
  });

  it("is robust to clock skew (a child timestamped before its parent still nests)", () => {
    const trees = buildSessionTrees([
      row("parent", { runId: "r", ts: 500 }),
      row("child", { runId: "r", parentStepId: "parent", ts: 100 }), // earlier than its parent
    ]);
    const t = trees[0]!;
    expect(t.roots.map((r) => r.stepId)).toEqual(["parent"]); // nesting is by lineage, not time
    expect(find(t.roots, "parent")!.children.map((c) => c.stepId)).toEqual(["child"]);
    expect(t.firstTs).toBe(100); // span still spans the skew
    expect(t.lastTs).toBe(500);
  });

  it("breaks a parent_step_id cycle defensively instead of looping", () => {
    // x → y → x : neither should nest under the other into an infinite structure.
    const trees = buildSessionTrees([
      row("x", { runId: "r", parentStepId: "y", ts: 100 }),
      row("y", { runId: "r", parentStepId: "x", ts: 200 }),
    ]);
    const t = trees[0]!;
    // One of them nests, the other is re-rooted — but the build terminates and both appear once.
    const all: string[] = [];
    const walk = (n: RunAction) => {
      all.push(n.stepId);
      n.children.forEach(walk);
    };
    t.roots.forEach(walk);
    expect(all.sort()).toEqual(["x", "y"]);
  });

  it("preserves tool params alongside the reserved correlation key", () => {
    const trees = buildSessionTrees([
      row("s1", { runId: "r", extraParams: { command: "ls" } }),
    ]);
    // The builder reads correlation but the underlying receipt still carries the tool's own args.
    expect(trees[0]!.actionCount).toBe(1);
  });
});

describe("summarizeCorrelation", () => {
  it("returns null when there are no correlated runs (drives the byte-identical export)", () => {
    expect(summarizeCorrelation(buildSessionTrees([row("s", {})]))).toBeNull();
    expect(summarizeCorrelation([])).toBeNull();
  });

  it("rolls the run structure up into the appendix numbers", () => {
    const trees = buildSessionTrees([
      row("m1", { runId: "sess", ts: 100, actionId: "claude-code__task" }),
      row("s1", { runId: "sess", agentId: "sub-A", ts: 200, success: false }),
      row("s2", { runId: "sess", agentId: "sub-B", ts: 300 }),
      row("o1", { runId: "run2", ts: 400 }),
    ]);
    expect(summarizeCorrelation(trees)).toEqual({
      runs: 2,
      subAgents: 2, // sub-A + sub-B in "sess"; run2 has none
      spawns: 1, // the claude-code__task
      actions: 4,
      blocked: 1, // s1 success:false
    });
  });
});
