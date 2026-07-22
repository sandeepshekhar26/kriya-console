// Run correlation (S3) — the session-tree builder. Groups VERIFIED receipts by their
// `kriya.corr.run_id` into a per-run tree: top-level actions, actions nested under a
// `parent_step_id` (the middleware lane's explicit lineage), and a sub-agent grouping by
// `kriya.corr.agent_id` (the Claude Code hook lane's discriminator, which has no parent pointer).
//
// It is the shared substrate doc 26's I2 (source-set / kill-chain graph) and I5 (session ABOM
// roll-up, keyed by run_id) extend — one correlation vocabulary, never two.
//
// Two invariants make this trustworthy as evidence:
//   1. VERIFIED-ONLY. A failed-verification row's `params` (hence its correlation) is untrusted
//      bytes, so it never enters a tree — exactly like `identity.ts`.
//   2. HONEST DEGRADATION. A receipt without `kriya.corr.run_id` is uncorrelated and simply absent
//      from every tree; a `parent_step_id` pointing at an unknown step is an ORPHAN (surfaced, not
//      hidden); a lineage cycle is broken defensively rather than looping.
//
// Pure + framework-free → exhaustively unit-testable; the React view is a thin shell.

import type { AuditRow, Actor, Json } from "./types";

const ATTESTATION_ID = "kriya.attestation.on_device";
/** Reserved params key the emitters stamp correlation under (mirrors `kriya::corr::RESERVED_KEY`). */
export const CORR_KEY = "kriya.corr";

/** Correlation read out of a receipt's `params["kriya.corr"]`. All fields optional. */
export interface Corr {
  runId?: string;
  parentStepId?: string;
  agentId?: string;
}

/** One action in a run — a node in the session tree. */
export interface RunAction {
  stepId: string;
  actionId: string;
  success: boolean;
  ts: number;
  source: string;
  actor?: Actor;
  /** The sub-agent this action ran in (`kriya.corr.agent_id`), or null for the main/root agent. */
  agentId: string | null;
  /** The parent action's step_id (`kriya.corr.parent_step_id`), or null. */
  parentStepId: string | null;
  /** True when `parentStepId` referenced a step not present in this run (surfaced, not dropped). */
  orphaned: boolean;
  /** A subagent-spawn action (Claude Code's Task tool) — the visible spawn point on the hook lane. */
  isSpawn: boolean;
  /** Children nested under this action via their `parentStepId`, ts-sorted. */
  children: RunAction[];
}

/** A distinct sub-agent observed within a run (the `run → subagent → actions` middle level). */
export interface SubAgent {
  agentId: string;
  /** How many actions in the run are attributed to this sub-agent. */
  actions: number;
}

/** One correlated run and its computed tree. */
export interface RunTree {
  runId: string;
  firstTs: number;
  lastTs: number;
  /** Total verified, correlated action receipts in this run. */
  actionCount: number;
  /** Of those, how many were blocked/failed (`success === false`) — deny or not-approved attempts. */
  blockedCount: number;
  /** Distinct `agent_id`s (the sub-agents that ran), sorted; excludes the main/null agent. */
  subAgents: SubAgent[];
  /** Subagent-spawn actions observed (Claude Code `*__task`). */
  spawnCount: number;
  /** Orphaned actions (a `parent_step_id` with no matching step in the run). */
  orphanCount: number;
  /** The forest: top-level actions (no parent, or re-rooted orphans), each with nested children. */
  roots: RunAction[];
  /** Audit sources (agent lanes) contributing to this run, sorted. */
  sources: string[];
}

/** Read `kriya.corr` out of a receipt's params. Absent/malformed → empty correlation. */
export function readCorr(params: Json): Corr {
  if (!params || typeof params !== "object" || Array.isArray(params)) return {};
  const c = (params as Record<string, Json>)[CORR_KEY];
  if (!c || typeof c !== "object" || Array.isArray(c)) return {};
  const o = c as Record<string, Json | undefined>;
  const str = (v: Json | undefined): string | undefined =>
    typeof v === "string" && v !== "" ? v : undefined;
  return { runId: str(o.run_id), parentStepId: str(o.parent_step_id), agentId: str(o.agent_id) };
}

/** A subagent-spawn action id (Claude Code's Task tool → `claude-code__task`). */
function isSpawn(actionId: string): boolean {
  const a = actionId.toLowerCase();
  return a === "task" || a.endsWith("__task");
}

/**
 * Build the per-run session trees from audit rows. Only VERIFIED receipts that carry a
 * `kriya.corr.run_id` participate; everything else (unverified, uncorrelated, the attestation
 * marker, the `kriya.io.*` ledger) is excluded. Runs are returned most-recent-first.
 */
export function buildSessionTrees(rows: AuditRow[]): RunTree[] {
  // 1. Flatten verified, correlated action receipts into RunAction stubs, grouped by run.
  const byRun = new Map<string, RunAction[]>();
  for (const row of rows) {
    if (!row.outcome.ok || !row.receipt) continue;
    const r = row.receipt;
    if (r.action_id === ATTESTATION_ID) continue; // a run record, not an app action
    const corr = readCorr(r.params);
    if (!corr.runId) continue; // uncorrelated → not part of any run
    const action: RunAction = {
      stepId: r.step_id,
      actionId: r.action_id,
      success: r.success,
      ts: r.ts_ms,
      source: row.source,
      actor: r.actor,
      agentId: corr.agentId ?? null,
      parentStepId: corr.parentStepId ?? null,
      orphaned: false,
      isSpawn: isSpawn(r.action_id),
      children: [],
    };
    const list = byRun.get(corr.runId) ?? [];
    list.push(action);
    byRun.set(corr.runId, list);
  }

  // 2. Per run, assemble the tree.
  const trees: RunTree[] = [];
  for (const [runId, actions] of byRun) {
    const byStep = new Map<string, RunAction>();
    for (const a of actions) byStep.set(a.stepId, a);

    const roots: RunAction[] = [];
    for (const a of actions) {
      const parent = a.parentStepId ? byStep.get(a.parentStepId) : undefined;
      // A parent that exists AND doesn't create a cycle nests; otherwise the action re-roots.
      if (parent && a.parentStepId !== a.stepId && !createsCycle(a, parent, byStep)) {
        parent.children.push(a);
      } else {
        if (a.parentStepId && !parent) a.orphaned = true; // dangling parent → surfaced orphan
        roots.push(a);
      }
    }

    const byTs = (x: RunAction, y: RunAction) => x.ts - y.ts || x.stepId.localeCompare(y.stepId);
    roots.sort(byTs);
    for (const a of actions) a.children.sort(byTs);

    // Sub-agent grouping (distinct non-null agent_ids).
    const agentCounts = new Map<string, number>();
    for (const a of actions) {
      if (a.agentId) agentCounts.set(a.agentId, (agentCounts.get(a.agentId) ?? 0) + 1);
    }
    const subAgents: SubAgent[] = [...agentCounts.entries()]
      .map(([agentId, count]) => ({ agentId, actions: count }))
      .sort((x, y) => y.actions - x.actions || x.agentId.localeCompare(y.agentId));

    const times = actions.map((a) => a.ts);
    trees.push({
      runId,
      firstTs: Math.min(...times),
      lastTs: Math.max(...times),
      actionCount: actions.length,
      blockedCount: actions.filter((a) => !a.success).length,
      subAgents,
      spawnCount: actions.filter((a) => a.isSpawn).length,
      orphanCount: actions.filter((a) => a.orphaned).length,
      roots,
      sources: [...new Set(actions.map((a) => a.source))].sort(),
    });
  }

  // Most-recent run first (by last activity), stable by runId.
  return trees.sort((a, b) => b.lastTs - a.lastTs || a.runId.localeCompare(b.runId));
}

/** Would nesting `child` under `parent` close a cycle? Walk parents up to the root. */
function createsCycle(
  child: RunAction,
  parent: RunAction,
  byStep: Map<string, RunAction>,
): boolean {
  let cur: RunAction | undefined = parent;
  const seen = new Set<string>();
  while (cur) {
    if (cur.stepId === child.stepId) return true;
    if (seen.has(cur.stepId)) return true; // pre-existing cycle among ancestors
    seen.add(cur.stepId);
    cur = cur.parentStepId ? byStep.get(cur.parentStepId) : undefined;
  }
  return false;
}

/** Fleet-wide summary across all runs — the numbers the evidence-export appendix reports. */
export interface CorrelationSummary {
  runs: number;
  /** Distinct sub-agents observed across all runs (by agent_id, per run). */
  subAgents: number;
  /** Subagent-spawn actions across all runs. */
  spawns: number;
  /** Total correlated actions across all runs. */
  actions: number;
  /** Blocked/failed attempts across correlated runs. */
  blocked: number;
}

/** Roll the trees up into the appendix numbers. `null` when there are no correlated runs at all. */
export function summarizeCorrelation(trees: RunTree[]): CorrelationSummary | null {
  if (trees.length === 0) return null;
  return {
    runs: trees.length,
    subAgents: trees.reduce((n, t) => n + t.subAgents.length, 0),
    spawns: trees.reduce((n, t) => n + t.spawnCount, 0),
    actions: trees.reduce((n, t) => n + t.actionCount, 0),
    blocked: trees.reduce((n, t) => n + t.blockedCount, 0),
  };
}
