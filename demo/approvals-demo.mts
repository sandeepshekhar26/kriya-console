// R6 increment 3 — approval routing demo.
//
//   node --experimental-strip-types demo/approvals-demo.mts
//   (or: npm run demo:approvals)
//
// Loads the sample cross-app approval queue, prioritizes it (high-risk first, oldest-first
// within a tier), shows the per-app and per-agent lenses, then records two decisions and
// prints the resulting state. Pure model — the React view is a thin shell over exactly this.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  decide,
  groupBy,
  ingestPending,
  parsePendingApprovals,
  routeQueue,
  summarize,
  type QueueState,
} from "../src/lib/approvals.ts";

const here = dirname(fileURLToPath(import.meta.url));
const text = readFileSync(join(here, "../src/sample/sample-approvals.jsonl"), "utf8");
const now = 1781809300000; // fixed "now" so the demo output is stable

let state: QueueState = { pending: [], decided: [] };
state = ingestPending(state, parsePendingApprovals(text, "sample"));

console.log("=== Incoming approval queue (cross-app) ===");
console.log(`${state.pending.length} guarded actions waiting for a human\n`);

const routed = routeQueue(state.pending, now);
console.log("=== Routed — high-risk first, then longest-waiting ===");
for (const a of routed) {
  const who = a.actor ? `${a.actor.agent}/${a.actor.user}` : "(unattributed)";
  const risk = a.risk === "high" ? "HIGH" : "    ";
  console.log(`  [${risk}] ${a.action_id.padEnd(20)} ${a.source.padEnd(11)} ${who.padEnd(24)} waited ${a.waitingSeconds}s`);
}

console.log("\n=== Grouped by agent ===");
for (const [agent, items] of groupBy(routed, "agent")) {
  console.log(`  ${agent}: ${items.map((i) => i.action_id).join(", ")}`);
}

console.log("\n=== Operator triages the two riskiest ===");
const top = routed[0]!;
const second = routed[1]!;
state = decide(state, top.id, "denied", "Cannot verify this is a duplicate — needs manual review", "ops@local", now + 1000);
console.log(`  DENY    ${top.action_id} (${top.source}) — reason recorded`);
state = decide(state, second.id, "approved", "Confirmed with the account holder", "ops@local", now + 2000);
console.log(`  APPROVE ${second.action_id} (${second.source})`);

const s = summarize(state);
console.log("\n=== Queue state after decisions ===");
console.log(`  pending=${s.pending}  high-risk=${s.highRiskPending}  approved=${s.approved}  denied=${s.denied}`);
console.log("\nDone. R6 inc 3: one prioritized, persistable queue across every app + agent.");
