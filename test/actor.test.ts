import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadAuditLog } from "../src/lib/receipts";
import { canonicalReceiptBytes, verifyReceipt } from "../src/lib/verify";
import type { Receipt, SignedReceipt } from "../src/lib/types";

const here = dirname(fileURLToPath(import.meta.url));
// REAL actor-bearing receipts emitted by the Rust host (kriya-mcp --actor), cross-verified
// by tools/verify-receipts before being committed. If the TS canonicalization of the R8
// `actor` field were off by a byte, neither would verify.
const sample = readFileSync(join(here, "../src/sample/sample-audit-actor.jsonl"), "utf8");
const decoder = new TextDecoder();

describe("R8 — verify REAL actor-bearing receipts", () => {
  it("parses and surfaces the actor", async () => {
    const rows = await loadAuditLog(sample, "actor");
    expect(rows.length).toBe(2);
    expect(rows[0]?.receipt?.actor).toEqual({ agent: "claude-desktop", user: "alice" });
  });

  it("verifies every actor receipt byte-identically to the Rust signer", async () => {
    const rows = await loadAuditLog(sample, "actor");
    const failures = rows.filter((r) => !r.outcome.ok);
    expect(failures.map((f) => (f.outcome.ok ? "" : f.outcome.reason))).toEqual([]);
  });

  it("rejects a forged operator — attribution is inside the signed bytes", async () => {
    const rows = await loadAuditLog(sample, "actor");
    const r = rows[0]?.receipt as SignedReceipt;
    const tampered: SignedReceipt = { ...r, actor: { agent: r.actor!.agent, user: "mallory" } };
    expect((await verifyReceipt(tampered)).ok).toBe(false);
  });
});

describe("R8 — canonicalization parity", () => {
  const base: Receipt = {
    step_id: "s",
    action_id: "a",
    params: {},
    success: true,
    ts_ms: 1,
  };

  it("omits actor entirely when absent (byte-identical to pre-R8)", () => {
    const bytes = decoder.decode(canonicalReceiptBytes(base));
    expect(bytes).toBe('{"step_id":"s","action_id":"a","params":{},"success":true,"ts_ms":1}');
  });

  it("appends actor LAST in declaration order when present", () => {
    const withActor: Receipt = { ...base, actor: { agent: "agentX", user: "userY" } };
    const bytes = decoder.decode(canonicalReceiptBytes(withActor));
    expect(bytes).toBe(
      '{"step_id":"s","action_id":"a","params":{},"success":true,"ts_ms":1,"actor":{"agent":"agentX","user":"userY"}}',
    );
  });
});
