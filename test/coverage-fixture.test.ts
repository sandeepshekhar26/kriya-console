import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { loadAuditLog } from "../src/lib/receipts";

// W1-8: REAL `kriya.coverage.snapshot` receipts signed by the Console's own mini-signer
// (src-tauri/src/coverage.rs emit_snapshot, via the ignored generate_ts_parity_fixture test).
// If the Console's canonical signed-byte construction drifted from the runtime format by one
// byte, the TS verifier would reject these — the same parity gate the gateway receipts get.
const here = dirname(fileURLToPath(import.meta.url));
const fixture = readFileSync(join(here, "fixtures/coverage-sample.jsonl"), "utf8");

describe("Console-signed coverage snapshots verify in the TS spine (W1-8)", () => {
  it("verifies every snapshot receipt byte-identically", async () => {
    const rows = await loadAuditLog(fixture, "coverage.jsonl");
    expect(rows.length).toBe(2);
    const failures = rows.filter((r) => !r.outcome.ok);
    expect(failures.map((f) => (f.outcome.ok ? "" : f.outcome.reason))).toEqual([]);
  });

  it("snapshots are coverage-shaped: action id, six lanes, states only", async () => {
    const rows = await loadAuditLog(fixture, "coverage.jsonl");
    for (const row of rows) {
      const r = row.receipt!;
      expect(r.action_id).toBe("kriya.coverage.snapshot");
      const lanes = (r.params as { lanes: Record<string, { state: string }> }).lanes;
      expect(Object.keys(lanes).sort()).toEqual([
        "claude-code-tools",
        "desktop-apps",
        "local-stdio-mcp",
        "raw-egress",
        "raw-file-exec",
        "remote-mcp",
      ]);
      for (const lane of Object.values(lanes)) {
        expect(["green", "amber", "grey"]).toContain(lane.state);
      }
    }
  });

  it("snapshots hash-chain like any other receipts (visible-by-absence anchor)", () => {
    const lines = fixture.split("\n").filter((l) => l.trim().length > 0);
    const first = JSON.parse(lines[0]!);
    const second = JSON.parse(lines[1]!);
    expect(first.prev_hash).toBeUndefined();
    const h1 = createHash("sha256").update(Buffer.from(lines[0]!, "utf8")).digest("hex");
    expect(second.prev_hash).toBe(h1);
  });
});
