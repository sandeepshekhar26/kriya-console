import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadAuditLog } from "../src/lib/receipts";
import { verifyReceipt } from "../src/lib/verify";
import type { SignedReceipt } from "../src/lib/types";

const here = dirname(fileURLToPath(import.meta.url));
// Real receipts emitted by the Rust host (crates/kriya). Ground-truth-verified by
// tools/verify-receipts before being committed. If the TS canonicalization were off
// by a single byte, none of these would verify.
const sample = readFileSync(join(here, "../src/sample/sample-audit.jsonl"), "utf8");

describe("verify against REAL Rust-signed receipts", () => {
  it("parses every sample line into a receipt", async () => {
    const rows = await loadAuditLog(sample, "sample");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.receipt !== undefined)).toBe(true);
  });

  it("verifies every real receipt (byte-identical to serde_json + ed25519-dalek)", async () => {
    const rows = await loadAuditLog(sample, "sample");
    const failures = rows.filter((r) => !r.outcome.ok);
    expect(failures.map((f) => (f.outcome.ok ? "" : f.outcome.reason))).toEqual([]);
  });
});

describe("tamper + forgery detection", () => {
  async function firstReceipt(): Promise<SignedReceipt> {
    const rows = await loadAuditLog(sample, "sample");
    const r = rows[0]?.receipt;
    if (!r) throw new Error("no fixture receipt");
    return r;
  }

  it("rejects tampered params", async () => {
    const r = await firstReceipt();
    const tampered: SignedReceipt = { ...r, params: { ...(r.params as object), injected: "EVIL" } as never };
    expect((await verifyReceipt(tampered)).ok).toBe(false);
  });

  it("rejects a flipped success flag", async () => {
    const r = await firstReceipt();
    expect((await verifyReceipt({ ...r, success: !r.success })).ok).toBe(false);
  });

  it("rejects a swapped action_id", async () => {
    const r = await firstReceipt();
    expect((await verifyReceipt({ ...r, action_id: "delete_everything" })).ok).toBe(false);
  });

  it("rejects a forged signature", async () => {
    const r = await firstReceipt();
    const forged = r.signature.replace(/^./, (c) => (c === "a" ? "b" : "a"));
    expect((await verifyReceipt({ ...r, signature: forged })).ok).toBe(false);
  });

  it("rejects a mismatched public key", async () => {
    const r = await firstReceipt();
    const other = "00".repeat(32);
    expect((await verifyReceipt({ ...r, public_key: other })).ok).toBe(false);
  });

  it("rejects malformed hex without throwing", async () => {
    const r = await firstReceipt();
    expect((await verifyReceipt({ ...r, public_key: "not-hex" })).ok).toBe(false);
    expect((await verifyReceipt({ ...r, signature: "zz" })).ok).toBe(false);
  });
});

// S3 run correlation: real Rust-signed receipts carrying `kriya.corr` (run_id / agent_id /
// parent_step_id) must verify byte-for-byte in the TS verifier — the frozen-schema + TS↔Rust-parity
// proof that correlation rides `params` and changes no signing rule. The fixture also carries a
// LEGACY (pre-S3, no-corr) receipt: the cross-version guarantee that old receipts verify unchanged.
// Generated via the real `kriya-govern` binary (see the PR notes); regenerate the same way.
const corrSample = readFileSync(join(here, "fixtures/s3-corr-audit.jsonl"), "utf8");

describe("run correlation (S3) — TS↔Rust parity on kriya.corr receipts", () => {
  it("verifies every correlated + legacy receipt byte-for-byte", async () => {
    const rows = await loadAuditLog(corrSample, "s3-corr");
    expect(rows.length).toBe(3);
    expect(rows.every((r) => r.outcome.ok)).toBe(true); // incl. the legacy no-corr line
  });

  it("the fixture actually carries kriya.corr (we are testing the real thing)", async () => {
    const rows = await loadAuditLog(corrSample, "s3-corr");
    const corr = (r: SignedReceipt) => (r.params as Record<string, unknown>)["kriya.corr"] as
      | Record<string, string>
      | undefined;
    expect(corr(rows[0]!.receipt!)).toMatchObject({ run_id: "sess-fixture-1", agent_id: "subagent-explore-1" });
    expect(corr(rows[1]!.receipt!)).toMatchObject({ run_id: "run-fixture-2", parent_step_id: "step-parent-abc" });
    expect(corr(rows[2]!.receipt!)).toBeUndefined(); // the legacy receipt has none
  });

  it("tampering a run id inside kriya.corr breaks the signature (it is inside the signed bytes)", async () => {
    const rows = await loadAuditLog(corrSample, "s3-corr");
    const r = rows[0]!.receipt!;
    const params = r.params as Record<string, unknown>;
    const corr = { ...(params["kriya.corr"] as Record<string, string>), run_id: "FORGED-RUN" };
    const tampered: SignedReceipt = { ...r, params: { ...params, "kriya.corr": corr } as never };
    expect((await verifyReceipt(tampered)).ok).toBe(false);
  });
});

describe("parse robustness", () => {
  it("flags concatenated / garbage lines as failed rows, not crashes", async () => {
    const rows = await loadAuditLog('{"a":1}{"b":2}\nnot json at all\n', "junk");
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => !r.outcome.ok)).toBe(true);
  });

  it("skips blank lines", async () => {
    const rows = await loadAuditLog("\n\n   \n", "blank");
    expect(rows).toHaveLength(0);
  });
});
