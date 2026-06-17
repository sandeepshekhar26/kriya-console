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
