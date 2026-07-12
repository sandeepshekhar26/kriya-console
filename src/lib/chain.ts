//! The receipt hash-chain check (R20) in TypeScript — the FIRST TS implementation of the rule the
//! compiled `kriya_verify::chain_continues_from` (crates/kriya-verify/src/receipts.rs) enforces:
//! each non-genesis line's `prev_hash` must equal the lowercase-hex SHA-256 of the PREVIOUS raw JSONL
//! line's bytes, and the genesis (first) line must carry no `prev_hash`. A deletion, truncation,
//! reorder, or single-byte edit of any line surfaces as a break.
//!
//! Pure and DOM-free on purpose, so the desktop `AuditView` and the offline self-verifying artifact
//! (`src/selfverify/runtime.ts`) share this ONE implementation rather than each rolling their own — a
//! second, subtly-different chain check is exactly how a false green ships.
//!
//! Parity: this mirrors `chain_continues_from(None, lines)` — the genesis seed is `null`. The
//! *envelope* chain (`prev_envelope_hash`) is a different linkage with its own sibling primitive
//! (`sha256Hex` in envelope.ts); this module is the RECEIPT-line chain.

const encoder = new TextEncoder();

/** Lowercase-hex SHA-256 of a string's UTF-8 bytes — the chain link (parity with Rust `sha256_hex`). */
export async function sha256Hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(s));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Verify a receipt hash-chain over the given RAW JSONL lines. The caller passes the lines already
 * split and with blank lines removed, but otherwise VERBATIM — the exact bytes on disk are what the
 * previous line's hash committed to, so any normalization here would defeat the check.
 *
 * Returns the 1-based index of the first line that breaks the chain, or `null` if the whole chain is
 * intact. Mirrors `kriya_verify::chain_continues_from(None, lines)` exactly:
 *   - the first line must declare no `prev_hash` (genesis, seed = null);
 *   - every later line's `prev_hash` must equal `sha256Hex(previous raw line)`;
 *   - a line that is not valid JSON breaks the chain at its own index.
 *
 * NEVER fails open: any structural surprise returns a break index, not `null`.
 */
export async function chainBreak(lines: string[]): Promise<number | null> {
  let prevLineHash: string | null = null; // genesis seed = None
  for (const [i, line] of lines.entries()) {
    let declared: string | null;
    try {
      const parsed = JSON.parse(line) as { prev_hash?: unknown };
      // Only a *string* prev_hash counts (Rust reads it via `Value::as_str`); anything else → null,
      // which correctly breaks a non-genesis line.
      declared = typeof parsed.prev_hash === "string" ? parsed.prev_hash : null;
    } catch {
      return i + 1; // unparseable line → break here (matches Rust's parse-error arm)
    }
    // Each line must point at the line before it; the first line must match the genesis seed (null).
    if (declared !== prevLineHash) return i + 1;
    prevLineHash = await sha256Hex(line);
  }
  return null;
}
