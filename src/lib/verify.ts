import * as ed from "@noble/ed25519";
import type { Json, Receipt, SignedReceipt, VerifyOutcome } from "./types";

// noble-ed25519 v2 delegates SHA-512 to the host. Wire WebCrypto (present in
// browsers and Node 18+) so verification behaves identically everywhere.
ed.etc.sha512Async = async (...msgs: Uint8Array[]) => {
  // Copy into a fresh ArrayBuffer-backed view so the argument matches BufferSource
  // across TS lib versions (TS 5.7 made Uint8Array generic over its buffer).
  const data = Uint8Array.from(ed.etc.concatBytes(...msgs));
  const digest = await crypto.subtle.digest("SHA-512", data);
  return new Uint8Array(digest);
};

const HEX_PUBKEY = /^[0-9a-f]{64}$/; // 32 bytes
const HEX_SIG = /^[0-9a-f]{128}$/; // 64 bytes
const encoder = new TextEncoder();

/**
 * Re-derive the exact bytes the Rust host signed.
 *
 * `audit.rs` signs `serde_json::to_vec(&receipt)` where `receipt` is the struct
 * `{ step_id, action_id, params, success, ts_ms }`. Two rules make it canonical:
 *   1. struct fields serialize in DECLARATION order (not alphabetical);
 *   2. `params` is a `serde_json::Value` (BTreeMap) → its object keys serialize SORTED.
 * Output is compact (no whitespace). We reproduce both rules here, so a byte-for-byte
 * match is the only way the signature can verify.
 *
 * Assumptions (hold for every receipt kriya emits today): ASCII object keys (JS sorts by
 * UTF-16 unit, serde by UTF-8 byte — identical for ASCII) and integer/string/bool params
 * (serde's shortest-float formatting can differ from JS for non-integer floats). Revisit
 * if params ever gain float values or non-ASCII keys.
 */
export function canonicalReceiptBytes(r: Receipt): Uint8Array {
  const json =
    "{" +
    '"step_id":' +
    JSON.stringify(r.step_id) +
    ',"action_id":' +
    JSON.stringify(r.action_id) +
    ',"params":' +
    canonicalJson(r.params) +
    ',"success":' +
    (r.success ? "true" : "false") +
    ',"ts_ms":' +
    canonicalNumber(r.ts_ms) +
    "}";
  return encoder.encode(json);
}

function canonicalJson(v: Json): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      return canonicalNumber(v);
    case "string":
      return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k] as Json)).join(",") + "}";
}

function canonicalNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error(`non-finite number in receipt: ${n}`);
  return String(n);
}

/** Verify one signed receipt against its own embedded public key. */
export async function verifyReceipt(s: SignedReceipt): Promise<VerifyOutcome> {
  if (!HEX_PUBKEY.test(s.public_key)) {
    return { ok: false, reason: "public_key must be 32 bytes of lowercase hex" };
  }
  if (!HEX_SIG.test(s.signature)) {
    return { ok: false, reason: "signature must be 64 bytes of lowercase hex" };
  }
  try {
    const msg = canonicalReceiptBytes(s);
    const ok = await ed.verifyAsync(s.signature, msg, s.public_key);
    return ok ? { ok: true } : { ok: false, reason: "signature does not match receipt" };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}
