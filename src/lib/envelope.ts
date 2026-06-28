import * as ed from "@noble/ed25519";

// noble-ed25519 v2 delegates SHA-512 to the host (same wiring as verify.ts; idempotent if both load).
ed.etc.sha512Async = async (...msgs: Uint8Array[]) => {
  const data = Uint8Array.from(ed.etc.concatBytes(...msgs));
  const digest = await crypto.subtle.digest("SHA-512", data);
  return new Uint8Array(digest);
};

const HEX_PUBKEY = /^[0-9a-f]{64}$/; // 32 bytes
const HEX_SIG = /^[0-9a-f]{128}$/; // 64 bytes
const encoder = new TextEncoder();

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/**
 * Recursively key-sorted, compact JSON — byte-identical to Rust's `kriya_verify::canonical_json_bytes`
 * for the envelope shape (ASCII keys; integer/string/bool/array/object values). The whole envelope is
 * canonical-sorted (unlike a receipt, which is declaration-order), so this is just a generic sort.
 *
 * Assumption (holds for every envelope kriya emits): ASCII object keys (JS sorts by UTF-16 unit, serde
 * by UTF-8 byte — identical for ASCII) and integer numbers (no floats in an envelope).
 */
function canonicalJson(v: Json): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new Error(`non-finite number in envelope: ${v}`);
      return String(v);
    case "string":
      return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k] as Json)).join(",") + "}";
}

/** Exposed for the hash-chain check: the exact canonical string Rust's `canonical_json_bytes` produces. */
export function canonicalJsonString(v: unknown): string {
  return canonicalJson(v as Json);
}

/** SHA-256 hex of a string's UTF-8 bytes — the envelope-chain link (`prev_envelope_hash`). */
export async function sha256Hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(s));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface SignedEnvelope {
  envelope: Record<string, Json>;
  public_key: string;
  signature: string;
}

export interface VerifyOutcome {
  ok: boolean;
  reason?: string;
}

/** Re-derive the exact bytes the device signed over an AttestationEnvelope. */
export function canonicalEnvelopeBytes(envelope: Record<string, Json>): Uint8Array {
  return encoder.encode(canonicalJson(envelope as Json));
}

/**
 * Verify a SignedEnvelope independently of the device: `device_pub` must equal `public_key`, and the
 * Ed25519 signature must match the canonical envelope bytes. The TS half of the envelope trust spine
 * (parity with `kriya_verify::verify_envelope` — count sanity is the Rust verifier's concern).
 */
export async function verifyEnvelope(s: SignedEnvelope): Promise<VerifyOutcome> {
  if (!HEX_PUBKEY.test(s.public_key)) {
    return { ok: false, reason: "public_key must be 32 bytes of lowercase hex" };
  }
  if (!HEX_SIG.test(s.signature)) {
    return { ok: false, reason: "signature must be 64 bytes of lowercase hex" };
  }
  if (s.envelope?.device_pub !== s.public_key) {
    return { ok: false, reason: "device_pub does not match public_key" };
  }
  try {
    const msg = canonicalEnvelopeBytes(s.envelope);
    const ok = await ed.verifyAsync(s.signature, msg, s.public_key);
    return ok ? { ok: true } : { ok: false, reason: "envelope signature does not match" };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}
