import * as ed from "@noble/ed25519";

// noble-ed25519 v2 delegates SHA-512 to the host (same wiring as verify.ts/envelope.ts; idempotent if
// more than one module installs it).
ed.etc.sha512Async = async (...msgs: Uint8Array[]) => {
  const data = Uint8Array.from(ed.etc.concatBytes(...msgs));
  const digest = await crypto.subtle.digest("SHA-512", data);
  return new Uint8Array(digest);
};

const HEX_SIG = /^[0-9a-f]{128}$/; // 64 bytes
const HEX_PUBKEY = /^[0-9a-f]{64}$/; // 32 bytes
const encoder = new TextEncoder();

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/**
 * Recursively key-sorted, compact JSON — byte-identical to Rust's `kriya_verify::canonical_json_bytes`.
 * Same generic canonicalizer as `envelope.ts`/`verify.ts` (kept as its own copy per module, matching
 * the existing convention, rather than a shared import — each signed-artifact module stays pure and
 * self-contained).
 */
function canonicalJson(v: Json): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new Error(`non-finite number in policy bundle: ${v}`);
      return String(v);
    case "string":
      return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k] as Json)).join(",") + "}";
}

export interface PolicyScope {
  business_unit?: string | null;
  device_pubs?: string[] | null;
}

export interface GovernDirective {
  target: string;
  action: string;
}

/** Mirrors Rust `kriya_verify::PolicyBundle` — see doc 22 §5. */
export interface PolicyBundle {
  org_id: string;
  version: number;
  issued_ms: number;
  expires_ms?: number | null;
  scope: PolicyScope;
  policy: Record<string, Json>;
  budgets: Record<string, Json>;
  govern?: GovernDirective[];
  envelope_verbosity?: string;
}

export interface SignedPolicyBundle {
  bundle: PolicyBundle;
  signature: string;
}

export interface VerifyOutcome {
  ok: boolean;
  reason?: string;
}

/** Re-derive the exact bytes the org policy key signed over a `PolicyBundle`. */
export function canonicalPolicyBundleBytes(bundle: Record<string, Json>): Uint8Array {
  return encoder.encode(canonicalJson(bundle as Json));
}

/**
 * Verify a `SignedPolicyBundle` against a PINNED `orgPolicyPub` (lowercase hex) — NEVER a key the
 * payload itself asserts (a policy bundle carries no embedded public key; see `policy.rs`'s module
 * docs for why). Parity with Rust's `kriya_verify::verify_policy_bundle`.
 */
export async function verifyPolicyBundle(
  s: SignedPolicyBundle,
  orgPolicyPub: string,
): Promise<VerifyOutcome> {
  if (!HEX_PUBKEY.test(orgPolicyPub)) {
    return { ok: false, reason: "org_policy_pub must be 32 bytes of lowercase hex" };
  }
  if (!HEX_SIG.test(s.signature)) {
    return { ok: false, reason: "signature must be 64 bytes of lowercase hex" };
  }
  try {
    const msg = canonicalPolicyBundleBytes(s.bundle as unknown as Record<string, Json>);
    const ok = await ed.verifyAsync(s.signature, msg, orgPolicyPub);
    return ok ? { ok: true } : { ok: false, reason: "policy bundle signature does not match" };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

/** Anti-rollback: parity with Rust's `kriya_verify::supersedes`. */
export function supersedes(newVersion: number, lastApplied: number | null): boolean {
  return lastApplied === null ? true : newVersion > lastApplied;
}
