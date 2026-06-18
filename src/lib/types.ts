/** A JSON value, as it appears in a receipt's `params`. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/**
 * Who took the action (R8) — mirrors `kriya::audit::Actor`. Serialized in declaration
 * order (`agent`, then `user`), which is load-bearing for the signature.
 */
export interface Actor {
  agent: string;
  user: string;
}

/**
 * The unsigned receipt. Field order mirrors `crates/kriya/src/audit.rs` exactly —
 * it is load-bearing: the host signs `serde_json::to_vec(&receipt)` over this shape.
 * `actor` is optional and, when present, signed LAST (R8).
 */
export interface Receipt {
  step_id: string;
  action_id: string;
  params: Json;
  success: boolean;
  ts_ms: number;
  actor?: Actor;
}

/** A full JSONL line: the receipt fields flattened, then `public_key` + `signature` (lowercase hex). */
export interface SignedReceipt extends Receipt {
  public_key: string;
  signature: string;
}

export type VerifyOutcome = { ok: true } | { ok: false; reason: string };

/** A parsed + verified line, tagged with the source it came from (filename = the "app"). */
export interface AuditRow {
  source: string;
  lineNo: number;
  raw: string;
  receipt?: SignedReceipt;
  outcome: VerifyOutcome;
}
