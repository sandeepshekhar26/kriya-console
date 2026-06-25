//! Authoritative, **compiled** receipt verification — the on-device "tamper-proof anchoring" the
//! Console sells (D-018). The free browser verifier (`src/lib/verify.ts`) re-derives the same bytes
//! for the import path, but the live monitor and every paid feature verify here, in Rust, so the
//! verdict an auditor relies on is produced by code that can't be lifted out of a shipped `.app`.
//!
//! The canonical signed-byte format mirrors `crates/kriya/src/audit.rs` exactly (kept honest by the
//! `canonical_parity` test): the host signs `serde_json::to_vec(&receipt)` where the receipt struct
//! serializes its fields in **declaration order** — `step_id, action_id, params, success, ts_ms`,
//! then the optional `actor` (R8), then the optional `prev_hash` (R20 hash-chain) — both skipped when
//! absent, and `params` object keys recursively **sorted** (R21). Reproduce all three rules and a
//! byte-for-byte match is the only way the Ed25519 signature can verify.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Who took the action (R8). Field order (`agent`, then `user`) is load-bearing for the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub agent: String,
    pub user: String,
}

/// The receipt fields in **declaration order**, serialized to reproduce the host's signed bytes.
/// `actor` and `prev_hash` are skipped when absent so an unattributed / genesis receipt signs
/// byte-identically to the pre-R8 / pre-R20 shape.
#[derive(Serialize)]
struct CanonicalReceipt {
    step_id: String,
    action_id: String,
    params: Value,
    success: bool,
    ts_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<Actor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<String>,
}

/// One parsed + verified JSONL row, tagged with the file it came from (filename = the "app"). Shape
/// matches the TS `AuditRow` so the React views render Rust- and browser-verified rows identically.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRow {
    pub source: String,
    pub line_no: usize,
    pub raw: String,
    /// The parsed signed receipt (passthrough JSON) when the line is a well-formed receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
    /// `{ ok: true }` or `{ ok: false, reason }` — verified in compiled Rust.
    pub outcome: Value,
}

fn ok() -> Value {
    json!({ "ok": true })
}
fn bad(reason: impl Into<String>) -> Value {
    json!({ "ok": false, "reason": reason.into() })
}

/// Parse a JSONL audit log and verify every line, returning rows in source order. Malformed or
/// non-receipt lines become failed rows rather than being dropped — a tampered/forged line should be
/// *visible* in the trail, not silently filtered.
pub fn load_rows(source: &str, text: &str) -> Vec<AuditRow> {
    let mut rows = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let line_no = i + 1;
        let parsed: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                rows.push(AuditRow {
                    source: source.to_string(),
                    line_no,
                    raw: raw.to_string(),
                    receipt: None,
                    outcome: bad(format!("JSON parse error: {e}")),
                });
                continue;
            }
        };
        let outcome = match verify_value(&parsed) {
            Ok(()) => ok(),
            Err(reason) => bad(reason),
        };
        let is_receipt = looks_like_receipt(&parsed);
        rows.push(AuditRow {
            source: source.to_string(),
            line_no,
            raw: raw.to_string(),
            receipt: is_receipt.then(|| parsed.clone()),
            outcome,
        });
    }
    rows
}

fn looks_like_receipt(v: &Value) -> bool {
    v.get("step_id").map(Value::is_string).unwrap_or(false)
        && v.get("action_id").map(Value::is_string).unwrap_or(false)
        && v.get("signature").map(Value::is_string).unwrap_or(false)
        && v.get("public_key").map(Value::is_string).unwrap_or(false)
}

/// Verify one parsed signed receipt against its own embedded Ed25519 public key. `Ok(())` ⇒ the
/// signature matches the canonical bytes; `Err(reason)` ⇒ malformed, forged, or tampered.
pub fn verify_value(v: &Value) -> Result<(), String> {
    let public_key = v
        .get("public_key")
        .and_then(Value::as_str)
        .ok_or("not a signed receipt (missing public_key)")?;
    let signature = v
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("not a signed receipt (missing signature)")?;
    let step_id = field_str(v, "step_id")?;
    let action_id = field_str(v, "action_id")?;
    let success = v
        .get("success")
        .and_then(Value::as_bool)
        .ok_or("success must be a boolean")?;
    let ts_ms = v
        .get("ts_ms")
        .and_then(Value::as_u64)
        .ok_or("ts_ms must be a non-negative integer")?;
    let params = v.get("params").cloned().unwrap_or(Value::Null);
    let actor = match v.get("actor") {
        None | Some(Value::Null) => None,
        Some(a) => Some(
            serde_json::from_value::<Actor>(a.clone())
                .map_err(|e| format!("malformed actor: {e}"))?,
        ),
    };
    let prev_hash = match v.get("prev_hash") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("prev_hash must be a string".into()),
    };

    let pub_bytes = decode_fixed::<32>(public_key).ok_or("public_key must be 32 bytes of hex")?;
    let sig_bytes = decode_fixed::<64>(signature).ok_or("signature must be 64 bytes of hex")?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| format!("bad public key: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let canon = CanonicalReceipt {
        step_id: step_id.to_string(),
        action_id: action_id.to_string(),
        params: canonical_value(&params),
        success,
        ts_ms,
        actor,
        prev_hash,
    };
    let msg = serde_json::to_vec(&canon).map_err(|e| format!("canonicalize: {e}"))?;
    vk.verify(&msg, &sig)
        .map_err(|_| "signature does not match receipt".to_string())
}

fn field_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Recursively sort object keys so serialization is deterministic regardless of any build's
/// serde_json `preserve_order` flag (R21). Arrays keep order; their object elements are sorted.
/// Identical to `crates/kriya/src/audit.rs::canonical_value`.
pub fn canonical_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical_value(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}

/// Lowercase-hex SHA-256 of `bytes` — the hash-chain link primitive (R20). Each receipt's
/// `prev_hash` should equal the SHA-256 of the previous **line** on disk.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Verify a file's hash-chain (R20): each non-genesis line's `prev_hash` must equal the SHA-256 of
/// the previous non-empty line. Returns the 1-based line number of the first break, or `None` if the
/// whole chain is intact (deletion / truncation / reorder all surface as a break).
pub fn chain_break(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.split('\n').filter(|l| !l.trim().is_empty()).collect();
    let mut prev_line_hash: Option<String> = None;
    for (idx, line) in lines.iter().enumerate() {
        let parsed: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(idx + 1),
        };
        let declared = parsed
            .get("prev_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        // The genesis line declares no prev_hash; every later line must point at the line before it.
        if declared != prev_line_hash {
            return Some(idx + 1);
        }
        prev_line_hash = Some(sha256_hex(line.as_bytes()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Sign a receipt the way `audit.rs` does, then confirm Rust verification accepts it and a
    /// 1-byte tamper is rejected — the canonical-format parity guard.
    #[test]
    fn canonical_parity_round_trip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let canon = CanonicalReceipt {
            step_id: "s1".into(),
            action_id: "delete_transaction".into(),
            params: canonical_value(&json!({ "z": 1, "a": { "y": 2, "x": 3 } })),
            success: true,
            ts_ms: 1_700_000_000_000,
            actor: Some(Actor {
                agent: "claude".into(),
                user: "sandeep".into(),
            }),
            prev_hash: Some("deadbeef".into()),
        };
        let msg = serde_json::to_vec(&canon).unwrap();
        let sig = hex::encode(key.sign(&msg).to_bytes());
        let pk = hex::encode(key.verifying_key().to_bytes());

        let mut line = json!({
            "step_id": "s1",
            "action_id": "delete_transaction",
            "params": { "z": 1, "a": { "y": 2, "x": 3 } },
            "success": true,
            "ts_ms": 1_700_000_000_000u64,
            "actor": { "agent": "claude", "user": "sandeep" },
            "prev_hash": "deadbeef",
            "public_key": pk,
            "signature": sig,
        });
        assert!(verify_value(&line).is_ok(), "honest receipt must verify");

        line["success"] = json!(false); // tamper
        assert!(verify_value(&line).is_err(), "tampered receipt must fail");
    }

    #[test]
    fn genesis_receipt_without_actor_or_chain_verifies() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let canon = CanonicalReceipt {
            step_id: "g".into(),
            action_id: "list_notes".into(),
            params: json!({}),
            success: true,
            ts_ms: 42,
            actor: None,
            prev_hash: None,
        };
        let msg = serde_json::to_vec(&canon).unwrap();
        let line = json!({
            "step_id": "g", "action_id": "list_notes", "params": {},
            "success": true, "ts_ms": 42,
            "public_key": hex::encode(key.verifying_key().to_bytes()),
            "signature": hex::encode(key.sign(&msg).to_bytes()),
        });
        assert!(verify_value(&line).is_ok());
    }

    /// End-to-end proof of the LIVE path: a two-receipt hash-chained log (genesis + a chained,
    /// attributed destructive action) must both verify via `load_rows` AND have an intact chain —
    /// the exact shape the gateway writes and the Console tails. Guards the `prev_hash` handling.
    #[test]
    fn chained_two_receipt_log_verifies_end_to_end() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());

        let c1 = CanonicalReceipt {
            step_id: "s1".into(),
            action_id: "list_notes".into(),
            params: json!({}),
            success: true,
            ts_ms: 100,
            actor: None,
            prev_hash: None,
        };
        let sig1 = hex::encode(key.sign(&serde_json::to_vec(&c1).unwrap()).to_bytes());
        let line1 = serde_json::to_string(&json!({
            "step_id": "s1", "action_id": "list_notes", "params": {},
            "success": true, "ts_ms": 100, "public_key": pk, "signature": sig1,
        }))
        .unwrap();
        let h1 = sha256_hex(line1.as_bytes());

        let c2 = CanonicalReceipt {
            step_id: "s2".into(),
            action_id: "delete_note".into(),
            params: json!({ "id": "x" }),
            success: true,
            ts_ms: 200,
            actor: Some(Actor {
                agent: "claude".into(),
                user: "sandeep".into(),
            }),
            prev_hash: Some(h1.clone()),
        };
        let sig2 = hex::encode(key.sign(&serde_json::to_vec(&c2).unwrap()).to_bytes());
        let line2 = serde_json::to_string(&json!({
            "step_id": "s2", "action_id": "delete_note", "params": { "id": "x" },
            "success": true, "ts_ms": 200,
            "actor": { "agent": "claude", "user": "sandeep" }, "prev_hash": h1,
            "public_key": pk, "signature": sig2,
        }))
        .unwrap();

        let log = format!("{line1}\n{line2}\n");
        let rows = load_rows("notes.jsonl", &log);
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|r| r.outcome.get("ok").and_then(|v| v.as_bool()) == Some(true)),
            "both chained receipts must verify, got {:?}",
            rows.iter().map(|r| &r.outcome).collect::<Vec<_>>()
        );
        assert_eq!(chain_break(&log), None, "intact chain");
    }

    #[test]
    fn chain_break_detects_deletion() {
        // Two well-formed lines where line 2 points at line 1; deleting line 1 breaks the chain.
        let l1 = "alpha";
        let h1 = sha256_hex(l1.as_bytes());
        let l2 = format!("{{\"prev_hash\":\"{h1}\"}}");
        let intact = format!("{l1}\n{l2}\n");
        // l1 isn't valid JSON, so chain_break flags line 1 regardless — use JSON lines instead:
        let a = json!({ "n": 1 }).to_string();
        let ha = sha256_hex(a.as_bytes());
        let b = json!({ "n": 2, "prev_hash": ha }).to_string();
        let good = format!("{a}\n{b}\n");
        assert_eq!(chain_break(&good), None);
        // Drop the genesis line: line "b" now declares a prev_hash with nothing before it → break at 1.
        assert_eq!(chain_break(&format!("{b}\n")), Some(1));
        let _ = intact; // (the non-JSON sketch above is illustrative only)
    }
}
