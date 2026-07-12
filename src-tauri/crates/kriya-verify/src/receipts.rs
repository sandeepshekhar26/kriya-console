//! Authoritative signed-receipt verification + the hash-chain integrity check (moved from the
//! Console's `receipts.rs`, 0.3). The verdict an auditor relies on is produced here, by compiled code
//! the Console, the `kriyad` server, and the auditor CLI all share.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canonical::{canonical_value, sha256_hex};
use crate::sig::verify_detached;

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

    // Build the canonical signed MESSAGE here (the construction stays at the call site); the raw
    // Ed25519 decode + verify is the shared `verify_detached` primitive.
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
    verify_detached(public_key, signature, &msg)
}

/// Sign a NEW receipt — the production counterpart to [`verify_value`]'s reconstruction, reusing the
/// exact same [`CanonicalReceipt`] shape so the result round-trips through the identical
/// verify/chain/Compiler pipeline as any front-signed receipt. For control-plane-internal events the
/// Console itself needs to attest (e.g. `kriya.policy.applied`, doc 22 §5) — not a general-purpose
/// front-signing API; the runtime's own hooks/gateway sign their receipts independently in
/// `experiment1`. Returns the full signed JSON line (params canonically key-sorted, `actor`/`prev_hash`
/// omitted when absent, `public_key`/`signature` appended) — the caller writes/chains it into an audit
/// source file exactly like any other receipt.
#[allow(clippy::too_many_arguments)] // mirrors CanonicalReceipt's own field count 1:1 (compile_window has the same allow)
pub fn sign_receipt(
    key: &SigningKey,
    step_id: &str,
    action_id: &str,
    params: Value,
    success: bool,
    ts_ms: u64,
    actor: Option<Actor>,
    prev_hash: Option<String>,
) -> Value {
    let canon = CanonicalReceipt {
        step_id: step_id.to_string(),
        action_id: action_id.to_string(),
        params: canonical_value(&params),
        success,
        ts_ms,
        actor,
        prev_hash,
    };
    let msg = serde_json::to_vec(&canon).expect("CanonicalReceipt always serializes");
    let signature = hex::encode(key.sign(&msg).to_bytes());
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let mut v = serde_json::to_value(&canon).unwrap_or(Value::Null);
    if let Value::Object(ref mut obj) = v {
        obj.insert("public_key".into(), Value::String(public_key));
        obj.insert("signature".into(), Value::String(signature));
    }
    v
}

fn field_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

/// Verify a file's hash-chain (R20): each non-genesis line's `prev_hash` must equal the SHA-256 of
/// the previous non-empty line. Returns the 1-based line number of the first break, or `None` if the
/// whole chain is intact (deletion / truncation / reorder all surface as a break).
pub fn chain_break(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.split('\n').filter(|l| !l.trim().is_empty()).collect();
    chain_continues_from(None, &lines)
}

/// Windowed continuity for the Compiler's incremental tail (0.8): like [`chain_break`] but the
/// expected `prev_hash` of the FIRST line is seeded from `prev_tail_hash` (the SHA-256 of the prior
/// window's last line) instead of `None`. So tailing "new lines since last seq" doesn't false-positive
/// on the first line, which legitimately points back into the previous window. `lines` are the exact
/// (non-empty JSON) lines to check; the returned index is 1-based into this slice. Passing the genesis
/// seed `None` recovers [`chain_break`]'s behavior exactly — `chain_break(text)` is defined as
/// `chain_continues_from(None, &non_empty_lines(text))`.
pub fn chain_continues_from(prev_tail_hash: Option<&str>, lines: &[&str]) -> Option<usize> {
    let mut prev_line_hash: Option<String> = prev_tail_hash.map(str::to_string);
    for (idx, line) in lines.iter().enumerate() {
        let parsed: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Some(idx + 1),
        };
        let declared = parsed
            .get("prev_hash")
            .and_then(Value::as_str)
            .map(str::to_string);
        // Each line must point at the line before it; the first line must match the seed.
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
        // Two well-formed JSON lines where line 2 points at line 1; dropping the genesis breaks it.
        let a = json!({ "n": 1 }).to_string();
        let ha = sha256_hex(a.as_bytes());
        let b = json!({ "n": 2, "prev_hash": ha }).to_string();
        let good = format!("{a}\n{b}\n");
        assert_eq!(chain_break(&good), None);
        // Drop the genesis line: line "b" now declares a prev_hash with nothing before it → break at 1.
        assert_eq!(chain_break(&format!("{b}\n")), Some(1));
    }

    #[test]
    fn sign_receipt_produces_a_line_verify_value_accepts_and_chains() {
        let key = SigningKey::from_bytes(&[19u8; 32]);
        let genesis = sign_receipt(
            &key,
            "policy-apply-1",
            "kriya.policy.applied",
            json!({ "version": 13, "bundle_hash": "deadbeef" }),
            true,
            1000,
            None,
            None,
        );
        assert!(verify_value(&genesis).is_ok(), "a freshly signed receipt verifies");
        assert!(looks_like_receipt(&genesis));

        let line1 = serde_json::to_string(&genesis).unwrap();
        let h1 = sha256_hex(line1.as_bytes());
        let second = sign_receipt(
            &key,
            "policy-apply-2",
            "kriya.policy.stale",
            json!({}),
            false,
            2000,
            Some(Actor { agent: "kriya-console".into(), user: "system".into() }),
            Some(h1.clone()),
        );
        assert!(verify_value(&second).is_ok());
        let line2 = serde_json::to_string(&second).unwrap();

        // The chain check accepts consecutive sign_receipt output exactly like front-signed receipts.
        assert_eq!(chain_break(&format!("{line1}\n{line2}\n")), None);

        // Tamper after signing → verification fails (proves this isn't a rubber stamp).
        let mut tampered = second.clone();
        tampered["success"] = json!(true);
        assert!(verify_value(&tampered).is_err());
    }

    #[test]
    fn chain_continues_from_matches_chain_break_and_seeds_a_window() {
        // A 3-line chained log (plain JSON; the chain check only inspects prev_hash linkage).
        let l1 = json!({ "n": 1 }).to_string();
        let h1 = sha256_hex(l1.as_bytes());
        let l2 = json!({ "n": 2, "prev_hash": h1 }).to_string();
        let h2 = sha256_hex(l2.as_bytes());
        let l3 = json!({ "n": 3, "prev_hash": h2 }).to_string();
        let text = format!("{l1}\n{l2}\n{l3}\n");
        let lines: Vec<&str> = text.split('\n').filter(|l| !l.trim().is_empty()).collect();

        // The defining invariant: chain_break == chain_continues_from(None, &non_empty_lines).
        assert_eq!(chain_break(&text), None);
        assert_eq!(chain_continues_from(None, &lines), chain_break(&text));

        // A TAIL window (l2, l3) seeded from l1's hash must NOT false-positive on its first line...
        let tail = [l2.as_str(), l3.as_str()];
        assert_eq!(
            chain_continues_from(Some(&h1), &tail),
            None,
            "a correctly-seeded window is intact"
        );
        // ...whereas with no seed the tail's first line reads as a broken genesis (the bug this fixes).
        assert_eq!(
            chain_continues_from(None, &tail),
            Some(1),
            "an unseeded tail false-positives"
        );
        // A wrong seed breaks immediately at line 1.
        assert_eq!(chain_continues_from(Some("deadbeef"), &tail), Some(1));
    }

    /// EG-2/EG-3 cross-repo parity: the REAL `kriya.io.*` receipts the public runtime
    /// (`experiment1/crates/kriya`) actually signs — copied verbatim, not authored here — must verify
    /// under THIS repo's Rust verifier byte-identically, exactly like the `kriya-audit` CLI proved in
    /// the runtime's own test suite (`verified 6, failed 0, chain breaks 0`). This is the strongest
    /// parity claim available: not "the Console's own synthetic fixture round-trips," but "the actual
    /// runtime's signed bytes verify here too." Regenerate by copying
    /// `experiment1/crates/kriya/tests/fixtures/egress_ledger.jsonl` over
    /// `fixtures/runtime-egress-ledger.jsonl` whenever the runtime's fixture changes.
    #[test]
    fn runtime_egress_ledger_fixture_verifies_byte_identically() {
        let text = include_str!("../fixtures/runtime-egress-ledger.jsonl");
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 6, "the runtime fixture's line count");

        let mut io_seen = 0;
        for line in &lines {
            let v: Value = serde_json::from_str(line).expect("fixture line parses");
            assert!(verify_value(&v).is_ok(), "runtime-signed line must verify under this verifier: {line}");
            if v["action_id"].as_str().unwrap_or("").starts_with("kriya.io.") {
                io_seen += 1;
            }
        }
        assert_eq!(io_seen, 5, "five kriya.io.* receipts in the runtime fixture");
        assert_eq!(chain_break(text), None, "the runtime's chain must be intact under this verifier");
    }
}
