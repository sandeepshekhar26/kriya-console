//! Device-side redaction (1.9): the allowlist DATA (which action ids pass through VERBATIM — the
//! *enforcement* is the sealed `kriya_verify::minimize_window`) + the operator → pseudonym HMAC.
//!
//! Structural guard: this module NEVER reads `params`, and an operator name only ever appears as an
//! IRREVERSIBLE HMAC pseudonym keyed by the device-local pepper. The full-envelope version of this
//! guarantee is the redaction-manifest CI test (1.12).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use kriya_verify::Allowlist;

type HmacSha256 = Hmac<Sha256>;

/// The pilot's default allowlist — generic governance action ids that may pass through verbatim (their
/// real name is useful on the org dashboard and carries no user data). Everything else is bucketed by
/// the sealed minimizer. Per-deployment configuration is a later (Phase 3+) concern.
pub fn default_allowlist() -> Allowlist {
    Allowlist::new([
        "create_note",
        "edit_note",
        "delete_note",
        "list_notes",
        "create_task",
        "update_task",
        "delete_task",
        "list_tasks",
        "categorize_transaction",
        "list_transactions",
    ])
}

/// A stable, IRREVERSIBLE pseudonym for an operator: `op_` + 16 hex of HMAC-SHA256(pepper, user). The
/// pepper is device-local (never transmitted), so the server can dedup an operator across envelopes but
/// can never recover the plaintext name (the pseudonym map stays OFF the aggregator).
pub fn operator_pseudonym(pepper: &[u8], user: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts a key of any length");
    mac.update(user.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("op_{}", hex::encode(&tag[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn operator_pseudonym_is_deterministic_irreversible_and_pepper_scoped() {
        let pepper = [7u8; 32];
        let p1 = operator_pseudonym(&pepper, "Jane Q. Operator");
        assert_eq!(
            p1,
            operator_pseudonym(&pepper, "Jane Q. Operator"),
            "deterministic under a fixed pepper"
        );
        assert!(
            p1.starts_with("op_") && !p1.contains("Jane"),
            "no plaintext name leaks: {p1}"
        );
        assert_ne!(
            p1,
            operator_pseudonym(&pepper, "Bob"),
            "distinct operators → distinct pseudonyms"
        );
        assert_ne!(
            p1,
            operator_pseudonym(&[9u8; 32], "Jane Q. Operator"),
            "a different pepper → a different pseudonym (not reversible without it)"
        );
    }

    #[test]
    fn redacting_a_window_leaks_no_params_or_operator_name() {
        // Device-side structural guard: drive sentinel-laden receipts through minimize_window +
        // operator_pseudonym and assert nothing sensitive survives. (Full-envelope version: 1.12.)
        let pepper = [3u8; 32];
        let receipts = vec![json!({
            "action_id": "wire_funds", "success": true,
            "params": { "amount": "SENSITIVE_AMT" },
            "actor": { "agent": "claude", "user": "Jane Q. Operator" }
        })];
        let actions = kriya_verify::minimize_window(&receipts, &default_allowlist());
        let op = operator_pseudonym(&pepper, "Jane Q. Operator");
        let combined = format!("{}|{op}", serde_json::to_string(&actions).unwrap());

        assert!(!combined.contains("SENSITIVE_AMT"), "params must not leak");
        assert!(!combined.contains("Jane"), "operator name must not leak");
        // wire_funds is not allowlisted + destructive → the "destructive" bucket, never the raw id.
        assert!(
            combined.contains("destructive") && !combined.contains("wire_funds"),
            "a non-allowlisted destructive id must bucket, not pass verbatim: {combined}"
        );
    }
}
