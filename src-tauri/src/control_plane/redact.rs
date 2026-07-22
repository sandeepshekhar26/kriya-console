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

/// The pilot's default (`"standard"`) allowlist — generic governance action ids that may pass through
/// verbatim (their real name is useful on the org dashboard and carries no user data). Everything else
/// is bucketed by the sealed minimizer.
pub fn default_allowlist() -> Allowlist {
    Allowlist::new(STANDARD_IDS)
}

const STANDARD_IDS: [&str; 36] = [
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
    // P4 (doc 22 §9-CM): the device's OWN policy-lifecycle markers (P3) — governance metadata, not
    // app data, so these are allowlisted verbatim at EVERY verbosity, never bucketed to "other". This
    // is what lets the cockpit's drill-in reconstruct "policy history" from `actions[]` counts at all;
    // without this they'd be indistinguishable from any other non-prefixed action id.
    "kriya.policy.applied",
    "kriya.policy.stale",
    // EG-3 (doc 24 §4.5): the 24 `kriya.io.<direction>.<kind>.<decision>` ids — the SAME governance-
    // metadata precedent as `kriya.policy.*` above. Allowlisted verbatim at EVERY verbosity because the
    // structural seal already does the real work: `minimize_window` (kriya-verify) reads ONLY
    // `action_id` + `success`, so `params` — dest_host, bytes, content_sha256, everything doc 24 calls
    // high-fidelity — is UNREACHABLE by construction, at any verbosity, with zero redaction code here.
    // Allowlisting the id only lets the ENVELOPE say "5 egress-allow events happened", never what they
    // were. An id under `kriya.io.` NOT in this exact closed set (a future/malformed facet, or drift
    // like "mcp-connector") is not added here — it falls through to the generic buckets in
    // `kriya_verify::redact::bucket`, degrading safely rather than leaking (doc 24 §4.2 rule 5 / §6-H6).
    "kriya.io.egress.mcp.allow",
    "kriya.io.egress.mcp.deny",
    "kriya.io.egress.mcp.approve",
    "kriya.io.egress.http.allow",
    "kriya.io.egress.http.deny",
    "kriya.io.egress.http.approve",
    "kriya.io.egress.model.allow",
    "kriya.io.egress.model.deny",
    "kriya.io.egress.model.approve",
    "kriya.io.egress.file.allow",
    "kriya.io.egress.file.deny",
    "kriya.io.egress.file.approve",
    "kriya.io.ingress.mcp.allow",
    "kriya.io.ingress.mcp.deny",
    "kriya.io.ingress.mcp.approve",
    "kriya.io.ingress.http.allow",
    "kriya.io.ingress.http.deny",
    "kriya.io.ingress.http.approve",
    "kriya.io.ingress.model.allow",
    "kriya.io.ingress.model.deny",
    "kriya.io.ingress.model.approve",
    "kriya.io.ingress.file.allow",
    "kriya.io.ingress.file.deny",
    "kriya.io.ingress.file.approve",
];

/// `"extended"` verbosity (doc 22 §2/§5's `envelope_verbosity` dial) — a WIDER allowlist an operator
/// opts into via a signed `PolicyBundle`: more action ids pass through verbatim instead of collapsing
/// to a coarse bucket. Still allowlist-only and drop-by-default (never reads `params`; the redaction
/// mechanism is unchanged) — "extended" only widens WHICH action ids are named, never what's disclosed
/// about any single action.
fn extended_allowlist() -> Allowlist {
    Allowlist::new(STANDARD_IDS.into_iter().chain([
        "read_note",
        "get_task",
        "read_transaction",
        "export_report",
        "approve_request",
    ]))
}

/// Resolve the allowlist for the currently-applied `envelope_verbosity` (`"standard"` | `"extended"`,
/// doc 22 §5). Any other/unrecognized value falls back to `"standard"` (BC-4: an unknown future
/// verbosity value from a newer bundle degrades to the narrower, safer default rather than erroring).
pub fn allowlist_for(verbosity: &str) -> Allowlist {
    match verbosity {
        "extended" => extended_allowlist(),
        _ => default_allowlist(),
    }
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
    fn allowlist_for_widens_under_extended_and_falls_back_to_standard() {
        let standard = allowlist_for("standard");
        let extended = allowlist_for("extended");
        let unknown = allowlist_for("some-future-value");

        assert!(standard.allows("create_note"));
        assert!(!standard.allows("read_note"), "read_note is extended-only");

        assert!(
            extended.allows("create_note"),
            "extended is a superset of standard"
        );
        assert!(extended.allows("read_note"));

        assert!(
            unknown.allows("create_note") && !unknown.allows("read_note"),
            "an unrecognized verbosity value degrades to standard, never errors"
        );
    }

    /// The closed set of 24 `kriya.io.<direction>.<kind>.<decision>` ids (doc 24 §4.2 rule 5).
    const KRIYA_IO_IDS: [&str; 24] = [
        "kriya.io.egress.mcp.allow",
        "kriya.io.egress.mcp.deny",
        "kriya.io.egress.mcp.approve",
        "kriya.io.egress.http.allow",
        "kriya.io.egress.http.deny",
        "kriya.io.egress.http.approve",
        "kriya.io.egress.model.allow",
        "kriya.io.egress.model.deny",
        "kriya.io.egress.model.approve",
        "kriya.io.egress.file.allow",
        "kriya.io.egress.file.deny",
        "kriya.io.egress.file.approve",
        "kriya.io.ingress.mcp.allow",
        "kriya.io.ingress.mcp.deny",
        "kriya.io.ingress.mcp.approve",
        "kriya.io.ingress.http.allow",
        "kriya.io.ingress.http.deny",
        "kriya.io.ingress.http.approve",
        "kriya.io.ingress.model.allow",
        "kriya.io.ingress.model.deny",
        "kriya.io.ingress.model.approve",
        "kriya.io.ingress.file.allow",
        "kriya.io.ingress.file.deny",
        "kriya.io.ingress.file.approve",
    ];

    #[test]
    fn all_24_kriya_io_ids_are_allowlisted_at_every_verbosity() {
        for verbosity in ["standard", "extended", "some-future-value"] {
            let allow = allowlist_for(verbosity);
            for id in KRIYA_IO_IDS {
                assert!(
                    allow.allows(id),
                    "verbosity={verbosity} must allowlist {id}"
                );
            }
        }
        assert_eq!(
            KRIYA_IO_IDS.len(),
            24,
            "the closed 2x4x3 facet set (doc 24 §4.2 rule 5)"
        );
    }

    #[test]
    fn an_off_vocabulary_kriya_io_id_is_not_allowlisted() {
        // A malformed/future/drifted id (e.g. a fifth dest_kind) must NOT be added here — it falls
        // through to the generic buckets in kriya_verify::redact::bucket, degrading safely instead of
        // being treated as trusted governance metadata (doc 24 §6-H6).
        let allow = allowlist_for("standard");
        assert!(!allow.allows("kriya.io.egress.mcp-connector.allow"));
        assert!(!allow.allows("kriya.io.egress.mcp.allowed")); // wrong decision facet
        assert!(!allow.allows("kriya.io.something.else"));
    }

    #[test]
    fn policy_lifecycle_markers_are_allowlisted_at_every_verbosity() {
        // P4: the drill-in's "policy history" reconstructs from actions[] counts — these markers must
        // pass through verbatim (never bucketed to "other") at BOTH verbosities, since they're
        // governance metadata, not app data an operator would want to dial down.
        for verbosity in ["standard", "extended", "anything-unrecognized"] {
            let allow = allowlist_for(verbosity);
            assert!(
                allow.allows("kriya.policy.applied"),
                "verbosity={verbosity}"
            );
            assert!(allow.allows("kriya.policy.stale"), "verbosity={verbosity}");
        }
    }

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

    /// S3 hostile fixture (device side): run correlation rides `params.kriya.corr`, which the sealed
    /// `minimize_window` never reads — so a secret planted in `run_id` cannot reach an envelope at
    /// EITHER verbosity. The default posture for run correlation is therefore "nothing leaves",
    /// structurally, with zero allowlist change (design law 2 / doc 24 §4.5).
    #[test]
    fn a_secret_in_run_correlation_never_reaches_an_envelope_at_any_verbosity() {
        let receipts = vec![json!({
            "action_id": "create_note", "success": true,
            "params": {
                "title": "hi",
                "kriya.corr": { "run_id": "SECRET-RUN", "agent_id": "SECRET-AGENT" }
            },
            "actor": { "agent": "claude-code", "user": "Jane Q. Operator" }
        })];
        for verbosity in ["standard", "extended", "some-future-value"] {
            let actions = kriya_verify::minimize_window(&receipts, &allowlist_for(verbosity));
            let serialized = serde_json::to_string(&actions).unwrap();
            assert!(
                !serialized.contains("SECRET"),
                "verbosity={verbosity}: run correlation must not leak: {serialized}"
            );
            assert!(
                !serialized.contains("kriya.corr"),
                "verbosity={verbosity}: reserved key must not surface"
            );
        }
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
