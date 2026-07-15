//! Allowlist-only, drop-by-default redaction — the load-bearing privacy control (1.5).
//!
//! [`MinimizedAction`] is **sealed** (a private witness field), so the ONLY way to mint one is
//! [`minimize_window`], which reads a receipt's `action_id` + `success` and NOTHING ELSE — `params`
//! is never touched, so it cannot leak. An action id not on the allowlist collapses to a coarse type
//! bucket, so a never-before-seen (possibly sensitive) action name never passes through verbatim.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::is_destructive;

/// One minimized action line in an envelope. SEALED via `#[non_exhaustive]`: a crate OTHER than
/// kriya-verify (the device builder, the server) cannot construct one with a struct literal — the ONLY
/// way to mint one is [`minimize_window`], the drop-by-default boundary. (Deserialization on the verify
/// side still works: the derived impl lives here, where construction is allowed.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MinimizedAction {
    /// An allowlisted action id verbatim, ELSE its coarse type bucket, ELSE `"other"`. Never raw params.
    pub action: String,
    /// Verified receipts of this action in the window.
    pub count: u32,
    /// Of those, how many had `success == false`.
    pub failures: u32,
    /// Whether the action id names a destructive / money-moving operation.
    pub destructive: bool,
}

/// The set of action ids permitted to pass through VERBATIM. Everything else is bucketed.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    ids: HashSet<String>,
}

impl Allowlist {
    pub fn new(ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            ids: ids.into_iter().map(Into::into).collect(),
        }
    }
    pub fn allows(&self, action_id: &str) -> bool {
        self.ids.contains(action_id)
    }
}

/// Coarse type bucket for a non-allowlisted action id (drop-by-default). Destructive ids reuse the
/// shared keyword classification; otherwise a small create/read/update/other taxonomy. Never the raw id.
fn bucket(action_id: &str, destructive: bool) -> String {
    if destructive {
        return "destructive".into();
    }
    let a = action_id.to_lowercase();
    if a.starts_with("create") || a.starts_with("add") || a.starts_with("new") {
        "create".into()
    } else if a.starts_with("update") || a.starts_with("edit") || a.starts_with("set") {
        "update".into()
    } else if a.starts_with("list")
        || a.starts_with("get")
        || a.starts_with("read")
        || a.starts_with("view")
    {
        "read".into()
    } else {
        "other".into()
    }
}

/// The SOLE constructor of [`MinimizedAction`]. Groups `raw_receipts` by their minimized action,
/// counting occurrences and failures. Reads ONLY `action_id` + `success` from each receipt — `params`
/// is never accessed, so it cannot leak. Returns the rollup sorted by action (deterministic).
pub fn minimize_window(raw_receipts: &[Value], allow: &Allowlist) -> Vec<MinimizedAction> {
    // (count, failures, destructive) per minimized action string.
    let mut by_action: BTreeMap<String, (u32, u32, bool)> = BTreeMap::new();
    for r in raw_receipts {
        let action_id = r.get("action_id").and_then(Value::as_str).unwrap_or("");
        let success = r.get("success").and_then(Value::as_bool).unwrap_or(false);
        let destructive = is_destructive(action_id);
        let action = if allow.allows(action_id) {
            action_id.to_string()
        } else {
            bucket(action_id, destructive)
        };
        let entry = by_action.entry(action).or_insert((0, 0, destructive));
        entry.0 += 1;
        if !success {
            entry.1 += 1;
        }
        entry.2 = entry.2 || destructive; // sticky: a bucket is destructive if any contributor is
    }
    by_action
        .into_iter()
        .map(|(action, (count, failures, destructive))| MinimizedAction {
            action,
            count,
            failures,
            destructive,
        })
        .collect()
}

// ─── The pattern-echo minimizer (doc 24 §4.5/§7.5, EG-4) ──────────────────────────────────────────
//
// A destination appears in an envelope ONLY as the operator-authored policy pattern it matched
// (observed `api.eu.vendor.com` → the pattern `*.vendor.com`, a string that already exists in the
// operator-signed PolicyBundle — nothing the org didn't author leaves the device). A host matching
// NO authored pattern collapses to the fixed [`UNLISTED_PATTERN`] sentinel, never the raw host. This
// is the second, and ONLY other, sanctioned widening of the "reads action_id + success and nothing
// else" seal [`minimize_window`] enforces — sealed the identical way (`#[non_exhaustive]`, sole
// constructor [`minimize_io`]).

/// The fixed sentinel a non-matching destination collapses to — never a real host, never derived
/// from `dest_host` in any way (a truly constant string, so it can't leak anything by construction).
pub const UNLISTED_PATTERN: &str = "unlisted";

/// One destination pattern's roll-up in an envelope. SEALED via `#[non_exhaustive]`: the only way to
/// mint one is [`minimize_io`]. `pattern` is either a VERBATIM string from the caller's
/// `egress_patterns` allowlist, or exactly [`UNLISTED_PATTERN`] — never anything else, and never a
/// raw observed host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IoDestinationPattern {
    pub pattern: String,
    /// Verified `kriya.io.egress.*` receipts whose `dest_host` matched this pattern (or, for
    /// [`UNLISTED_PATTERN`], matched none of `egress_patterns`).
    pub count: u32,
    /// Of those, how many were denied (`kriya.io.egress.*.deny`).
    pub denied: u32,
}

/// Match an operator-authored **host pattern** against a concrete host. Deliberately reimplemented
/// here (this crate never depends on the runtime `kriya` crate — one-way dependency, see CLAUDE.md)
/// rather than shared: same semantics as the runtime's own `permissions::host_matches` so a pattern
/// authored in a `PolicyBundle`'s `policy.egress.rules[].host` and echoed here means the same thing
/// on both sides of the wire.
///
/// - `*` → any host
/// - `*.vendor.com` → the vendor.com domain: any subdomain and the apex
/// - `api.vendor.com` → exact match only
fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")));
    }
    pattern == host
}

/// The SOLE constructor of [`IoDestinationPattern`]. Reads ONLY `action_id` (to select
/// `kriya.io.egress.*` receipts and their `.allow`/`.deny`/`.approve` decision suffix) and
/// `params.dest_host` (to match against `egress_patterns`) from each receipt — nothing else in
/// `params` is ever touched, so `content_sha256`/`bytes_out`/every other io field cannot leak
/// through this path either. `egress_patterns` is the operator's OWN authored allowlist (the exact
/// `host` strings from the applied `PolicyBundle`'s `policy.egress.rules[]`) — the only strings this
/// function can ever echo verbatim, besides the fixed [`UNLISTED_PATTERN`] sentinel. Ingress receipts
/// are excluded (this reports egress destinations, doc 24 EG-4 — "fleet destination visibility").
/// Returns rows sorted by pattern (deterministic).
pub fn minimize_io(receipts: &[Value], egress_patterns: &[String]) -> Vec<IoDestinationPattern> {
    let mut by_pattern: BTreeMap<String, (u32, u32)> = BTreeMap::new(); // (count, denied)
    for r in receipts {
        let action_id = r.get("action_id").and_then(Value::as_str).unwrap_or("");
        if !action_id.starts_with("kriya.io.egress.") {
            continue;
        }
        let dest_host = r
            .get("params")
            .and_then(|p| p.get("dest_host"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let pattern = egress_patterns
            .iter()
            .find(|p| host_matches(p, dest_host))
            .cloned()
            .unwrap_or_else(|| UNLISTED_PATTERN.to_string());
        let denied = action_id.ends_with(".deny");
        let entry = by_pattern.entry(pattern).or_insert((0, 0));
        entry.0 += 1;
        if denied {
            entry.1 += 1;
        }
    }
    by_pattern
        .into_iter()
        .map(|(pattern, (count, denied))| IoDestinationPattern {
            pattern,
            count,
            denied,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn receipt(action_id: &str, success: bool, params: Value) -> Value {
        json!({ "action_id": action_id, "success": success, "params": params })
    }

    #[test]
    fn allowlisted_verbatim_unknown_bucketed_params_never_read() {
        let allow = Allowlist::new(["create_note", "list_notes"]);
        let receipts = vec![
            receipt("create_note", true, json!({ "body": "SENSITIVE-A" })),
            receipt("create_note", false, json!({ "body": "SENSITIVE-B" })),
            receipt("list_notes", true, json!({})),
            receipt("delete_account", true, json!({ "amount": 999999 })), // not allowlisted, destructive
            receipt("frobnicate_xyz", true, json!({ "k": "SENSITIVE-C" })), // unknown, non-destructive
        ];
        let actions = minimize_window(&receipts, &allow);

        // The load-bearing assertion: NO params content can serialize into the minimized output.
        let serialized = serde_json::to_string(&actions).unwrap();
        assert!(
            !serialized.contains("SENSITIVE") && !serialized.contains("999999"),
            "params must never appear in a MinimizedAction: {serialized}"
        );
        let by: std::collections::HashMap<_, _> =
            actions.iter().map(|a| (a.action.as_str(), a)).collect();
        assert_eq!(by["create_note"].count, 2, "allowlisted id aggregates");
        assert_eq!(by["create_note"].failures, 1);
        assert!(
            by.contains_key("list_notes"),
            "allowlisted id passes verbatim"
        );
        assert!(
            !by.contains_key("delete_account"),
            "a non-allowlisted id must NOT pass through verbatim"
        );
        assert!(
            by.contains_key("destructive"),
            "delete_* → destructive bucket"
        );
        assert!(by["destructive"].destructive);
        assert!(
            by.contains_key("other"),
            "unknown non-destructive id → other bucket"
        );
    }

    // ─── minimize_io (doc 24 §4.5/§7.5, EG-4) ──────────────────────────────────────────────────────

    fn io_receipt(action_id: &str, dest_host: &str) -> Value {
        json!({
            "action_id": action_id,
            "success": !action_id.ends_with(".deny"),
            "params": {
                "dest_host": dest_host,
                "content_sha256": "SENSITIVE-HASH-should-never-leak",
                "bytes_out": 4300,
            },
        })
    }

    /// The load-bearing sentinel test: a host matching NO authored pattern must NEVER appear
    /// verbatim anywhere in the output — only the fixed [`UNLISTED_PATTERN`] string.
    #[test]
    fn a_non_matching_host_collapses_to_the_unlisted_sentinel_never_the_raw_host() {
        let patterns = vec!["*.vendor.com".to_string()];
        let receipts = vec![io_receipt(
            "kriya.io.egress.http.allow",
            "SENSITIVE-TENANT.internal.example",
        )];
        let out = minimize_io(&receipts, &patterns);

        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains("SENSITIVE") && !serialized.contains("internal.example"),
            "no raw host or params content may ever appear: {serialized}"
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, UNLISTED_PATTERN);
        assert_eq!(out[0].count, 1);
    }

    /// Only bundle-authored pattern strings ever survive for a MATCHED host — the observed host
    /// itself never appears, only the operator's own pattern.
    #[test]
    fn a_matching_host_echoes_the_authored_pattern_verbatim_never_the_observed_host() {
        let patterns = vec!["*.vendor.com".to_string(), "api.partner.com".to_string()];
        let receipts = vec![
            io_receipt("kriya.io.egress.http.allow", "eu.vendor.com"),
            io_receipt("kriya.io.egress.mcp.allow", "us.vendor.com"),
            io_receipt("kriya.io.egress.http.deny", "api.partner.com"),
        ];
        let out = minimize_io(&receipts, &patterns);

        let serialized = serde_json::to_string(&out).unwrap();
        assert!(!serialized.contains("eu.vendor.com"), "observed host must never leak");
        assert!(!serialized.contains("us.vendor.com"), "observed host must never leak");

        let by: std::collections::HashMap<_, _> = out.iter().map(|p| (p.pattern.as_str(), p)).collect();
        assert_eq!(by["*.vendor.com"].count, 2, "both vendor.com subdomains aggregate under the pattern");
        assert_eq!(by["*.vendor.com"].denied, 0);
        assert_eq!(by["api.partner.com"].count, 1);
        assert_eq!(by["api.partner.com"].denied, 1);
    }

    #[test]
    fn ingress_receipts_and_non_egress_params_are_excluded() {
        let patterns = vec!["*.vendor.com".to_string()];
        let receipts = vec![
            io_receipt("kriya.io.ingress.http.allow", "eu.vendor.com"),
            receipt("create_note", true, json!({ "body": "irrelevant" })),
        ];
        let out = minimize_io(&receipts, &patterns);
        assert!(out.is_empty(), "ingress + non-io receipts contribute nothing to the destination view");
    }

    #[test]
    fn no_egress_patterns_configured_means_every_host_is_unlisted() {
        let receipts = vec![io_receipt("kriya.io.egress.http.allow", "anything.example")];
        let out = minimize_io(&receipts, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern, UNLISTED_PATTERN);
    }

    #[test]
    fn empty_input_produces_no_rows() {
        assert!(minimize_io(&[], &["*.vendor.com".to_string()]).is_empty());
    }

    #[test]
    fn host_matching_mirrors_the_runtime_semantics() {
        assert!(host_matches("*", "anything.example"));
        assert!(host_matches("*.vendor.com", "vendor.com"), "apex matches too");
        assert!(host_matches("*.vendor.com", "a.b.vendor.com"), "nested subdomain matches");
        assert!(!host_matches("*.vendor.com", "notvendor.com"), "no accidental suffix match");
        assert!(!host_matches("api.vendor.com", "www.vendor.com"), "exact pattern is exact");
        assert!(!host_matches("*.", "vendor.com"), "malformed bare '*.' matches nothing");
    }
}
