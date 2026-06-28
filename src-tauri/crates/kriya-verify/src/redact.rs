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
}
