//! Pure counterfactual replay of the runtime's action-tier policy gate (I3 — "Policy CI").
//!
//! Hand-ported from `experiment1/crates/kriya/src/permissions.rs`'s `matches`/`Policy::check` — no
//! crate dependency exists between the two repos today (by design; the two signed-byte formats are
//! kept honest by hand via `canonical_parity`-style fixture tests, and this follows the same
//! posture rather than inventing a new cross-repo coupling for one function).
//!
//! Deliberately narrow: this replays ONLY the action-tier gate (allow / requires-approval / deny),
//! including the B11 read-only pre-empt. It does NOT replay budget exhaustion, egress-tier
//! decisions, or the detection-pack body/host heuristics (B5–B10, B12) — those need timestamps,
//! hosts, or outbound payload bytes that a bare `action_id` doesn't carry. A bare-action_id tier
//! verdict is still the load-bearing "would this have been denied" signal; callers presenting this
//! to a human should say so (see `policy_sim.rs`'s doc comment on the caller side).

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimDecision {
    Allow,
    RequiresApproval,
    Deny,
}

impl SimDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            SimDecision::Allow => "allow",
            SimDecision::RequiresApproval => "approval",
            SimDecision::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SimRule {
    action: String,
    #[serde(default)]
    allow: bool,
    #[serde(default)]
    require_approval: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct SimDetectionPolicy {
    #[serde(default)]
    read_only: Vec<String>,
}

/// The candidate policy shape being replayed — a deliberately NEW, narrow struct: not a dependency
/// on `experiment1`'s private `Rule`/`Policy`, nor on this crate's own `PolicyBundle`, whose
/// `policy` field is intentionally opaque `Value`. Unknown fields (`budget`, `egress`, `secrets`,
/// `a2a`, …) are ignored by serde's default behavior, so a real `agent-policy.yaml` or a fleet
/// `PolicyBundle.policy` parses here unmodified — the caller supplies whichever deserializer fits
/// (YAML or JSON; this struct is deserializer-agnostic).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SimPolicy {
    #[serde(default)]
    rules: Vec<SimRule>,
    #[serde(default)]
    detection: Option<SimDetectionPolicy>,
}

fn matches(pattern: &str, action_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return action_id.starts_with(prefix);
    }
    pattern == action_id
}

/// B11's OWN destructive-keyword list (`permissions.rs::is_destructive_name`) — deliberately NOT
/// this crate's `classify::is_destructive`, which carries a different keyword set for a different
/// purpose (redaction/compliance rollups) and would silently misreplay B11 if reused here.
fn is_destructive_name(action_id: &str) -> bool {
    let a = action_id.to_lowercase();
    ["delete", "remove", "destroy", "drop", "purge", "wipe"]
        .iter()
        .any(|k| a.contains(k))
}

impl SimDetectionPolicy {
    fn read_only_denies(&self, action_id: &str) -> bool {
        if !is_destructive_name(action_id) {
            return false;
        }
        self.read_only.iter().any(|pattern| {
            let pattern = if pattern.contains('*') {
                pattern.clone()
            } else {
                format!("{pattern}__*")
            };
            matches(&pattern, action_id)
        })
    }
}

/// Faithful replay of `permissions.rs::Policy::check` for one action id: the B11 read-only
/// pre-empt first (it can't be widened back open by an explicit `allow` rule in the real engine
/// either), then first-match-wins over `rules` in order, defaulting to `Deny` when nothing matches
/// — the runtime's own implicit deny-by-default. Pure: no I/O, no mutable state.
pub fn simulate_tier(policy: &SimPolicy, action_id: &str) -> SimDecision {
    if policy
        .detection
        .as_ref()
        .is_some_and(|d| d.read_only_denies(action_id))
    {
        return SimDecision::Deny;
    }
    for rule in &policy.rules {
        if matches(&rule.action, action_id) {
            if !rule.allow {
                return SimDecision::Deny;
            }
            return if rule.require_approval {
                SimDecision::RequiresApproval
            } else {
                SimDecision::Allow
            };
        }
    }
    SimDecision::Deny
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json_str: &str) -> SimPolicy {
        serde_json::from_str(json_str).unwrap()
    }

    #[test]
    fn exact_match_wins_over_nothing() {
        let p = policy(r#"{"rules":[{"action":"foo","allow":true}]}"#);
        assert_eq!(simulate_tier(&p, "foo"), SimDecision::Allow);
        assert_eq!(simulate_tier(&p, "bar"), SimDecision::Deny);
    }

    #[test]
    fn prefix_glob() {
        let p = policy(r#"{"rules":[{"action":"claude-code__mcp__github__*","allow":true}]}"#);
        assert_eq!(
            simulate_tier(&p, "claude-code__mcp__github__create_issue"),
            SimDecision::Allow
        );
        assert_eq!(
            simulate_tier(&p, "claude-code__mcp__slack__post"),
            SimDecision::Deny
        );
    }

    #[test]
    fn wildcard_matches_everything() {
        let p = policy(r#"{"rules":[{"action":"*","allow":true}]}"#);
        assert_eq!(simulate_tier(&p, "anything__at__all"), SimDecision::Allow);
    }

    #[test]
    fn require_approval_tier() {
        let p = policy(r#"{"rules":[{"action":"delete_*","allow":true,"require_approval":true}]}"#);
        assert_eq!(
            simulate_tier(&p, "delete_repo"),
            SimDecision::RequiresApproval
        );
    }

    #[test]
    fn first_match_wins_ordering() {
        let p = policy(
            r#"{"rules":[{"action":"delete_safe","allow":true},{"action":"delete_*","allow":false}]}"#,
        );
        assert_eq!(simulate_tier(&p, "delete_safe"), SimDecision::Allow);
        assert_eq!(simulate_tier(&p, "delete_other"), SimDecision::Deny);
    }

    #[test]
    fn empty_rules_default_deny() {
        let p = SimPolicy::default();
        assert_eq!(simulate_tier(&p, "anything"), SimDecision::Deny);
    }

    #[test]
    fn allow_false_denies_even_with_require_approval_set() {
        // A malformed-but-parseable rule (allow:false, require_approval:true) must still deny —
        // `allow` gates everything else, exactly like the runtime's own struct field order implies.
        let p = policy(r#"{"rules":[{"action":"foo","allow":false,"require_approval":true}]}"#);
        assert_eq!(simulate_tier(&p, "foo"), SimDecision::Deny);
    }

    #[test]
    fn b11_read_only_preempts_an_explicit_allow_rule() {
        let p = policy(
            r#"{"rules":[{"action":"*","allow":true}],"detection":{"read_only":["mcp__github"]}}"#,
        );
        // A destructive-named tool under the read-only-marked connector is denied even though the
        // explicit rule below allows everything.
        assert_eq!(
            simulate_tier(&p, "mcp__github__delete_issue"),
            SimDecision::Deny
        );
        // A non-destructive-named tool under the same connector is unaffected.
        assert_eq!(
            simulate_tier(&p, "mcp__github__create_issue"),
            SimDecision::Allow
        );
    }

    #[test]
    fn b11_ignores_non_destructive_action_names() {
        let p = policy(
            r#"{"rules":[{"action":"*","allow":true}],"detection":{"read_only":["mcp__github__*"]}}"#,
        );
        assert_eq!(
            simulate_tier(&p, "mcp__github__create_issue"),
            SimDecision::Allow
        );
    }

    #[test]
    fn malformed_policy_is_a_real_error_not_a_silent_default() {
        let result: Result<SimPolicy, _> = serde_json::from_str("{not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        // A real agent-policy.yaml (budget/egress/secrets/a2a/…) or a fleet PolicyBundle.policy
        // value must parse here unmodified.
        let p = policy(
            r#"{"rules":[{"action":"*","allow":true}],"budget":{"max_actions_per_minute":60},"on_device":true}"#,
        );
        assert_eq!(simulate_tier(&p, "anything"), SimDecision::Allow);
    }
}
