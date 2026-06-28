//! Action classification — one definition of "destructive/financial", shared by the redaction
//! minimizer (envelopes, 1.5) and the Console's paid fleet/compliance rollups, so the two never drift.

/// True when an action id names a destructive or money-moving operation (case-insensitive keyword
/// match). The single source of truth reused by `redact::minimize` and `paid.rs`.
pub fn is_destructive(action_id: &str) -> bool {
    let a = action_id.to_lowercase();
    [
        "delete", "remove", "destroy", "drop", "close", "transfer", "pay", "send", "wire",
    ]
    .iter()
    .any(|kw| a.contains(kw))
}
