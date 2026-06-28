//! Enrollment (1.3) — the device's binding to a control-plane server, and the runtime dormancy gate.
//!
//! `~/.kriya/console/enrollment.json` names the server + authority-asserted org/BU/operator + the
//! pinned server-CA hash. In production an MDM writes it (zero-touch); in the pilot a dev `kriyad-ca`
//! script drops it (Phase 3 = the real enrollment handshake). Its presence is one of the two dormancy
//! gates; the other is the `control-plane` license flag. Pure parsing + a disk read; no network.

use std::path::PathBuf;

use serde::Deserialize;

/// The on-device enrollment record. Org/BU/operator are **authority-asserted** (MDM / dev script),
/// not free text the user types. `business_unit` is optional; every other field is required.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub server_url: String,
    pub org_id: String,
    #[serde(default)]
    pub business_unit: Option<String>,
    pub operator_id: String,
    pub server_ca_pin_sha256: String,
}

/// Where the enrollment record lives on-device (alongside the installed license).
fn enrollment_path() -> PathBuf {
    crate::audit::console_dir().join("enrollment.json")
}

/// Load + validate `~/.kriya/console/enrollment.json`. `None` when absent, malformed, or missing/empty
/// a required field — so a half-written file never half-activates the control plane.
pub fn load_enrollment() -> Option<Enrollment> {
    let text = std::fs::read_to_string(enrollment_path()).ok()?;
    parse_enrollment(&text)
}

/// Pure parse + non-empty validation, split out so the gate logic is testable without disk.
fn parse_enrollment(text: &str) -> Option<Enrollment> {
    let e: Enrollment = serde_json::from_str(text).ok()?;
    let required_present = ![
        &e.server_url,
        &e.org_id,
        &e.operator_id,
        &e.server_ca_pin_sha256,
    ]
    .into_iter()
    .any(|f| f.trim().is_empty());
    required_present.then_some(e)
}

/// The dormancy decision: the control plane is active ONLY when a valid license grants `control-plane`
/// AND a valid enrollment exists. Both gates — neither alone flips it. No network, no side effects.
pub fn control_plane_active() -> bool {
    crate::license::require_control_plane().is_ok() && load_enrollment().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enrollment_accepts_complete_and_rejects_incomplete() {
        let complete = r#"{"serverUrl":"https://kriyad.acme.internal","orgId":"acme-dod",
            "businessUnit":"enclave-7","operatorId":"op-1","serverCaPinSha256":"ab12cd"}"#;
        let e = parse_enrollment(complete).expect("complete enrollment parses");
        assert_eq!(e.org_id, "acme-dod");
        assert_eq!(e.business_unit.as_deref(), Some("enclave-7"));

        // businessUnit is optional → still valid without it.
        let no_bu =
            r#"{"serverUrl":"https://x","orgId":"o","operatorId":"op","serverCaPinSha256":"ab"}"#;
        assert!(parse_enrollment(no_bu).is_some());

        // A missing REQUIRED field fails serde deserialization → None.
        let missing = r#"{"serverUrl":"https://x","orgId":"o"}"#;
        assert!(
            parse_enrollment(missing).is_none(),
            "missing operatorId/pin → rejected"
        );

        // A present-but-empty required field → None (no half-activation).
        let empty = r#"{"serverUrl":"","orgId":"o","operatorId":"op","serverCaPinSha256":"ab"}"#;
        assert!(
            parse_enrollment(empty).is_none(),
            "empty serverUrl → rejected"
        );

        // Malformed JSON → None.
        assert!(parse_enrollment("not json").is_none());
    }
}
