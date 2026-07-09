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
    /// The enterprise-assigned MDM asset tag (doc 22 §7's `device_label` — P1). Additive + optional
    /// (`#[serde(default)]`) so an `enrollment.json` written by a pre-P1 MDM tool still parses
    /// unchanged. This is deliberately the ONLY on-device source of `device_label` — never the OS
    /// hostname (doc 22 §7's exclusion table).
    #[serde(default)]
    pub device_label: Option<String>,
    /// The pinned **org policy public key** (P3, doc 22 §3/§5) — lowercase hex, the device's trust
    /// anchor for verifying a `PolicyBundle` before applying it. Additive + optional
    /// (`#[serde(default)]`): a pre-P3 `enrollment.json` (or one an MDM simply never set this on) still
    /// parses unchanged, and its ABSENCE is the downlink's own dormancy gate — see
    /// [`Enrollment::org_policy_pub_hex`] and BC-4 in doc 22 §8. In production an MDM writes this
    /// alongside the rest of enrollment (mirrors `device_label`'s provisioning story); the dev
    /// `kriyd-ca` stub sets it from the operator's freshly-generated `org-policy.pub`.
    #[serde(default)]
    pub org_policy_pub: Option<String>,
}

impl Enrollment {
    /// The device's pinned org-key trust anchor, if the downlink is enabled for this device at all.
    /// `None` ⇒ policy downlink is OFF (BC-4: an enrollment with no org key configured behaves
    /// EXACTLY as a pre-P3 device — it simply never calls `GET /v1/policy`).
    pub fn org_policy_pub_hex(&self) -> Option<&str> {
        self.org_policy_pub.as_deref().filter(|s| !s.trim().is_empty())
    }
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

    #[test]
    fn org_policy_pub_is_optional_and_absence_is_the_downlink_off_switch() {
        // A pre-P3 enrollment.json (no org_policy_pub at all) must still parse — BC-4.
        let pre_p3 = r#"{"serverUrl":"https://x","orgId":"o","operatorId":"op","serverCaPinSha256":"ab"}"#;
        let e = parse_enrollment(pre_p3).expect("pre-P3 enrollment still parses");
        assert_eq!(e.org_policy_pub_hex(), None, "no org key configured ⇒ downlink off");

        // An empty-string org_policy_pub is likewise treated as "not configured" (never a half-pin).
        let blank = r#"{"serverUrl":"https://x","orgId":"o","operatorId":"op","serverCaPinSha256":"ab",
            "orgPolicyPub":"  "}"#;
        assert_eq!(parse_enrollment(blank).unwrap().org_policy_pub_hex(), None);

        // A real pinned key is exposed verbatim.
        let with_key = r#"{"serverUrl":"https://x","orgId":"o","operatorId":"op","serverCaPinSha256":"ab",
            "orgPolicyPub":"deadbeef"}"#;
        assert_eq!(
            parse_enrollment(with_key).unwrap().org_policy_pub_hex(),
            Some("deadbeef")
        );
    }
}
