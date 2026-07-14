//! The `PolicyBundle` schema (doc 22 §5, P3) — the signed unit an operator publishes and every device
//! pulls, verifies, and applies. "kriyad authors nothing" (doc 22 §3): a bundle is signed ONLY by the
//! customer-held **org policy key**, never by kriyad. Unlike the envelope/heartbeat/device-info
//! schemas, a bundle carries NO embedded public key — there is nothing analogous to `device_pub ==
//! public_key` to self-assert, because a self-asserted signer would be meaningless (anyone could claim
//! any key). Verification is always against a PINNED `org_policy_pub`, supplied out-of-band by the
//! caller (kriyad's `KRIYAD_ORG_POLICY_PUB`/`org-policy.pub`, or the device's pinned
//! `enrollment.json::org_policy_pub`) — see [`verify_policy_bundle`].
//!
//! Canonical signed bytes = compact JSON of the recursively key-sorted `bundle` value (R21), the same
//! technique as every other signed artifact in this crate (envelope/heartbeat/device-info/license).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::canonical_json_bytes;
use crate::sig::verify_detached;

/// Targeting for a bundle: `business_unit` of `None`/`"*"` means every device in the org; a concrete
/// string restricts to that BU. `device_pubs`, if present, further restricts to an explicit allowlist
/// (both may combine — scope filtering is SERVING, not deciding: a device always re-verifies the
/// signature itself regardless of whether kriyad's scope filter would have served it this bundle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_pubs: Option<Vec<String>>,
}

impl PolicyScope {
    /// Every device in the org — the common case.
    pub fn all() -> Self {
        PolicyScope {
            business_unit: None,
            device_pubs: None,
        }
    }

    /// Whether this scope covers a device with the given `business_unit` (`None` if the device has
    /// none configured) and `device_pub`. `business_unit` of `None` or `"*"` on the scope means "every
    /// BU"; an explicit `device_pubs` allowlist, if present, is an ADDITIONAL restriction (both must
    /// pass).
    pub fn covers(&self, device_pub: &str, business_unit: Option<&str>) -> bool {
        let bu_ok = match self.business_unit.as_deref() {
            None | Some("*") => true,
            Some(want) => business_unit == Some(want),
        };
        let device_ok = match &self.device_pubs {
            None => true,
            Some(list) => list.iter().any(|d| d == device_pub),
        };
        bu_ok && device_ok
    }
}

/// One directive in `govern[]` — drives a device's doc-21 detect→wire engine. `target` is a governable
/// agent id (`"claude-code"` | `"hermes"`); `action` is `"wire"` (govern it) or `"unwire"` (revert it).
/// Kept as plain strings (not an enum) so a future target/action value from a newer operator console
/// still round-trips through an older device without erroring (BC-4: unknown values are tolerated,
/// simply not acted on).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernDirective {
    pub target: String,
    pub action: String,
}

fn default_verbosity() -> String {
    "standard".to_string()
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The signed policy/connector/budget bundle (doc 22 §5), verbatim schema. `policy` and `budgets` are
/// carried as opaque `Value` — this crate does not interpret the runtime policy/budget format, only
/// signs and verifies the bytes; the device-side apply step (control_plane, app crate) owns turning
/// them into the existing on-disk policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub org_id: String,
    /// Monotonic — devices reject `version <= last_applied` (anti-rollback, see [`supersedes`]).
    pub version: u64,
    pub issued_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<u64>,
    pub scope: PolicyScope,
    /// The existing runtime policy format (allow/approval/deny tiers) — opaque here.
    pub policy: Value,
    /// The existing budgets format (rate caps) — opaque here.
    pub budgets: Value,
    #[serde(default)]
    pub govern: Vec<GovernDirective>,
    /// `"standard"` | `"extended"` — kept as a raw string (not an enum), like `DeviceCoverage::status`,
    /// so an unrecognized future value from a newer operator console still deserializes cleanly on an
    /// older device (BC-4) rather than hard-failing the whole bundle.
    #[serde(default = "default_verbosity")]
    pub envelope_verbosity: String,
    /// The org-wide kill switch (doc 24 §11 B16/EG-F). When `true`, a device applies a fixed,
    /// maximally-restrictive fallback policy INSTEAD of `policy`/`budgets` — an emergency halt, not
    /// a policy dial. `#[serde(default, skip_serializing_if = "is_false")]`: an absent/`false` value
    /// (the overwhelming common case) is omitted entirely from the canonical bytes, so an old bundle
    /// that never sets this hashes byte-for-byte identical to before this field existed (BC-4/BC-5).
    /// Also engages automatically when a device's applied bundle goes stale (see
    /// `control_plane::policy::check_staleness`) — "kriyad authors nothing" (doc 22 §3): kriyad never
    /// originates a kill switch either; it's operator-authored (this field) or device-detected
    /// (staleness), never server-decided.
    #[serde(default, skip_serializing_if = "is_false")]
    pub kill_switch: bool,
}

/// `{ bundle, signature }` — signature is Ed25519 over [`policy_bundle_canonical_bytes`], by the
/// customer-held org policy key. No embedded public key (see module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyBundle {
    pub bundle: PolicyBundle,
    pub signature: String,
}

/// Canonical signed bytes of a bundle = compact JSON of its recursively key-sorted value.
pub fn policy_bundle_canonical_bytes(b: &PolicyBundle) -> Vec<u8> {
    let v = serde_json::to_value(b).unwrap_or(Value::Null);
    canonical_json_bytes(&v)
}

/// Sign a `PolicyBundle` with the org policy key. The caller (the Tauri authoring command) supplies
/// `key` — this crate holds no operator secrets, mirroring [`crate::device_info::sign_device_info`]'s
/// "caller supplies the key" shape.
pub fn sign_policy_bundle(
    key: &ed25519_dalek::SigningKey,
    bundle: PolicyBundle,
) -> SignedPolicyBundle {
    use ed25519_dalek::Signer;
    let msg = policy_bundle_canonical_bytes(&bundle);
    let signature = hex::encode(key.sign(&msg).to_bytes());
    SignedPolicyBundle { bundle, signature }
}

/// Verify a parsed `SignedPolicyBundle` against a PINNED `org_policy_pub` (lowercase hex) — never a key
/// the payload itself asserts. `Ok(())` only when the Ed25519 signature over the canonical bundle bytes
/// matches. The caller is responsible for feeding this the RAW parsed value from the wire/disk (BC-5) —
/// this recomputes canonical bytes from the parsed, typed `PolicyBundle`, which is reorder-safe (the
/// same pattern as `verify_envelope`/`verify_device_info`): a verifier gets identical bytes regardless
/// of the original wire's key order or whitespace, so tampering — not incidental re-formatting — is
/// what fails this check.
pub fn verify_policy_bundle(v: &Value, org_policy_pub_hex: &str) -> Result<(), String> {
    let signed: SignedPolicyBundle =
        serde_json::from_value(v.clone()).map_err(|e| format!("not a signed policy bundle: {e}"))?;
    let msg = policy_bundle_canonical_bytes(&signed.bundle);
    verify_detached(org_policy_pub_hex, &signed.signature, &msg)
        .map_err(|_| "policy bundle signature does not match".to_string())
}

/// Anti-rollback: whether `new_version` supersedes `last_applied` (`None` = nothing applied yet, so
/// any version supersedes). Devices apply a bundle ONLY when this is true — a version equal to or
/// lower than what's already applied is a replay/rollback attempt and must be rejected.
pub fn supersedes(new_version: u64, last_applied: Option<u64>) -> bool {
    match last_applied {
        None => true,
        Some(last) => new_version > last,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn sample_bundle(version: u64) -> PolicyBundle {
        PolicyBundle {
            org_id: "acme".into(),
            version,
            issued_ms: 1_783_500_000_000,
            expires_ms: None,
            scope: PolicyScope::all(),
            policy: json!({ "rules": [{ "action": "*", "allow": true }] }),
            budgets: json!({ "max_actions_per_minute": 60 }),
            govern: vec![
                GovernDirective { target: "claude-code".into(), action: "wire".into() },
                GovernDirective { target: "hermes".into(), action: "wire".into() },
            ],
            envelope_verbosity: "standard".into(),
            kill_switch: false,
        }
    }

    #[test]
    fn round_trips_and_verifies() {
        let key = SigningKey::from_bytes(&[41u8; 32]);
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        let signed = sign_policy_bundle(&key, sample_bundle(1));
        let v = serde_json::to_value(&signed).unwrap();
        assert!(
            verify_policy_bundle(&v, &pub_hex).is_ok(),
            "an honestly-signed bundle verifies against the pinned org key"
        );

        // A different (wrong) pinned key must NOT verify — proves this isn't a no-op check.
        let other = SigningKey::from_bytes(&[42u8; 32]);
        let other_pub = hex::encode(other.verifying_key().to_bytes());
        assert!(verify_policy_bundle(&v, &other_pub).is_err());
    }

    #[test]
    fn tamper_fails() {
        let key = SigningKey::from_bytes(&[43u8; 32]);
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        let signed = sign_policy_bundle(&key, sample_bundle(5));
        let mut v = serde_json::to_value(&signed).unwrap();

        v["bundle"]["version"] = json!(999);
        assert!(
            verify_policy_bundle(&v, &pub_hex).is_err(),
            "tampering version after signing must fail"
        );

        let mut v2 = serde_json::to_value(&signed).unwrap();
        v2["bundle"]["govern"][0]["target"] = json!("evil-agent");
        assert!(
            verify_policy_bundle(&v2, &pub_hex).is_err(),
            "tampering a nested govern[] field must fail"
        );

        let mut v3 = serde_json::to_value(&signed).unwrap();
        v3["bundle"]["policy"]["rules"][0]["allow"] = json!(false);
        assert!(
            verify_policy_bundle(&v3, &pub_hex).is_err(),
            "tampering the opaque policy payload must fail"
        );
    }

    #[test]
    fn garbage_never_verifies() {
        let v = json!({ "bundle": sample_bundle(1), "signature": "00".repeat(64) });
        assert!(verify_policy_bundle(&v, &"ab".repeat(32)).is_err());
    }

    #[test]
    fn scope_covers_all_by_default_and_restricts_when_set() {
        let all = PolicyScope::all();
        assert!(all.covers("devA", Some("bu-1")));
        assert!(all.covers("devA", None));

        let bu_scoped = PolicyScope {
            business_unit: Some("enclave-7".into()),
            device_pubs: None,
        };
        assert!(bu_scoped.covers("devA", Some("enclave-7")));
        assert!(!bu_scoped.covers("devA", Some("other-bu")));
        assert!(!bu_scoped.covers("devA", None));

        let star = PolicyScope {
            business_unit: Some("*".into()),
            device_pubs: None,
        };
        assert!(star.covers("devA", Some("anything")));

        let device_scoped = PolicyScope {
            business_unit: None,
            device_pubs: Some(vec!["devA".into()]),
        };
        assert!(device_scoped.covers("devA", None));
        assert!(!device_scoped.covers("devB", None));
    }

    #[test]
    fn version_comparison_helper_is_the_anti_rollback_gate() {
        assert!(supersedes(1, None), "any version supersedes nothing applied yet");
        assert!(supersedes(2, Some(1)), "a higher version supersedes");
        assert!(!supersedes(1, Some(1)), "an equal version does NOT supersede (replay)");
        assert!(!supersedes(1, Some(2)), "a lower version does NOT supersede (rollback)");
    }

    #[test]
    fn envelope_verbosity_defaults_to_standard_when_absent() {
        // An older-shaped bundle (pre-verbosity-field) must still parse, defaulting to "standard" —
        // BC-4 additive evolution from the OLD-artifact side.
        let old_shape = json!({
            "org_id": "acme",
            "version": 1,
            "issued_ms": 1000,
            "scope": { },
            "policy": {},
            "budgets": {},
        });
        let bundle: PolicyBundle = serde_json::from_value(old_shape).unwrap();
        assert_eq!(bundle.envelope_verbosity, "standard");
        assert!(bundle.govern.is_empty());
    }

    #[test]
    fn kill_switch_defaults_to_false_and_omits_from_canonical_bytes() {
        // An older-shaped bundle (pre-kill-switch) still parses, defaulting to false.
        let old_shape = json!({
            "org_id": "acme",
            "version": 1,
            "issued_ms": 1000,
            "scope": {},
            "policy": {},
            "budgets": {},
        });
        let bundle: PolicyBundle = serde_json::from_value(old_shape).unwrap();
        assert!(!bundle.kill_switch);

        // `false` is the common case, so it must be OMITTED from the canonical bytes entirely — an
        // old and a new bundle that both leave the switch off hash IDENTICALLY (BC-5: the pinned
        // fixture hash below must never move just because this field was added).
        let bytes = policy_bundle_canonical_bytes(&sample_bundle(1));
        assert!(
            !String::from_utf8_lossy(&bytes).contains("kill_switch"),
            "kill_switch: false must not appear in the canonical bytes at all"
        );
    }

    #[test]
    fn kill_switch_true_is_present_in_canonical_bytes_and_tamper_fails() {
        let key = SigningKey::from_bytes(&[71u8; 32]);
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        let mut bundle = sample_bundle(1);
        bundle.kill_switch = true;
        let bytes = policy_bundle_canonical_bytes(&bundle);
        assert!(String::from_utf8_lossy(&bytes).contains("\"kill_switch\":true"));

        let signed = sign_policy_bundle(&key, bundle);
        let mut v = serde_json::to_value(&signed).unwrap();
        assert!(verify_policy_bundle(&v, &pub_hex).is_ok());

        // Flipping kill_switch off after signing must fail verification, same as any other field.
        v["bundle"]["kill_switch"] = json!(false);
        assert!(
            verify_policy_bundle(&v, &pub_hex).is_err(),
            "tampering kill_switch after signing must fail"
        );
    }

    /// P4 (doc 22 §9-CM) TS↔Rust parity: the committed `sample-policy-bundle.json` fixture hashes to
    /// this exact value — the SAME constant `test/policy-bundle.test.ts`'s `bundleHash()` test asserts,
    /// so a canonicalization drift on either side is caught by BOTH suites independently.
    #[test]
    fn bundle_hash_matches_the_committed_ts_parity_constant() {
        let raw = include_str!("../../../../src/sample/sample-policy-bundle.json");
        let signed: SignedPolicyBundle = serde_json::from_str(raw).unwrap();
        let hash = crate::sha256_hex(&policy_bundle_canonical_bytes(&signed.bundle));
        assert_eq!(hash, "1295bcc0ec28992b4228b85cd4ecde943fa4456a5ef252ae01d6b471e66d151f");
    }

    /// Emits the committed Rust↔TS parity fixture (`src/sample/sample-policy-bundle.json`) for the TS
    /// verifier test. Deterministic (fixed key seed). Regenerate with:
    ///   cargo test -p kriya-verify print_sample_policy_bundle -- --ignored --nocapture
    #[test]
    #[ignore = "fixture generator; run with --ignored --nocapture to (re)generate the parity fixture"]
    fn print_sample_policy_bundle() {
        let key = SigningKey::from_bytes(&[41u8; 32]);
        let signed = sign_policy_bundle(&key, sample_bundle(1));
        println!("{}", serde_json::to_string_pretty(&signed).unwrap());
        eprintln!("pinned org_policy_pub: {}", hex::encode(key.verifying_key().to_bytes()));
    }
}
