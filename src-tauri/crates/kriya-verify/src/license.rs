//! Offline license verification (R29) — the VERIFY half, moved into the shared crate (0.5) so the
//! headless `kriyad` server can gate ingest on a valid `control-plane` license without depending on
//! the Tauri app. A license is just another signed artifact: the issuer signs a small JSON payload
//! with a key whose public half is pinned here ([`ISSUER_PUBLIC_KEY_HEX`]); verification is entirely
//! offline. The dev issuer + the Tauri activation commands stay app-side.

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_value;
use crate::sig::verify_detached;

/// The issuer's **public** key (lowercase hex, 32 bytes) — the on-device trust anchor. The matching
/// private key is NOT in this binary in production; the dev/demo seed lives only in the gitignored
/// `dev-keys/issuer-dev-seed.hex` (read app-side).
pub const ISSUER_PUBLIC_KEY_HEX: &str =
    "3042180089b12d85d962884f9f2a152c0edb22e2355ec123486a0e13996949f5";

/// The signed license payload. Kept tiny on purpose; `params`-style canonicalization on the JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Who the license is issued to (org or person) — shown in the cockpit.
    pub holder: String,
    /// Tier string; `pro` unlocks the paid features.
    pub tier: String,
    /// Paid feature flags this license grants (e.g. `compliance-export`, `control-plane`).
    pub features: Vec<String>,
    /// Milliseconds since the Unix epoch when issued.
    pub issued_ms: u64,
    /// Optional hard expiry (ms since epoch). `None` = perpetual (the common enterprise case).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<u64>,
    /// Opaque license id for support/revocation bookkeeping.
    pub license_id: String,
}

/// The full license token: the payload plus the issuer's signature over its canonical bytes. (No
/// embedded public key — verification is against the pinned [`ISSUER_PUBLIC_KEY_HEX`].)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseToken {
    pub license: LicensePayload,
    /// Ed25519 signature (lowercase hex, 64 bytes) over `canonical(license)`.
    pub signature: String,
}

/// The canonical bytes signed/verified for a license payload: the JSON value with object keys
/// recursively sorted (R21), serialized compactly. This MESSAGE construction is deliberately distinct
/// from a receipt's and stays here at its call site (it is NOT the receipt canonicalization).
pub fn canonical_license_bytes(p: &LicensePayload) -> Result<Vec<u8>, String> {
    let v = serde_json::to_value(p).map_err(|e| e.to_string())?;
    serde_json::to_vec(&canonical_value(&v)).map_err(|e| e.to_string())
}

/// Verify a token against the pinned issuer key and expiry. `Ok(payload)` only when the signature is
/// valid AND the license has not expired.
pub fn verify_token(token: &LicenseToken, now_ms: u64) -> Result<LicensePayload, String> {
    let msg = canonical_license_bytes(&token.license)?;
    verify_detached(ISSUER_PUBLIC_KEY_HEX, &token.signature, &msg)
        .map_err(|_| "license signature does not match (not issued by Kriya)".to_string())?;
    if let Some(exp) = token.license.expires_ms {
        if now_ms > exp {
            return Err("license has expired".into());
        }
    }
    Ok(token.license.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Always-on guard (no dev seed needed): random/zero signatures never verify against the pinned
    /// issuer key. The dev-seed round-trip + expiry tests live app-side with `dev_issue`.
    #[test]
    fn rejects_garbage_and_unsigned() {
        let bad = LicenseToken {
            license: LicensePayload {
                holder: "Acme Regulated Co".into(),
                tier: "pro".into(),
                features: vec!["compliance-export".into()],
                issued_ms: 1_700_000_000_000,
                expires_ms: None,
                license_id: "dev-0001".into(),
            },
            signature: "00".repeat(64),
        };
        assert!(verify_token(&bad, 0).is_err());
    }

    /// Seed-independent license-byte PARITY gate (0.6): a real dev-issuer-signed token, committed as
    /// ground truth, must verify against the PINNED issuer key — so a license canonicalization/format
    /// regression fails CI even on a clone WITHOUT the gitignored dev seed (where `dev_issue`'s
    /// round-trip test skips). Mirrors how the TS `verify.test.ts` gates receipt parity via the
    /// committed `sample-audit.jsonl`. The token is perpetual (no `expires_ms`), so `now_ms` is moot.
    const DEV_LICENSE_FIXTURE: &str = include_str!("../fixtures/dev-license.json");

    #[test]
    fn committed_dev_license_verifies_against_pinned_issuer_key() {
        let token: LicenseToken =
            serde_json::from_str(DEV_LICENSE_FIXTURE).expect("fixture parses");
        assert!(
            verify_token(&token, 1_782_657_400_000).is_ok(),
            "the committed dev license must verify against the pinned issuer key — a license-byte \
             regression (canonicalization/format) would break this"
        );
    }

    #[test]
    fn tampering_the_committed_license_breaks_verification() {
        let mut token: LicenseToken = serde_json::from_str(DEV_LICENSE_FIXTURE).unwrap();
        token.license.tier = "enterprise-unlimited".into(); // forge a higher tier after signing
        assert!(
            verify_token(&token, 1_782_657_400_000).is_err(),
            "a tampered license must fail"
        );
    }
}
