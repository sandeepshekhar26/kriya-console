//! Offline Ed25519 license verification (R29 / D-018) — the paid-tier gate, in compiled Rust.
//!
//! A license is just another signed artifact (same primitive as the audit receipts): the issuer
//! signs a small JSON payload with a private key whose **public half ships embedded in this binary**
//! ([`ISSUER_PUBLIC_KEY_HEX`]). The Console verifies the signature **entirely offline** — no runtime
//! server, no phone-home, no account — which is exactly what the regulated, on-device thesis demands.
//! The free tier needs no license; only the paid features ([`crate::paid`]) call [`require_pro`].
//!
//! ## What is real vs. deferred (the "scaffold" boundary, kickoff-honest)
//! The **verify path is real and shipped**. What is deliberately deferred until a buyer exists is the
//! **issuer**: there is no checkout, no customer DB, no key-management service. For development and
//! the demo, a dev keypair lets us mint a working token (`issue-license` dev binary, gated on a
//! **gitignored** seed file under `dev-keys/`). Productionizing = generate a real issuer key whose
//! private half NEVER enters the repo, replace [`ISSUER_PUBLIC_KEY_HEX`], and wire checkout → a tiny
//! offline signer. DRM isn't unbreakable and that's fine (D-018): consumers crack, enterprises buy
//! the relationship (support, updates, key custody, compliance).

use std::path::PathBuf;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::receipts::canonical_value;

/// The issuer's **public** key (lowercase hex, 32 bytes) — the on-device trust anchor. The matching
/// private key is NOT in this binary in production; the dev/demo private seed lives only in the
/// gitignored `dev-keys/issuer-dev-seed.hex`.
pub const ISSUER_PUBLIC_KEY_HEX: &str =
    "3042180089b12d85d962884f9f2a152c0edb22e2355ec123486a0e13996949f5";

/// The signed license payload. Field order is load-bearing for the signature (declaration order,
/// `params`-style canonicalization on the JSON form). Kept tiny on purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Who the license is issued to (org or person) — shown in the cockpit.
    pub holder: String,
    /// Tier string; `pro` unlocks the paid features. (Room for future tiers without a format change.)
    pub tier: String,
    /// Paid feature flags this license grants (e.g. `compliance-export`, `fleet-correlation`).
    pub features: Vec<String>,
    /// Milliseconds since the Unix epoch when issued.
    pub issued_ms: u64,
    /// Optional hard expiry (ms since epoch). `None` = perpetual (the common enterprise case).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<u64>,
    /// Opaque license id for support/revocation bookkeeping.
    pub license_id: String,
}

/// The full license token as activated: the payload plus the issuer's signature over its canonical
/// bytes. (No embedded public key — verification is against the pinned [`ISSUER_PUBLIC_KEY_HEX`], so
/// a token can't smuggle in its own trust anchor.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseToken {
    pub license: LicensePayload,
    /// Ed25519 signature (lowercase hex, 64 bytes) over `canonical(license)`.
    pub signature: String,
}

/// The status the UI renders + the gate the paid commands consult.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseStatus {
    /// `free` or `pro`.
    pub tier: String,
    /// Whether an installed license is present AND valid (signature + not expired).
    pub valid: bool,
    pub holder: Option<String>,
    pub features: Vec<String>,
    pub expires_ms: Option<u64>,
    pub license_id: Option<String>,
    /// Why the tier is `free` when a token is installed but rejected (bad signature / expired).
    pub reason: Option<String>,
}

impl LicenseStatus {
    fn free(reason: Option<String>) -> Self {
        Self {
            tier: "free".into(),
            valid: false,
            holder: None,
            features: Vec::new(),
            expires_ms: None,
            license_id: None,
            reason,
        }
    }
}

/// The canonical bytes signed/verified for a license payload: the JSON value with object keys
/// recursively sorted (same rule as receipts, R21), serialized compactly. Independent of field
/// declaration order so issuer and verifier always agree.
fn canonical_license_bytes(p: &LicensePayload) -> Result<Vec<u8>, String> {
    let v = serde_json::to_value(p).map_err(|e| e.to_string())?;
    serde_json::to_vec(&canonical_value(&v)).map_err(|e| e.to_string())
}

/// Verify a token against the pinned issuer key and expiry. `Ok(payload)` only when the signature is
/// valid AND the license has not expired.
pub fn verify_token(token: &LicenseToken, now_ms: u64) -> Result<LicensePayload, String> {
    let pub_bytes: [u8; 32] = hex::decode(ISSUER_PUBLIC_KEY_HEX)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("embedded issuer public key is malformed")?;
    let sig_bytes: [u8; 64] = hex::decode(&token.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("signature must be 64 bytes of hex")?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| format!("bad issuer key: {e}"))?;
    let msg = canonical_license_bytes(&token.license)?;
    vk.verify(&msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| "license signature does not match (not issued by Kriya)".to_string())?;
    if let Some(exp) = token.license.expires_ms {
        if now_ms > exp {
            return Err("license has expired".into());
        }
    }
    Ok(token.license.clone())
}

/// Where an activated license is persisted on-device.
fn license_path() -> PathBuf {
    crate::audit::console_dir().join("license.json")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Read + verify the installed license, returning the live status. Free (with a reason) when no
/// license is installed or the installed one fails verification.
pub fn current_status() -> LicenseStatus {
    let path = license_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return LicenseStatus::free(None), // no license installed = the free tier
    };
    let token: LicenseToken = match serde_json::from_str(&text) {
        Ok(t) => t,
        Err(e) => return LicenseStatus::free(Some(format!("installed license is malformed: {e}"))),
    };
    match verify_token(&token, now_ms()) {
        Ok(p) => LicenseStatus {
            tier: if p.tier.is_empty() {
                "pro".into()
            } else {
                p.tier.clone()
            },
            valid: true,
            holder: Some(p.holder),
            features: p.features,
            expires_ms: p.expires_ms,
            license_id: Some(p.license_id),
            reason: None,
        },
        Err(reason) => LicenseStatus::free(Some(reason)),
    }
}

/// The gate the paid commands call. `Ok(())` only on a valid `pro` license.
pub fn require_pro() -> Result<(), String> {
    let s = current_status();
    if s.valid && s.tier == "pro" {
        Ok(())
    } else {
        Err(s
            .reason
            .unwrap_or_else(|| "this is a paid feature — activate a Kriya Console license".into()))
    }
}

// ── Tauri commands ───────────────────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn license_status() -> LicenseStatus {
    current_status()
}

/// Validate a pasted license token and, if valid, persist it on-device. Returns the resulting status
/// (so a bad token surfaces its reason without changing the installed state).
#[tauri::command]
pub fn install_license(token: String) -> Result<LicenseStatus, String> {
    let parsed: LicenseToken = serde_json::from_str(token.trim())
        .map_err(|e| format!("not a valid license token: {e}"))?;
    // Verify BEFORE persisting — never store a token we'd reject.
    verify_token(&parsed, now_ms())?;
    let path = license_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let pretty = serde_json::to_string_pretty(&parsed).map_err(|e| e.to_string())?;
    std::fs::write(&path, pretty).map_err(|e| format!("writing license: {e}"))?;
    Ok(current_status())
}

/// Remove the installed license (return to the free tier).
#[tauri::command]
pub fn remove_license() -> LicenseStatus {
    let _ = std::fs::remove_file(license_path());
    current_status()
}

// ── Dev issuer (NOT shipped logic — gated on the gitignored dev seed) ─────────────────────────────

/// Read the dev issuer seed from the gitignored `dev-keys/issuer-dev-seed.hex`, if present. Returns
/// `None` in any build/clone without the dev key (so CI and a shipped app simply can't mint).
pub fn dev_issuer_seed() -> Option<[u8; 32]> {
    // The dev seed lives in the repo-root `dev-keys/` (gitignored); CARGO_MANIFEST_DIR is `src-tauri/`.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("dev-keys")
        .join("issuer-dev-seed.hex");
    let hex_str = std::fs::read_to_string(path).ok()?;
    hex::decode(hex_str.trim()).ok()?.try_into().ok()
}

/// Mint a signed license with the dev issuer seed — DEV/DEMO ONLY (the `issue-license` binary + the
/// round-trip test). Production issuance is the deferred checkout → offline-signer path; this exists
/// solely so the verify path can be exercised end-to-end on a dev machine.
pub fn dev_issue(payload: LicensePayload) -> Result<LicenseToken, String> {
    use ed25519_dalek::{Signer, SigningKey};
    let seed =
        dev_issuer_seed().ok_or("dev issuer seed not present (dev-keys/issuer-dev-seed.hex)")?;
    let key = SigningKey::from_bytes(&seed);
    // Sanity: the dev seed must match the embedded public anchor, else issued tokens won't verify.
    let derived = hex::encode(key.verifying_key().to_bytes());
    if derived != ISSUER_PUBLIC_KEY_HEX {
        return Err(format!(
            "dev seed does not match embedded issuer key ({derived} != {ISSUER_PUBLIC_KEY_HEX})"
        ));
    }
    let msg = canonical_license_bytes(&payload)?;
    let signature = hex::encode(key.sign(&msg).to_bytes());
    Ok(LicenseToken {
        license: payload,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> LicensePayload {
        LicensePayload {
            holder: "Acme Regulated Co".into(),
            tier: "pro".into(),
            features: vec!["compliance-export".into(), "fleet-correlation".into()],
            issued_ms: 1_700_000_000_000,
            expires_ms: None,
            license_id: "dev-0001".into(),
        }
    }

    #[test]
    fn rejects_garbage_and_unsigned() {
        // Always-on guard (no dev seed needed): random bytes / wrong signature never verify.
        let bad = LicenseToken {
            license: sample_payload(),
            signature: "00".repeat(64),
        };
        assert!(verify_token(&bad, 0).is_err());
    }

    #[test]
    fn dev_issued_license_round_trips() {
        // Only runs where the dev seed is present (this machine / the private repo with dev-keys/).
        let Some(_) = dev_issuer_seed() else {
            eprintln!("skipping: no dev issuer seed present");
            return;
        };
        let token = dev_issue(sample_payload()).expect("mint");
        let ok = verify_token(&token, 1_700_000_100_000);
        assert!(ok.is_ok(), "freshly minted license must verify: {ok:?}");

        // Tamper: flip the tier after signing → must fail.
        let mut tampered = token.clone();
        tampered.license.tier = "enterprise-unlimited".into();
        assert!(verify_token(&tampered, 1_700_000_100_000).is_err());
    }

    #[test]
    fn expired_license_is_rejected() {
        let Some(_) = dev_issuer_seed() else { return };
        let mut p = sample_payload();
        p.expires_ms = Some(1_000);
        let token = dev_issue(p).unwrap();
        assert!(verify_token(&token, 2_000).is_err(), "expired must fail");
        assert!(verify_token(&token, 500).is_ok(), "pre-expiry must pass");
    }
}
