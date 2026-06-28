//! The `AttestationEnvelope` schema (1.5) — the signed, minimized unit that LEAVES the device, and its
//! verification (1.6). The device-side BUILDER (assemble + sign) lives in `control_plane::envelope`
//! (1.10); here we define the shape + how anyone (Console, kriyad, auditor) RE-verifies it.
//!
//! Canonical signed bytes = compact JSON of the **recursively key-sorted** envelope value (R21) — the
//! whole envelope is canonical-sorted, so field declaration order is irrelevant and the TS re-derivation
//! (1.7) just sorts keys. `non_egress`'s `attested` is derived (`attestation_count > 0`); `counts` has no
//! approvals/denials (those were policy, dropped with `MinimizedAction.decision` — Open decision 5).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_json_bytes, sha256_hex};
use crate::redact::MinimizedAction;
use crate::sig::verify_detached;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    pub schema: String,
    /// The device evidence key (stable fleet identity); equals the signing `public_key`.
    pub device_pub: String,
    pub org_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub business_unit: Option<String>,
    /// Operator rollup — PSEUDONYMS only (HMAC), never a plaintext name.
    pub operators: Vec<OperatorRollup>,
    /// Monotonic per device; gaps ⇒ a missing window.
    pub seq: u64,
    /// `sha256` of the previous signed-envelope's canonical bytes; absent on genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_envelope_hash: Option<String>,
    pub window: Window,
    /// Rollup of the underlying receipt-signer fingerprints covered.
    pub signers: Vec<SignerRollup>,
    pub actions: Vec<MinimizedAction>,
    pub counts: Counts,
    pub integrity: Integrity,
    pub non_egress: NonEgress,
    pub compiler: CompilerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRollup {
    #[serde(rename = "ref")]
    pub op_ref: String,
    pub actions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    pub from_ms: u64,
    pub to_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerRollup {
    pub fingerprint: String,
    pub receipts: u32,
    pub verified: u32,
}

/// Window aggregates derived from receipts only (no policy). `failed` = receipts whose signature did
/// NOT verify (a tamper signal carried upward); `verified + failed == receipts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counts {
    pub receipts: u32,
    pub verified: u32,
    pub failed: u32,
    pub destructive: u32,
    pub attestations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    /// RFC-6962 Merkle root over the covered receipt LINES (total order: source↑ then line-index↑).
    pub merkle_root: String,
    /// AND of every covered source's windowed `chain_continues_from` check.
    pub chain_intact: bool,
    /// `source@line` for any source whose chain broke (forensics). Empty when intact.
    #[serde(default)]
    pub broken_sources: Vec<String>,
}

/// Device-ASSERTED non-egress summary over merkle-committed-but-withheld attestations. `attested` is
/// DERIVED as `attestation_count > 0` (never hard-coded). Not trustlessly verifiable until the P3
/// Merkle-membership spot-audit (the auditor CLI deliberately never checks `proof_digest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonEgress {
    pub attested: bool,
    pub attestation_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    pub version: String,
    pub produced_ms: u64,
}

/// `{ envelope, public_key, signature }` — the signature is Ed25519 over [`envelope_canonical_bytes`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub envelope: AttestationEnvelope,
    pub public_key: String,
    pub signature: String,
}

/// Canonical signed bytes of an envelope = compact JSON of its recursively key-sorted value.
pub fn envelope_canonical_bytes(env: &AttestationEnvelope) -> Vec<u8> {
    let v = serde_json::to_value(env).unwrap_or(Value::Null);
    canonical_json_bytes(&v)
}

/// Verify a parsed `SignedEnvelope`: the Ed25519 signature over the canonical envelope bytes (against
/// the envelope's own `device_pub`, which must equal `public_key`), plus internal count sanity. The
/// anti-forgery guarantee — a stolen transport cert can't forge this (it lacks the evidence key).
pub fn verify_envelope(v: &Value) -> Result<(), String> {
    let signed: SignedEnvelope =
        serde_json::from_value(v.clone()).map_err(|e| format!("not a signed envelope: {e}"))?;
    if signed.envelope.device_pub != signed.public_key {
        return Err("device_pub does not match the signing public_key".into());
    }
    let msg = envelope_canonical_bytes(&signed.envelope);
    verify_detached(&signed.public_key, &signed.signature, &msg)
        .map_err(|_| "envelope signature does not match".to_string())?;
    sanity_counts(&signed.envelope)
}

/// Cheap internal coherence checks (NOT a recomputation — the device asserts, the server sanity-checks).
fn sanity_counts(env: &AttestationEnvelope) -> Result<(), String> {
    let c = &env.counts;
    if c.verified + c.failed != c.receipts {
        return Err("counts: verified + failed must equal receipts".into());
    }
    let action_total: u32 = env.actions.iter().map(|a| a.count).sum();
    if action_total + c.attestations > c.verified {
        return Err("counts: actions + attestations exceed verified receipts".into());
    }
    let action_failures: u32 = env.actions.iter().map(|a| a.failures).sum();
    if action_failures > action_total {
        return Err("counts: action failures exceed action count".into());
    }
    if env.non_egress.attested != (env.non_egress.attestation_count > 0) {
        return Err("non_egress.attested must equal (attestation_count > 0)".into());
    }
    Ok(())
}

/// Chain-continuity over an ORDERED slice of signed-envelope values (by `seq`): each non-genesis
/// envelope's `prev_envelope_hash` must equal the `sha256` of the previous signed envelope's canonical
/// bytes. Returns the 1-based index of the first break (deletion / reorder / forgery), or `None`.
pub fn envelope_chain_break(lines: &[Value]) -> Option<usize> {
    let mut prev_hash: Option<String> = None;
    for (idx, v) in lines.iter().enumerate() {
        let declared = v
            .get("envelope")
            .and_then(|e| e.get("prev_envelope_hash"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if declared != prev_hash {
            return Some(idx + 1);
        }
        prev_hash = Some(sha256_hex(&canonical_json_bytes(v)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::{minimize_window, Allowlist};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn sign_envelope(env: AttestationEnvelope, key: &SigningKey) -> Value {
        let msg = envelope_canonical_bytes(&env);
        let signature = hex::encode(key.sign(&msg).to_bytes());
        let public_key = hex::encode(key.verifying_key().to_bytes());
        serde_json::to_value(SignedEnvelope {
            envelope: env,
            public_key,
            signature,
        })
        .unwrap()
    }

    fn sample_envelope(pk: &str, seq: u64, prev: Option<String>) -> AttestationEnvelope {
        let receipts = vec![
            json!({ "action_id": "create_note", "success": true }),
            json!({ "action_id": "delete_account", "success": true }),
        ];
        let actions = minimize_window(&receipts, &Allowlist::new(["create_note"]));
        AttestationEnvelope {
            schema: "kriya.envelope.v1".into(),
            device_pub: pk.into(),
            org_id: "acme".into(),
            business_unit: None,
            operators: vec![OperatorRollup {
                op_ref: "op_ab12".into(),
                actions: 2,
            }],
            seq,
            prev_envelope_hash: prev,
            window: Window {
                from_ms: 1000,
                to_ms: 2000,
            },
            signers: vec![SignerRollup {
                fingerprint: "ab12".into(),
                receipts: 2,
                verified: 2,
            }],
            actions,
            counts: Counts {
                receipts: 2,
                verified: 2,
                failed: 0,
                destructive: 1,
                attestations: 0,
            },
            integrity: Integrity {
                merkle_root: "deadbeef".into(),
                chain_intact: true,
                broken_sources: vec![],
            },
            non_egress: NonEgress {
                attested: false,
                attestation_count: 0,
                proof_digest: None,
            },
            compiler: CompilerInfo {
                version: "0.1.0".into(),
                produced_ms: 2000,
            },
        }
    }

    #[test]
    fn signed_envelope_verifies_and_tamper_fails() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let signed = sign_envelope(sample_envelope(&pk, 1, None), &key);
        assert!(verify_envelope(&signed).is_ok(), "honest envelope verifies");

        let mut tampered = signed.clone();
        tampered["envelope"]["org_id"] = json!("evil-corp");
        assert!(
            verify_envelope(&tampered).is_err(),
            "tampering a signed field must fail"
        );

        let mut mismatched = signed.clone();
        mismatched["envelope"]["device_pub"] = json!("00".repeat(32));
        assert!(
            verify_envelope(&mismatched).is_err(),
            "device_pub != public_key must fail"
        );
    }

    #[test]
    fn count_sanity_rejects_incoherent_envelope() {
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let mut env = sample_envelope(&pk, 1, None);
        env.counts.failed = 5; // verified(2) + failed(5) != receipts(2)
        let signed = sign_envelope(env, &key); // validly SIGNED but incoherent
        assert!(
            verify_envelope(&signed).is_err(),
            "a signed-but-incoherent envelope must still fail count sanity"
        );
    }

    #[test]
    fn envelope_chain_continuity() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let e1 = sign_envelope(sample_envelope(&pk, 1, None), &key);
        let h1 = sha256_hex(&canonical_json_bytes(&e1));
        let e2 = sign_envelope(sample_envelope(&pk, 2, Some(h1.clone())), &key);

        assert_eq!(
            envelope_chain_break(&[e1.clone(), e2.clone()]),
            None,
            "intact"
        );
        assert_eq!(
            envelope_chain_break(&[e2.clone()]),
            Some(1),
            "a dropped genesis breaks at line 1"
        );
        let e2_bad = sign_envelope(sample_envelope(&pk, 2, Some("deadbeef".into())), &key);
        assert_eq!(
            envelope_chain_break(&[e1, e2_bad]),
            Some(2),
            "a wrong prev_envelope_hash breaks"
        );
    }
}
