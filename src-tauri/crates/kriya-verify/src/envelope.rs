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
    /// v1.1 (P3, doc 22 §5) — a freshness echo of the policy bundle applied at compile time, emitted
    /// by the Compiler once a device has actually applied a `PolicyBundle` (the P3 downlink). Optional
    /// and additive (`#[serde(default)]` + `skip_serializing_if`): a pre-P3 device (or one that has
    /// never applied a bundle) omits this field entirely, byte-for-byte identical to v1.0 — never
    /// `null`. See [`verify_envelope`]'s doc comment for how this stays BC-5 safe both ways.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_state: Option<PolicyStateEcho>,
}

/// The v1.1 envelope's policy freshness echo — `{version, bundle_hash, applied_ms}` verbatim per doc
/// 22 §5. Distinct from `kriya_verify::DeviceInfo`'s `PolicyEcho` (`{applied_version, bundle_hash}`,
/// doc 22 §7) — same idea, two different schemas from two different doc sections, deliberately not
/// unified (an envelope field and a device-inventory field are not the same wire contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStateEcho {
    pub version: u64,
    pub bundle_hash: String,
    pub applied_ms: u64,
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
///
/// **BC-5, the trap, made concrete (doc 22 §8):** the signature is checked against the canonical bytes
/// of the RAW `v["envelope"]` value exactly as received — never a re-serialization of the *parsed*
/// [`AttestationEnvelope`] struct. Re-serializing the typed struct would silently DROP any field this
/// exact build doesn't define (e.g. an older `kriya-verify` reading a v1.1 envelope's `policy_state`),
/// recomputing bytes that don't match what was actually signed and wrongly failing a legitimately
/// signed newer envelope. Canonicalizing the untyped value sidesteps this: it includes every key that
/// was actually on the wire, known or not to this build, so the recomputed bytes always match what the
/// signer signed — in both directions (an old verifier reading a new artifact, and a new verifier
/// reading an old one, where the newer optional field is simply absent either way).
pub fn verify_envelope(v: &Value) -> Result<(), String> {
    let signed: SignedEnvelope =
        serde_json::from_value(v.clone()).map_err(|e| format!("not a signed envelope: {e}"))?;
    if signed.envelope.device_pub != signed.public_key {
        return Err("device_pub does not match the signing public_key".into());
    }
    let raw_envelope = v.get("envelope").ok_or("missing envelope field")?;
    let msg = canonical_json_bytes(raw_envelope);
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
            policy_state: None,
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
    fn envelope_with_policy_state_verifies_and_tamper_fails() {
        let key = SigningKey::from_bytes(&[15u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let mut env = sample_envelope(&pk, 1, None);
        env.policy_state = Some(PolicyStateEcho {
            version: 13,
            bundle_hash: "deadbeef".into(),
            applied_ms: 1_783_500_000_000,
        });
        let signed = sign_envelope(env, &key);
        assert!(
            verify_envelope(&signed).is_ok(),
            "a v1.1 envelope carrying policy_state verifies"
        );

        let mut tampered = signed.clone();
        tampered["envelope"]["policy_state"]["version"] = json!(999);
        assert!(
            verify_envelope(&tampered).is_err(),
            "tampering policy_state after signing must fail"
        );
    }

    #[test]
    fn policy_state_is_omitted_not_null_when_absent() {
        // BC-4: additive-only evolution depends on ABSENCE, not `null`, being the "pre-P3 / not yet
        // applied" signal — mirrors DeviceInfo's identical `policy`/`device_label` convention.
        let key = SigningKey::from_bytes(&[16u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let signed = sign_envelope(sample_envelope(&pk, 1, None), &key);
        let s = serde_json::to_string(&signed).unwrap();
        assert!(!s.contains("\"policy_state\":null"));
        assert!(!s.contains("policy_state")); // truly absent, not present-as-null
    }

    /// THE BC-5 regression proof (doc 22 §8's "trap"): a field genuinely NEWER than anything this
    /// exact build's `AttestationEnvelope` struct defines — not `policy_state` specifically, something
    /// this code has never heard of at all — must still verify. This is the practical stand-in for
    /// "an old verifier reads a new artifact": if verification recomputed bytes from the PARSED (and
    /// therefore unknown-field-dropping) struct, this would wrongly fail; canonicalizing the RAW wire
    /// value (this crate's actual behavior, fixed in this same change) succeeds regardless.
    #[test]
    fn verify_envelope_tolerates_a_field_newer_than_this_code_knows_about() {
        let key = SigningKey::from_bytes(&[17u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let mut env_value = serde_json::to_value(sample_envelope(&pk, 1, None)).unwrap();
        env_value["a_field_from_a_future_schema_bump"] = json!({ "nested": "whatever", "n": 42 });
        let msg = canonical_json_bytes(&env_value);
        let signature = hex::encode(key.sign(&msg).to_bytes());
        let signed = json!({ "envelope": env_value, "public_key": pk, "signature": signature });
        assert!(
            verify_envelope(&signed).is_ok(),
            "an envelope field this build has never heard of must not break verification"
        );

        // And tampering that SAME unknown field must still be caught — proof this isn't just "ignore
        // everything I don't recognize," it's "canonicalize exactly what's there, known or not."
        let mut tampered = signed.clone();
        tampered["envelope"]["a_field_from_a_future_schema_bump"]["n"] = json!(43);
        assert!(verify_envelope(&tampered).is_err(), "tampering an unknown field must still fail");
    }

    /// BC-5 cross-version fixture pair (doc 22 §8, P3): the CURRENT verifier accepts BOTH the
    /// pre-existing v1.0 fixture (no `policy_state` at all — committed since Phase 1, unchanged) and
    /// the new v1.1 fixture (`policy_state` present, this change) — proving additive schema evolution
    /// holds in both directions against the SAME code, the practical proxy this codebase already uses
    /// for "old ↔ new" compatibility (mirrors `kriya-aggregator`'s own coverage/heartbeat cross-version
    /// tests). The companion TS-side proof lives in `test/envelope.test.ts`.
    #[test]
    fn cross_version_fixtures_both_verify() {
        let v1_0: Value =
            serde_json::from_str(include_str!("../../../../src/sample/sample-envelope.json")).unwrap();
        assert!(
            v1_0["envelope"].get("policy_state").is_none(),
            "the v1.0 fixture must genuinely predate policy_state"
        );
        assert!(verify_envelope(&v1_0).is_ok(), "the v1.0 (no policy_state) fixture verifies");

        let v1_1: Value = serde_json::from_str(include_str!(
            "../../../../src/sample/sample-envelope-v1.1.json"
        ))
        .unwrap();
        assert!(
            v1_1["envelope"]["policy_state"]["version"] == json!(13),
            "the v1.1 fixture must genuinely carry policy_state"
        );
        assert!(verify_envelope(&v1_1).is_ok(), "the v1.1 (with policy_state) fixture verifies");
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
            envelope_chain_break(std::slice::from_ref(&e2)),
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

    /// Emits the committed Rust↔TS parity fixture (`src/sample/sample-envelope.json`) for the TS
    /// envelope test (1.7). Deterministic (fixed key seed). Regenerate with:
    ///   cargo test -p kriya-verify print_sample_envelope -- --ignored --nocapture
    #[test]
    #[ignore = "fixture generator; run with --ignored --nocapture to (re)generate the parity fixture"]
    fn print_sample_envelope() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let signed = sign_envelope(sample_envelope(&pk, 1, None), &key);
        println!("{}", serde_json::to_string_pretty(&signed).unwrap());
    }

    /// Emits the BC-5 cross-version parity fixture (`src/sample/sample-envelope-v1.1.json`) — a v1.1
    /// envelope carrying `policy_state` (doc 22 §5, P3). The pre-existing `sample-envelope.json` (no
    /// `policy_state` at all) IS the "v1.0" fixture side of this same parity pair — both fixtures are
    /// verified by the SAME current code (see the BC-5 tests above + `test/envelope.test.ts`), proving
    /// additive schema evolution holds in both directions. Regenerate with:
    ///   cargo test -p kriya-verify print_sample_envelope_v1_1 -- --ignored --nocapture
    #[test]
    #[ignore = "fixture generator; run with --ignored --nocapture to (re)generate the parity fixture"]
    fn print_sample_envelope_v1_1() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let mut env = sample_envelope(&pk, 1, None);
        env.policy_state = Some(PolicyStateEcho {
            version: 13,
            bundle_hash: "deadbeefcafef00d".into(),
            applied_ms: 1_783_500_000_000,
        });
        let signed = sign_envelope(env, &key);
        println!("{}", serde_json::to_string_pretty(&signed).unwrap());
    }
}
