//! Redaction-enforced gate (1.12 ⭐) — the full-schema regression tripwire. Seed unique sentinels into
//! every raw receipt field (params, operator name, and a sensitive action id), build a full envelope
//! through the device builder, and assert NONE of them serialize into the envelope. This is the
//! build-failing guard behind "the redaction boundary is true in code" (LLD §B.4). Gated to the
//! control-plane feature on unix; layered on top of the STRUCTURAL guarantee (the sealed
//! MinimizedAction + the builder reading no params).
#![cfg(all(feature = "control-plane", unix))]

use ed25519_dalek::{Signer, SigningKey};
use kriya_console_lib::control_plane::envelope::{
    build_signed_envelope, SourceWindow, WindowInput,
};

/// A signed receipt LINE laden with sentinels: params (`secret` + free-text `reasoning`), a plaintext
/// operator name, and a sensitive (non-allowlisted) action id. Canonical bytes match `verify_value`
/// (declaration order; params pre-sorted), so the receipt genuinely verifies and flows through the
/// full rollup path — not silently dropped as "failed".
fn sentinel_receipt(host: &SigningKey) -> String {
    let params = r#"{"reasoning":"because the CEO asked","secret":"SENSITIVE_PARAM"}"#; // keys pre-sorted
    let fields = format!(
        r#""step_id":"s1","action_id":"wire_funds","params":{params},"success":true,"ts_ms":1,"actor":{{"agent":"claude","user":"Jane Q. Operator"}}"#
    );
    let canon = format!("{{{fields}}}");
    let sig = hex::encode(host.sign(canon.as_bytes()).to_bytes());
    let pk = hex::encode(host.verifying_key().to_bytes());
    format!(r#"{{{fields},"public_key":"{pk}","signature":"{sig}"}}"#)
}

#[test]
fn no_sentinel_survives_the_envelope_builder() {
    let host = SigningKey::from_bytes(&[42u8; 32]);
    let input = WindowInput {
        org_id: "acme".into(),
        business_unit: Some("enclave-7".into()),
        window_from_ms: 0,
        window_to_ms: 1,
        seq: 1,
        prev_envelope_hash: None,
        produced_ms: 1,
        sources: vec![SourceWindow {
            source: "x.jsonl".into(),
            lines: vec![sentinel_receipt(&host)],
            prev_tail_hash: None,
        }],
    };
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let signed = build_signed_envelope(&input, &key, &[3u8; 32]).expect("build envelope");

    // The full serialized envelope must contain NONE of the seeded sensitive tokens.
    let bytes = serde_json::to_string(&signed).expect("serialize envelope");
    for sentinel in [
        "SENSITIVE_PARAM",
        "because the CEO asked",
        "Jane Q. Operator",
        "wire_funds",
    ] {
        assert!(
            !bytes.contains(sentinel),
            "REDACTION LEAK: '{sentinel}' serialized into the envelope:\n{bytes}"
        );
    }

    // Positive controls — prove the receipt actually flowed through the path it was redacted on:
    assert_eq!(
        signed.envelope.counts.verified, 1,
        "the sentinel receipt verified and was counted (not silently dropped as failed)"
    );
    assert!(
        bytes.contains("\"op_"),
        "the operator appears only as an HMAC pseudonym"
    );
    assert!(
        bytes.contains("destructive"),
        "the non-allowlisted destructive id bucketed to \"destructive\""
    );
}
