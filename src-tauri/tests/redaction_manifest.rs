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
    signed_line(host, "s1", "wire_funds", params, Some("Jane Q. Operator"))
}

/// A `kriya.io.egress.mcp.allow` receipt (EG-2/EG-3, doc 24 §4.2) carrying the full high-fidelity
/// param set an assessor would actually see on-device: `dest_host`, byte counts, and a content hash —
/// exactly the fields the study is emphatic must stay device-local. `bytes_out`/`bytes_in` use the
/// spec's own sentinel value (424242) so a leak is unambiguous.
fn io_sentinel_receipt(host: &SigningKey) -> String {
    let params = concat!(
        r#"{"bytes_in":424242,"bytes_out":424242,"content_sha256":"#,
        r#""SENTINEL0000000000000000000000000000000000000000000000000000",""#,
        r#"corr":"s-io","decision":"allow","dest_host":"SENSITIVE-TENANT.internal.example","#,
        r#""dest_kind":"mcp","hash_scheme":"wire-bytes"}"#,
    );
    signed_line(host, "s-io", "kriya.io.egress.mcp.allow", params, Some("Jane Q. Operator"))
}

/// A `kriya.watch.net.connect` receipt (doc 20 §2/§5's reserved watcher namespace — "watch params are
/// never allowlisted verbatim"). Fulfills that doc's outstanding test commitment: the same structural
/// seal (`minimize_window` reads only `action_id` + `success`) must hold for the watcher vocabulary
/// too, proven here rather than only asserted in the doc.
fn watch_sentinel_receipt(host: &SigningKey) -> String {
    let params = concat!(
        r#"{"daddr":"10.66.66.66","dport":443,"exe":"/usr/bin/curl","pid":4242,"proto":"tcp","#,
        r#""scope_token":"SENTINEL-SCOPE-TOKEN","sni_or_host":"SENSITIVE-TENANT.internal.example"}"#,
    );
    signed_line(host, "s-watch", "kriya.watch.net.connect", params, None)
}

/// Build one signed receipt line with the given `action_id`/`params`/optional actor. Canonical bytes
/// match `verify_value` (declaration order; params pre-sorted) exactly, so every sentinel receipt
/// genuinely verifies and flows through the full rollup path — not silently dropped as "failed".
fn signed_line(host: &SigningKey, step_id: &str, action_id: &str, params: &str, user: Option<&str>) -> String {
    let actor = user
        .map(|u| format!(r#","actor":{{"agent":"claude","user":"{u}"}}"#))
        .unwrap_or_default();
    let fields =
        format!(r#""step_id":"{step_id}","action_id":"{action_id}","params":{params},"success":true,"ts_ms":1{actor}"#);
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
            lines: vec![
                sentinel_receipt(&host),
                io_sentinel_receipt(&host),
                watch_sentinel_receipt(&host),
            ],
            prev_tail_hash: None,
        }],
        envelope_verbosity: "standard".into(),
        policy_state: None,
        io_verbosity: "off".into(),
        egress_patterns: vec![],
    };
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let signed = build_signed_envelope(&input, &key, &[3u8; 32]).expect("build envelope");

    // The full serialized envelope must contain NONE of the seeded sensitive tokens — across the
    // original wire_funds sentinel, the EG-3 kriya.io.* sentinel, and the doc-20 kriya.watch.*
    // sentinel (its outstanding "watch params are never allowlisted verbatim" test commitment).
    let bytes = serde_json::to_string(&signed).expect("serialize envelope");
    for sentinel in [
        "SENSITIVE_PARAM",
        "because the CEO asked",
        "Jane Q. Operator",
        "wire_funds",
        "SENSITIVE-TENANT.internal.example",
        "SENTINEL0000000000000000000000000000000000000000000000000000",
        "424242",
        "SENTINEL-SCOPE-TOKEN",
        "10.66.66.66",
        "/usr/bin/curl",
    ] {
        assert!(
            !bytes.contains(sentinel),
            "REDACTION LEAK: '{sentinel}' serialized into the envelope:\n{bytes}"
        );
    }

    // Positive controls — prove every sentinel receipt actually flowed through the path it was
    // redacted on (not silently dropped as "failed"):
    assert_eq!(
        signed.envelope.counts.verified, 3,
        "all three sentinel receipts verified and were counted"
    );
    assert!(
        bytes.contains("\"op_"),
        "the operator appears only as an HMAC pseudonym"
    );
    assert!(
        bytes.contains("destructive"),
        "the non-allowlisted destructive id bucketed to \"destructive\""
    );
    // The kriya.io.* id IS allowlisted (EG-3, governance metadata) — it must appear VERBATIM in the
    // envelope's actions[] with count 1, never bucketed, proving the allowlist change took effect.
    assert!(
        bytes.contains(r#""action":"kriya.io.egress.mcp.allow","count":1"#)
            || bytes.contains(r#""count":1,"action":"kriya.io.egress.mcp.allow""#),
        "kriya.io.egress.mcp.allow must pass through verbatim with count 1: {bytes}"
    );
}

/// The EG-4 pattern-echo tripwire (doc 24 §4.5/§7.5): with `io_verbosity: "pattern-echo"` ENGAGED —
/// the one mode that reads `params.dest_host` at all — the same `SENSITIVE-TENANT.internal.example`
/// sentinel must STILL never serialize. Deliberately gives NO authored `egress_patterns`, so the
/// sentinel host matches nothing and must collapse to the fixed "unlisted" bucket.
#[test]
fn no_sentinel_survives_pattern_echo_even_when_engaged() {
    let host = SigningKey::from_bytes(&[43u8; 32]);
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
            lines: vec![io_sentinel_receipt(&host)],
            prev_tail_hash: None,
        }],
        envelope_verbosity: "standard".into(),
        policy_state: None,
        io_verbosity: "pattern-echo".into(),
        egress_patterns: vec!["*.totally-different-vendor.example".to_string()],
    };
    let key = SigningKey::from_bytes(&[12u8; 32]);
    let signed = build_signed_envelope(&input, &key, &[3u8; 32]).expect("build envelope");

    let bytes = serde_json::to_string(&signed).expect("serialize envelope");
    for sentinel in [
        "SENSITIVE-TENANT.internal.example",
        "SENTINEL0000000000000000000000000000000000000000000000000000",
        "424242",
    ] {
        assert!(
            !bytes.contains(sentinel),
            "REDACTION LEAK: '{sentinel}' serialized into a pattern-echo envelope:\n{bytes}"
        );
    }

    // Positive control: io_destinations IS present (pattern-echo engaged) and the non-matching host
    // collapsed to the fixed sentinel, proving the field genuinely populated rather than being
    // silently empty/absent.
    let io_destinations = signed.envelope.io_destinations.expect("pattern-echo must populate io_destinations");
    assert_eq!(io_destinations.len(), 1);
    assert_eq!(io_destinations[0].pattern, "unlisted");
    assert_eq!(io_destinations[0].count, 1);
}
