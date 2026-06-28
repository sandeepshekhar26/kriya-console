//! Phase-1 device end-to-end (1.19) — the wedge true in code, device-side (no server yet).
//!
//! A feature-built, licensed + enrolled device with REAL receipts in `~/.kriya/audit/` runs the
//! Compiler, which emits a signed, minimized `AttestationEnvelope` to the outbox. We then re-verify
//! that outbox OFFLINE with the SAME `kriya-verify` code the `kriya-audit` CLI links (sig +
//! envelope-chain + merkle-format), and confirm a 1-byte tamper is rejected. Gated to the control-plane
//! feature on unix; skips without the dev issuer seed. (The `emit_device_outbox` #[ignore] companion
//! prints the same outbox so the literal `kriya-audit` binary can be run against the device's bytes.)
#![cfg(all(feature = "control-plane", unix))]

use kriya_console_lib::control_plane::{compiler, enrollment};
use kriya_console_lib::license::{dev_issue, dev_issuer_seed, LicensePayload};
use kriya_verify::{envelope_chain_break, verify_envelope};
use serde_json::Value;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Set up a licensed + enrolled device under `home` with the real `sample-audit.jsonl` as a governed
/// source, then run one Compiler window. Returns the outbox path. Caller must have set `HOME = home`.
fn run_device(home: &std::path::Path) -> std::path::PathBuf {
    let console = home.join(".kriya").join("console");
    let audit = home.join(".kriya").join("audit");
    std::fs::create_dir_all(&console).unwrap();
    std::fs::create_dir_all(&audit).unwrap();

    // Real, host-signed receipts (ground-truth-verified) as a governed app's audit log.
    let sample = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../src/sample/sample-audit.jsonl"
    );
    std::fs::copy(sample, audit.join("app.jsonl")).unwrap();

    // Control-plane license + enrollment.
    let token = dev_issue(LicensePayload {
        holder: "Acme Regulated Co".into(),
        tier: "pro".into(),
        features: vec!["control-plane".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "e2e".into(),
    })
    .expect("mint a control-plane license");
    std::fs::write(
        console.join("license.json"),
        serde_json::to_string(&token).unwrap(),
    )
    .unwrap();
    std::fs::write(
        console.join("enrollment.json"),
        r#"{"serverUrl":"https://kriyad.acme","orgId":"acme","businessUnit":"enclave-7","operatorId":"op","serverCaPinSha256":"ab"}"#,
    )
    .unwrap();

    assert!(enrollment::control_plane_active(), "device must be active");
    let now = now_ms();
    compiler::compile_once((now.saturating_sub(1000), now), now).expect("compile_once");
    console.join("outbox.jsonl")
}

#[test]
fn device_emits_an_envelope_the_auditor_reverifies_offline() {
    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present");
        return;
    };
    let home = std::env::temp_dir().join(format!("kriya-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::env::set_var("HOME", &home);

    let outbox = run_device(&home);
    let text = std::fs::read_to_string(&outbox).expect("outbox exists");
    let values: Vec<Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(values.len(), 1, "one window → one envelope");

    // Re-verify OFFLINE with the auditor's code: signature + count sanity, envelope chain, merkle format.
    assert!(
        verify_envelope(&values[0]).is_ok(),
        "the device envelope verifies"
    );
    assert_eq!(
        envelope_chain_break(&values),
        None,
        "single genesis → intact chain"
    );
    let merkle = values[0]["envelope"]["integrity"]["merkle_root"]
        .as_str()
        .unwrap();
    assert_eq!(merkle.len(), 64, "real 64-hex merkle_root");

    // The real receipts flowed through, minimized: the sample's 20 receipts are verified + counted,
    // yet NO operator name / raw params survive.
    assert_eq!(
        values[0]["envelope"]["counts"]["verified"].as_u64(),
        Some(20)
    );
    assert!(
        !text.contains("\"params\""),
        "no raw params in the envelope"
    );

    // A 1-byte tamper is rejected (exit-1 equivalent).
    let mut tampered = values[0].clone();
    tampered["envelope"]["org_id"] = serde_json::json!("evil-corp");
    assert!(verify_envelope(&tampered).is_err(), "tamper must fail");

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&home);
}

/// Companion emitter: print the device's outbox (one compact JSONL line) so the literal `kriya-audit`
/// binary can be run against the device's real bytes:
///   cargo test -p kriya-console --features control-plane emit_device_outbox -- --ignored --nocapture
#[test]
#[ignore = "emitter: prints the device outbox JSONL for the kriya-audit binary step"]
fn emit_device_outbox() {
    if dev_issuer_seed().is_none() {
        return;
    }
    let home = std::env::temp_dir().join(format!("kriya-e2e-emit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::env::set_var("HOME", &home);
    let outbox = run_device(&home);
    print!("{}", std::fs::read_to_string(&outbox).unwrap());
    let _ = std::fs::remove_dir_all(&home);
}
