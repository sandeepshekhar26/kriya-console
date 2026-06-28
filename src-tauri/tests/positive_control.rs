//! Positive control for the dormancy guard (1.18) — with a valid `control-plane` license AND an
//! enrollment, the Compiler activates and MINTS its artifacts (evidence.key, pepper, outbox). This is
//! what makes the NEGATIVE dormancy test (tests/dormancy.rs) meaningful: together they prove the GUARD
//! flips behavior, not merely that an unexercised path stays quiet. Its own integration binary so the
//! `$HOME` override can't race the negative test. Gated to the control-plane feature on unix; skips
//! without the dev issuer seed.
#![cfg(all(feature = "control-plane", unix))]

use kriya_console_lib::control_plane::{compiler, enrollment};
use kriya_console_lib::license::{dev_issue, dev_issuer_seed, LicensePayload};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[test]
fn licensed_and_enrolled_compiler_creates_its_artifacts() {
    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present");
        return;
    };
    let tmp = std::env::temp_dir().join(format!("kriya-poscontrol-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let console = tmp.join(".kriya").join("console");
    std::fs::create_dir_all(&console).unwrap();
    std::env::set_var("HOME", &tmp);

    // Install a control-plane license + enroll.
    let token = dev_issue(LicensePayload {
        holder: "Acme Regulated Co".into(),
        tier: "pro".into(),
        features: vec!["control-plane".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "poscontrol".into(),
    })
    .expect("mint a control-plane license");
    std::fs::write(
        console.join("license.json"),
        serde_json::to_string(&token).unwrap(),
    )
    .unwrap();
    std::fs::write(
        console.join("enrollment.json"),
        r#"{"serverUrl":"https://kriyad.acme","orgId":"acme","operatorId":"op","serverCaPinSha256":"ab"}"#,
    )
    .unwrap();

    assert!(
        enrollment::control_plane_active(),
        "a valid control-plane license + enrollment must activate the control plane"
    );

    // One window of real work → mints evidence.key + pepper + the outbox (the artifacts the negative
    // test asserts are ABSENT when dormant).
    let now = now_ms();
    compiler::compile_once((now.saturating_sub(1000), now), now).expect("compile_once");

    for artifact in ["evidence.key", "pepper", "outbox.jsonl"] {
        assert!(
            console.join(artifact).exists(),
            "an active Compiler must create {artifact}"
        );
    }

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&tmp);
}
