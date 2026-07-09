//! Positive control for the dormancy guard (1.18) — with a valid `control-plane` license AND an
//! enrollment, the Compiler activates and MINTS its artifacts (evidence.key, pepper, outbox). This is
//! what makes the NEGATIVE dormancy test (tests/dormancy.rs) meaningful: together they prove the GUARD
//! flips behavior, not merely that an unexercised path stays quiet. Its own integration binary so the
//! `$HOME` override can't race the negative test. Gated to the control-plane feature on unix; skips
//! without the dev issuer seed.
#![cfg(all(feature = "control-plane", unix))]

use kriya_console_lib::control_plane::{compiler, enrollment, fleet};
use kriya_console_lib::license::{dev_issue, dev_issuer_seed, LicensePayload};

/// Guards `$HOME`-mutating tests in this binary from racing each other — this file now runs two
/// (the original Compiler positive control, plus the P0 fleet-console positive control below). Same
/// pattern as `govern.rs`'s / `dormancy.rs`'s `ENV_LOCK`.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

/// The mirror-image proof for the fleet cockpit's gate (P0): a license carrying the `fleet-console`
/// feature string flips `require_fleet_console()` open (and thus the pure-license-side checks the
/// three IPC commands make first) — the positive control that makes `dormancy.rs`'s
/// `fleet_commands_dormant_*` negative tests meaningful (together they prove the GATE flips behavior,
/// not merely that an unexercised path stays quiet). Only the license-gate half is exercised here
/// (no live kriyad to complete a real `/healthz` round-trip against) — `fleet_coverage`/
/// `fleet_device_evidence` still fail past the gate on "no fleet connection configured" (expected:
/// `fleet_connect` was never called), which is itself proof the gate OPENED rather than short-circuited
/// on the license check (a still-license-gated failure would instead mention `fleet-console`).
#[test]
fn fleet_console_licensed_opens_the_gate_past_the_license_check() {
    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join(format!("kriya-poscontrol-fleet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let console = tmp.join(".kriya").join("console");
    std::fs::create_dir_all(&console).unwrap();
    std::env::set_var("HOME", &tmp);

    let token = dev_issue(LicensePayload {
        holder: "Acme Regulated Co".into(),
        tier: "pro".into(),
        features: vec!["fleet-console".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "poscontrol-fleet".into(),
    })
    .expect("mint a fleet-console license");
    std::fs::write(
        console.join("license.json"),
        serde_json::to_string(&token).unwrap(),
    )
    .unwrap();

    let err = fleet::fleet_coverage().expect_err("no connection configured yet");
    assert!(
        !err.contains("fleet-console") && !err.contains("fleet cockpit"),
        "a licensed caller must get PAST the license gate — got the license-gate error instead: {err}"
    );
    assert!(
        err.contains("fleet_connect"),
        "past the gate, the next failure must be 'not connected', not a license error: {err}"
    );

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&tmp);
}
