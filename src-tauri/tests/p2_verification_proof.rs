//! P2 verification-pass proof (independent re-run, not part of CI) — extends `fleet_manual_proof.rs`'s
//! pattern with the missing link the P2 cockpit-UI acceptance bar needs: a REAL signed P1 DeviceInfo
//! beacon POSTed to a LIVE `kriyad` (mTLS) via the actual production `device_info::emit_if_changed`
//! path, then the real `fleet::fleet_connect` / `fleet::fleet_coverage` / `fleet::fleet_device_evidence`
//! Tauri commands called against that same kriyad, asserting the returned `DeviceCoverage` row actually
//! carries the P1 inventory fields (console_version, runtime_version, os_platform, agents, ...) the new
//! `src/lib/tauri.ts` TS bindings (`DeviceCoverageRow`) declare — i.e. the data shape the P2 cockpit UI
//! renders is real, not just type-compatible in the abstract.
//!
//! Requires the same fixtures as `fleet_manual_proof.rs`:
//!   1. `crates/kriya-aggregator/scripts/kriyd-ca.sh <dir> 1` to generate ca.pem/client-1.pem/key
//!   2. kriyad running on 127.0.0.1:8455 with KRIYAD_CA_DIR set to that dir (mTLS on)
//!   3. env var FLEET_E2E_CA_DIR (the ca/ dir). The device_pub is generated fresh each run (a new
//!      evidence.key under this test's own temp HOME) and printed — no need to pre-supply it, since
//!      this test both mints the device's identity AND queries kriyad for it in the same run.
//! Ignored by default — run explicitly:
//!   FLEET_E2E_CA_DIR=... \
//!     cargo test --features control-plane --test p2_verification_proof -- --ignored --nocapture
#![cfg(all(feature = "control-plane", unix))]

use kriya_console_lib::control_plane::{device_info, enrollment, envelope, fleet, push::PushTarget};
use kriya_console_lib::license::{dev_issue, dev_issuer_seed, LicensePayload};

#[test]
#[ignore = "manual proof: needs a live kriyad + real mTLS certs, see file header"]
fn p2_cockpit_data_shape_is_real_end_to_end() {
    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present");
        return;
    };
    let ca_dir = std::env::var("FLEET_E2E_CA_DIR").expect("set FLEET_E2E_CA_DIR");

    let tmp = std::env::temp_dir().join(format!("kriya-p2-proof-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let console = tmp.join(".kriya").join("console");
    std::fs::create_dir_all(&console).unwrap();
    std::env::set_var("HOME", &tmp);

    // 1. License this "device" for control-plane (device-side capability: emit device-info).
    let device_token = dev_issue(LicensePayload {
        holder: "P2 Proof Device".into(),
        tier: "pro".into(),
        features: vec!["control-plane".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "p2-proof-device".into(),
    })
    .expect("mint a control-plane license");
    std::fs::write(
        console.join("license.json"),
        serde_json::to_string(&device_token).unwrap(),
    )
    .unwrap();

    // 2. Enroll the device (device_label ONLY comes from here per doc 22 §7).
    std::fs::write(
        console.join("enrollment.json"),
        r#"{"serverUrl":"https://127.0.0.1:8455","orgId":"acme","businessUnit":"enclave-7","operatorId":"op","serverCaPinSha256":"ab","deviceLabel":"p2-proof-rig"}"#,
    )
    .unwrap();
    assert!(enrollment::control_plane_active(), "device must be active");

    // The device's real, stable evidence pubkey — freshly minted under this run's temp HOME. Printed so
    // the log is a self-contained proof of which device_pub the rest of this test's assertions concern.
    let device_pub = envelope::evidence_public_hex().expect("evidence pubkey");
    println!("device evidence_public_hex = {device_pub}");

    // 3. REAL signed P1 DeviceInfo beacon -> POST /v1/device-info on the LIVE kriyad, over mTLS, using
    //    the actual production entry point (collects real console/runtime/verify-crate versions, real
    //    OS info, real detected agents[], signs with the device's real evidence key).
    let target = PushTarget {
        server_url: "https://127.0.0.1:8455".into(),
        client_identity_pem: format!("{ca_dir}/client-1.pem").into(), // cert; key appended below
        server_ca_pem: format!("{ca_dir}/ca.pem").into(),
    };
    // mtls_client concatenates cert+key from ONE path in push.rs's convention; emit_if_changed uses
    // `target.client_identity_pem` directly as a PEM file, so build the concatenated identity file
    // exactly the way fleet.rs::to_fleet_config does for the pull side.
    let identity_path = tmp.join("client-identity.pem");
    let mut identity = std::fs::read_to_string(format!("{ca_dir}/client-1.pem")).unwrap();
    if !identity.ends_with('\n') {
        identity.push('\n');
    }
    identity.push_str(&std::fs::read_to_string(format!("{ca_dir}/client-1.key")).unwrap());
    std::fs::write(&identity_path, identity).unwrap();
    let target = PushTarget {
        client_identity_pem: identity_path,
        ..target
    };

    let outcome = device_info::emit_if_changed(&target).expect("emit_if_changed must not hard-error");
    println!("device_info::emit_if_changed -> {outcome:?}");
    assert_eq!(
        outcome,
        device_info::EmitOutcome::Sent,
        "the real signed DeviceInfo beacon must be accepted by the live kriyad"
    );

    // 4. Operator side: REAL fleet_connect / fleet_coverage / fleet_device_evidence Tauri commands
    //    (fleet-console licensed operator identity — separate persisted connection config, same HOME
    //    for this test's simplicity, matching fleet_manual_proof.rs's own pattern).
    let operator_token = dev_issue(LicensePayload {
        holder: "P2 Proof Operator".into(),
        tier: "pro".into(),
        features: vec!["fleet-console".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "p2-proof-operator".into(),
    })
    .expect("mint a fleet-console license");
    std::fs::write(
        console.join("license.json"),
        serde_json::to_string(&operator_token).unwrap(),
    )
    .unwrap();

    fleet::fleet_connect(
        "https://127.0.0.1:8455".into(),
        format!("{ca_dir}/ca.pem"),
        format!("{ca_dir}/client-1.pem"),
        format!("{ca_dir}/client-1.key"),
    )
    .expect("fleet_connect must succeed against a live kriyad");
    println!("fleet_connect: OK — fleet.json persisted");

    let coverage = fleet::fleet_coverage().expect("fleet_coverage");
    println!(
        "fleet_coverage (real kriyad response, re-parsed as the P0/P1 DeviceCoverage type):\n{}",
        serde_json::to_string_pretty(&coverage).unwrap()
    );
    let row = coverage
        .iter()
        .find(|r| r.device_pub == device_pub)
        .expect("coverage must contain a row for the device that just beaconed");

    // THE POINT OF THIS TEST: the P1 inventory fields must actually be populated (not just present-as-
    // Option-and-None) on the live response, i.e. exactly what P2's `DeviceCoverageRow` TS type and
    // ControlPlaneView's rendering (console/runtime version, os, agents chips, device_label) consume.
    assert!(row.console_version.is_some(), "console_version must be populated");
    assert!(row.runtime_version.is_some(), "runtime_version must be populated");
    assert!(row.verify_crate_version.is_some(), "verify_crate_version must be populated");
    assert!(row.os_platform.is_some(), "os_platform must be populated");
    assert!(row.os_arch.is_some(), "os_arch must be populated");
    assert_eq!(
        row.device_label.as_deref(),
        Some("p2-proof-rig"),
        "device_label must round-trip from enrollment.json, never a hostname"
    );
    assert!(row.agents.is_some(), "agents[] must be populated (even if empty array)");
    assert!(row.info_collected_ms.is_some(), "info_collected_ms must be populated");
    assert!(row.policy_applied_version.is_none(), "policy is None pre-P3 — must stay null, not a fabricated value");

    // 5. fleet_device_evidence — BC-5: every returned envelope re-verified LOCALLY. This device hasn't
    //    pushed any attestation envelopes (only a heartbeat via fleet_connect's own /healthz + the
    //    device-info beacon), so we just prove the call succeeds and returns a coherent, honest shape
    //    against the live server rather than asserting envelope contents that were never produced here.
    let evidence = fleet::fleet_device_evidence(device_pub.clone(), 0, 100)
        .expect("fleet_device_evidence must succeed against a live kriyad");
    println!(
        "fleet_device_evidence (real kriyad response):\n{}",
        serde_json::to_string_pretty(&evidence).unwrap()
    );
    assert!(
        evidence.envelopes.iter().all(|e| e.verified),
        "any envelope actually returned must re-verify locally (BC-5)"
    );

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&tmp);
}
