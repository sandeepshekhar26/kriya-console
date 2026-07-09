//! Manual e2e proof (not part of the CI suite) — drives the REAL `fleet_connect` / `fleet_coverage` /
//! `fleet_device_evidence` Tauri commands against a LIVE `kriyad` on 127.0.0.1:8455 with real mTLS
//! certs and a dev `fleet-console` license, and prints the re-verified coverage + evidence JSON so the
//! P0 acceptance bar's "manual proof" step has a real log to point at. Requires:
//!   1. `crates/kriya-aggregator/scripts/kriyd-ca.sh <dir> 1` to have generated ca.pem/client-1.pem/key
//!   2. kriyad running on 127.0.0.1:8455 with KRIYAD_CA_DIR set to that dir (mTLS on)
//!   3. env vars FLEET_E2E_CA_DIR (the ca/ dir) and FLEET_E2E_DEVICE_PUB set
//! Ignored by default — run explicitly:
//!   FLEET_E2E_CA_DIR=... FLEET_E2E_DEVICE_PUB=... \
//!     cargo test --features control-plane --test fleet_manual_proof -- --ignored --nocapture
#![cfg(all(feature = "control-plane", unix))]

use kriya_console_lib::control_plane::fleet;
use kriya_console_lib::license::{dev_issue, dev_issuer_seed, LicensePayload};

#[test]
#[ignore = "manual proof: needs a live kriyad + real mTLS certs, see file header"]
fn manual_proof_against_a_live_kriyad() {
    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present");
        return;
    };
    let ca_dir = std::env::var("FLEET_E2E_CA_DIR").expect("set FLEET_E2E_CA_DIR");
    let device_pub = std::env::var("FLEET_E2E_DEVICE_PUB").expect("set FLEET_E2E_DEVICE_PUB");

    let tmp = std::env::temp_dir().join(format!("kriya-fleet-manual-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let console = tmp.join(".kriya").join("console");
    std::fs::create_dir_all(&console).unwrap();
    std::env::set_var("HOME", &tmp);

    let token = dev_issue(LicensePayload {
        holder: "Manual Proof".into(),
        tier: "pro".into(),
        features: vec!["fleet-console".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "manual-proof".into(),
    })
    .expect("mint a fleet-console license");
    std::fs::write(
        console.join("license.json"),
        serde_json::to_string(&token).unwrap(),
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
    println!("fleet_coverage: {}", serde_json::to_string_pretty(&coverage).unwrap());
    assert!(!coverage.is_empty(), "expected at least one device row");

    let evidence = fleet::fleet_device_evidence(device_pub, 0, 100).expect("fleet_device_evidence");
    println!(
        "fleet_device_evidence: {}",
        serde_json::to_string_pretty(&evidence).unwrap()
    );
    assert!(!evidence.envelopes.is_empty(), "expected at least one envelope");
    assert!(
        evidence.envelopes.iter().all(|e| e.verified),
        "every envelope from a real kriyad must re-verify locally"
    );

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&tmp);
}
