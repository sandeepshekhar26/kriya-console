//! P5 end-to-end proof (not part of the CI suite) — self-contained, mirrors `p4_manual_proof.rs`'s
//! real-kriyad-subprocess technique exactly (see that file's header for why the org key is constructed
//! directly rather than pulled from the OS keychain). Runs the SAME kind of 2-device scenario P4's
//! proof used, then calls the NEW `fleet_org_evidence` Tauri command and prints the real, generated
//! Markdown report — the org-wide, envelope-native evidence export (doc 22 §9) — so the session log is
//! the artifact this phase's acceptance bar calls for.
//!
//! Run with:
//!   cargo test --features control-plane --test p5_manual_proof -- --ignored --nocapture
#![cfg(all(feature = "control-plane", unix))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use kriya_console_lib::control_plane::{compiler, fleet, fleet_client, policy, push};
use kriya_console_lib::license::{dev_issue, dev_issuer_seed, LicensePayload};

struct KriyadProcess {
    child: Child,
}
impl Drop for KriyadProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run(cmd: &mut Command, what: &str) {
    let status = cmd.status().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    assert!(status.success(), "{what} failed: {status}");
}

fn set_home(dir: &Path) {
    std::env::set_var("HOME", dir);
}

fn read_file(path: &Path) -> String {
    let mut s = String::new();
    std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()))
        .read_to_string(&mut s)
        .unwrap();
    s
}

/// Real wall-clock epoch ms. Unlike P3/P4's own proofs (which use tiny synthetic compiler-window
/// timestamps like `(0, 60_000)` — fine there, since nothing in those proofs filters by REAL recency),
/// this proof's `fleet_org_evidence` call filters envelopes by actual wall-clock cutoff
/// (`stream_fleet_envelopes`'s `now_ms - window_ms`), so the envelopes this proof produces must carry
/// REAL, plausible `window.to_ms` values or they would (correctly!) be treated as ancient and dropped.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn author_sign_publish(
    cfg: &fleet_client::FleetConfig,
    org_key: &SigningKey,
    policy_json: serde_json::Value,
    budgets_json: serde_json::Value,
) -> (u16, u64) {
    let next_version = match fleet_client::fetch_policy_preview(cfg, "_fleet_console_preview_", None).unwrap() {
        Some(raw) => {
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            v["bundle"]["version"].as_u64().unwrap() + 1
        }
        None => 1,
    };
    let bundle = kriya_verify::PolicyBundle {
        org_id: "acme-dod".into(),
        version: next_version,
        issued_ms: 1_783_500_000_000 + next_version,
        expires_ms: None,
        scope: kriya_verify::PolicyScope::all(),
        policy: policy_json,
        budgets: budgets_json,
        govern: vec![kriya_verify::GovernDirective { target: "claude-code".into(), action: "wire".into() }],
        envelope_verbosity: "standard".into(),
        kill_switch: false,
    };
    let signed = kriya_verify::sign_policy_bundle(org_key, bundle);
    let body = serde_json::to_string(&signed).unwrap();
    let (status, _resp) = fleet_client::publish_policy(cfg, &body).unwrap();
    (status, next_version)
}

fn setup_device_home(
    home: &Path,
    server_url: &str,
    org_key_pub_hex: &str,
    ca_dir: &Path,
    client_n: u32,
) -> push::PushTarget {
    let _ = std::fs::remove_dir_all(home);
    std::fs::create_dir_all(home.join(".kriya/console")).unwrap();
    std::fs::write(
        home.join(".kriya/console/enrollment.json"),
        serde_json::json!({
            "serverUrl": server_url,
            "orgId": "acme-dod",
            "operatorId": "op-1",
            "serverCaPinSha256": "unused-in-this-proof",
            "orgPolicyPub": org_key_pub_hex,
        })
        .to_string(),
    )
    .unwrap();

    let device_identity_pem = home.join(".kriya/console/device-identity.pem");
    std::fs::write(
        &device_identity_pem,
        format!(
            "{}\n{}",
            read_file(&ca_dir.join(format!("client-{client_n}.pem"))),
            read_file(&ca_dir.join(format!("client-{client_n}.key")))
        ),
    )
    .unwrap();

    push::PushTarget {
        server_url: server_url.to_string(),
        client_identity_pem: device_identity_pem,
        server_ca_pem: ca_dir.join("ca.pem"),
    }
}

/// See `p4_manual_proof.rs::compile_and_push`'s doc comment for why this proof drives
/// `push::push_envelopes` itself rather than relying on an unwired live network loop.
fn compile_and_push(window: (u64, u64), produced_ms: u64, home: &Path, target: &push::PushTarget) {
    compiler::compile_once(window, produced_ms).expect("compile_once");
    let outbox = read_file(&home.join(".kriya/console/outbox.jsonl"));
    let ndjson = outbox.trim_end();
    assert!(!ndjson.is_empty(), "compile_once must have produced at least one line");
    let report = push::push_envelopes(target, &format!("{ndjson}\n")).expect("push_envelopes");
    println!("push_envelopes -> {report}");
}

#[test]
#[ignore = "self-contained manual e2e proof: builds + spawns a real kriyad; see file header"]
fn p5_org_wide_evidence_proof() {
    let root = workspace_root();
    let ca_dir = std::env::temp_dir().join(format!("kriya-p5-ca-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ca_dir);

    println!("== build kriyad + generate dev mTLS certs (1 operator + 2 device identities) ==");
    run(
        Command::new("cargo").current_dir(&root).args(["build", "-q", "-p", "kriya-aggregator"]),
        "cargo build kriya-aggregator",
    );
    run(
        Command::new("bash")
            .arg(root.join("crates/kriya-aggregator/scripts/kriyd-ca.sh"))
            .arg(&ca_dir)
            .arg("3"),
        "kriyd-ca.sh",
    );

    let db_path = std::env::temp_dir().join(format!("kriya-p5-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let bind = "127.0.0.1:8468";
    let kriyad_bin = root.join("target/debug/kriyad");
    let license_path = root.join("crates/kriya-aggregator/fixtures/dev-control-plane-license.json");

    let org_key = SigningKey::from_bytes(&[0x37u8; 32]);
    let org_key_pub_hex = hex::encode(org_key.verifying_key().to_bytes());
    std::fs::write(ca_dir.join("org-policy.pub"), format!("{org_key_pub_hex}\n")).unwrap();

    println!("== spawn kriyad (mTLS, {bind}) ==");
    let child = Command::new(&kriyad_bin)
        .env("KRIYAD_BIND", bind)
        .env("KRIYAD_DB", &db_path)
        .env("KRIYAD_LICENSE", &license_path)
        .env("KRIYAD_CA_DIR", &ca_dir)
        // Predates P6 role-stamped certs (its certs are role-less) → documented legacy-grace mode.
        .env("KRIYAD_ALLOW_LEGACY_CERTS", "1")
        .spawn()
        .expect("spawn kriyad");
    let _kriyad = KriyadProcess { child };

    let operator_home = std::env::temp_dir().join(format!("kriya-p5-operator-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&operator_home);
    std::fs::create_dir_all(operator_home.join(".kriya/console")).unwrap();
    set_home(&operator_home);

    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present (dev-keys/issuer-dev-seed.hex)");
        return;
    };
    let operator_license = dev_issue(LicensePayload {
        holder: "P5 Manual Proof — Operator".into(),
        tier: "pro".into(),
        features: vec!["fleet-console".into(), "control-plane".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "p5-proof-operator".into(),
    })
    .expect("mint operator license");
    std::fs::write(
        operator_home.join(".kriya/console/license.json"),
        serde_json::to_string(&operator_license).unwrap(),
    )
    .unwrap();

    let server_url = format!("https://{bind}");
    println!("\n== (a) operator: fleet_connect over real mTLS ==");
    for attempt in 0..50 {
        let probe = fleet::fleet_connect(
            server_url.clone(),
            ca_dir.join("ca.pem").to_string_lossy().into_owned(),
            ca_dir.join("client-1.pem").to_string_lossy().into_owned(),
            ca_dir.join("client-1.key").to_string_lossy().into_owned(),
        );
        if probe.is_ok() {
            break;
        }
        assert!(attempt < 49, "fleet_connect never succeeded: {probe:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("fleet_connect: OK");

    let operator_cfg = fleet_client::FleetConfig {
        server_url: server_url.clone(),
        client_identity_pem: operator_home.join(".kriya/console/fleet-identity.pem"),
        server_ca_pem: ca_dir.join("ca.pem"),
    };

    println!("\n== (a) operator: author + sign + publish v1 ==");
    let (status, v1) = author_sign_publish(
        &operator_cfg,
        &org_key,
        serde_json::json!({ "rules": [{ "action": "*", "allow": true }] }),
        serde_json::json!({ "max_actions_per_minute": 30 }),
    );
    assert_eq!(status, 200);
    assert_eq!(v1, 1);

    let device_a_home = std::env::temp_dir().join(format!("kriya-p5-device-a-{}", std::process::id()));
    let device_b_home = std::env::temp_dir().join(format!("kriya-p5-device-b-{}", std::process::id()));
    let target_a = setup_device_home(&device_a_home, &server_url, &org_key_pub_hex, &ca_dir, 2);
    let target_b = setup_device_home(&device_b_home, &server_url, &org_key_pub_hex, &ca_dir, 3);

    let t0 = now_ms();

    println!("\n== (b) device A: pull_and_apply v1, compile + push envelope ==");
    set_home(&device_a_home);
    policy::pull_and_apply(&target_a).expect("device A pull_and_apply v1");
    compile_and_push((t0, t0 + 60_000), t0 + 60_000, &device_a_home, &target_a);

    println!("\n== (b) device B: pull_and_apply v1, compile + push envelope ==");
    set_home(&device_b_home);
    policy::pull_and_apply(&target_b).expect("device B pull_and_apply v1");
    compile_and_push((t0, t0 + 60_000), t0 + 60_000, &device_b_home, &target_b);

    println!("\n== (a) operator: publish v2 (only device A will pull it) ==");
    let (status, v2) = author_sign_publish(
        &operator_cfg,
        &org_key,
        serde_json::json!({ "rules": [{ "action": "delete_*", "allow": false }, { "action": "*", "allow": true }] }),
        serde_json::json!({ "max_actions_per_minute": 10 }),
    );
    assert_eq!(status, 200);
    assert_eq!(v2, 2);

    println!("\n== (b) device A pulls + applies v2; device B does nothing (the drift exception) ==");
    set_home(&device_a_home);
    policy::pull_and_apply(&target_a).expect("device A pull_and_apply v2");
    let t1 = now_ms();
    compile_and_push((t0 + 60_000, t1 + 60_000), t1 + 60_000, &device_a_home, &target_a);

    // ── operator: generate the org-wide evidence export ──────────────────────────────────────────
    set_home(&operator_home);
    println!("\n== (c) operator: fleet_org_evidence — the org-wide, envelope-native evidence export ==");
    let evidence = fleet::fleet_org_evidence("P5 Manual Proof — Fleet".into(), Some(60 * 60 * 1000))
        .expect("fleet_org_evidence");

    println!("\n===== GENERATED MARKDOWN REPORT (doc 22 §9) =====\n{}\n===== END REPORT =====", evidence.markdown);

    assert_eq!(evidence.devices_total, 2, "both devices reported at least one envelope");
    assert_eq!(evidence.latest_bundle_version, Some(2));
    assert_eq!(evidence.drift.len(), 1, "exactly device B is behind the published baseline");
    assert!(
        evidence.drift[0].contains("v1") && evidence.drift[0].contains("v2"),
        "drift citation names the version gap: {}",
        evidence.drift[0]
    );

    // The CM-family controls (3.4.1/3.4.2) are the NEW ones this phase unlocks (doc 22 §9 item 3).
    let c341 = evidence.controls.iter().find(|c| c.control.starts_with("3.4.1")).expect("3.4.1 present");
    assert_eq!(c341.status, kriya_console_lib::control_plane::fleet_evidence::ControlStatus::Partial);
    let c342 = evidence.controls.iter().find(|c| c.control.starts_with("3.4.2")).expect("3.4.2 present");
    assert_eq!(c342.status, kriya_console_lib::control_plane::fleet_evidence::ControlStatus::Partial);

    // Doc 21 honesty norms, carried forward (doc 22 §9 item 4).
    let c339 = evidence.controls.iter().find(|c| c.control.starts_with("3.3.9")).expect("3.3.9 present");
    assert_eq!(c339.status, kriya_console_lib::control_plane::fleet_evidence::ControlStatus::Gap);
    assert!(evidence.markdown.contains("evidence, not a certification"));

    println!(
        "\n✅ P5 end-to-end proof passed: real kriyad + 2 real devices -> publish v1 (both apply) -> \
         publish v2 (only device A applies) -> fleet_org_evidence reports devicesTotal=2, latest \
         bundle v2, ONE real named drift exception for device B, the NEW CM-family controls (3.4.1/ \
         3.4.2) computed from locally re-verified envelope data, and the doc-21 honesty norms (3.3.9 \
         permanent gap, verbatim footer) carried forward."
    );

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&ca_dir);
    let _ = std::fs::remove_dir_all(&operator_home);
    let _ = std::fs::remove_dir_all(&device_a_home);
    let _ = std::fs::remove_dir_all(&device_b_home);
    let _ = std::fs::remove_file(&db_path);
}
