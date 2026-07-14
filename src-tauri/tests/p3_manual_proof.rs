//! P3 end-to-end proof (not part of the CI suite) — self-contained: builds + spawns a REAL `kriyad`
//! with real dev mTLS certs, then drives the REAL Tauri commands (operator side) and the REAL device
//! downlink functions (device side) against it. Prints everything so the session log is the artifact.
//! Unlike `fleet_manual_proof.rs`/`p2_verification_proof.rs` (which need a kriyad already running with
//! externally-generated certs), this test spawns kriyad itself — run with:
//!   cargo test --features control-plane --test p3_manual_proof -- --ignored --nocapture
//!
//! **One documented substitution:** the org policy key normally lives in the OS keychain
//! (`org_key::org_policy_keygen`/`sign_with_org_key`) — verified for real, independently, by
//! `org_key::tests::keychain_round_trips_a_seed` (confirmed passing against the REAL macOS keychain in
//! this same environment, `--nocapture`'d with no "skip" message). THIS proof swaps `$HOME` between an
//! "operator" and a "device" identity to exercise both roles in one process, and macOS keychain
//! resolution follows `$HOME` (`NSHomeDirectory`) — a synthetic temp `$HOME` has no
//! `Library/Keychains/`, so `Security.framework` genuinely can't find a default keychain there. That is
//! a property of THIS test's role-switching technique, not of the shipped `org_key.rs` code (which a
//! real user's real `$HOME` satisfies trivially). Rather than mutate the real environment's actual
//! default keychain (a shared-state side effect this proof should not risk), this test constructs the
//! org key directly and calls the SAME `kriya_verify::sign_policy_bundle`/`fleet_client::publish_policy`
//! functions `org_key::sign_with_org_key`/`fleet::fleet_publish_policy` call internally — every other
//! step (mTLS connect, kriyad ingest/verify/store/serve, device pull/verify/apply/anti-rollback,
//! tamper rejection, envelope `policy_state`) runs through the REAL, unmodified production functions.
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
    // this file is src-tauri/tests/p3_manual_proof.rs
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

/// Stand-in for `fleet::fleet_publish_policy` — IDENTICAL logic (fetch the latest visible version,
/// compute `next_version`, build the `PolicyBundle`, sign, POST), the ONLY difference being the key
/// comes from a `&SigningKey` this test holds directly instead of `org_key::load_org_signing_key()`'s
/// keychain lookup (see the file-level doc comment for why).
fn author_sign_publish(
    cfg: &fleet_client::FleetConfig,
    org_key: &SigningKey,
    policy_json: serde_json::Value,
    budgets_json: serde_json::Value,
    govern: Vec<kriya_verify::GovernDirective>,
    envelope_verbosity: &str,
) -> (u16, String, u64) {
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
        govern,
        envelope_verbosity: envelope_verbosity.to_string(),
        kill_switch: false,
    };
    let signed = kriya_verify::sign_policy_bundle(org_key, bundle);
    let body = serde_json::to_string(&signed).unwrap();
    let (status, resp) = fleet_client::publish_policy(cfg, &body).unwrap();
    (status, resp, next_version)
}

#[test]
#[ignore = "self-contained manual e2e proof: builds + spawns a real kriyad; see file header"]
fn p3_end_to_end_policy_downlink_proof() {
    let root = workspace_root(); // src-tauri/
    let ca_dir = std::env::temp_dir().join(format!("kriya-p3-ca-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ca_dir);

    println!("== build kriyad + generate dev mTLS certs ==");
    run(
        Command::new("cargo").current_dir(&root).args(["build", "-q", "-p", "kriya-aggregator"]),
        "cargo build kriya-aggregator",
    );
    run(
        Command::new("bash")
            .arg(root.join("crates/kriya-aggregator/scripts/kriyd-ca.sh"))
            .arg(&ca_dir)
            .arg("2"),
        "kriyd-ca.sh",
    );
    assert!(ca_dir.join("client-1.pem").exists() && ca_dir.join("client-2.pem").exists());

    let db_path = std::env::temp_dir().join(format!("kriya-p3-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let bind = "127.0.0.1:8466";
    let kriyad_bin = root.join("target/debug/kriyad");
    let license_path = root.join("crates/kriya-aggregator/fixtures/dev-control-plane-license.json");

    // The org key normally lives in the OS keychain — see the file-level doc comment for why this
    // proof constructs it directly instead.
    let org_key = SigningKey::from_bytes(&[0xA5u8; 32]);
    let org_key_pub_hex = hex::encode(org_key.verifying_key().to_bytes());
    std::fs::write(ca_dir.join("org-policy.pub"), format!("{org_key_pub_hex}\n")).unwrap();

    println!("== spawn kriyad (mTLS, {bind}), org-policy.pub pre-distributed to its CA dir ==");
    let child = Command::new(&kriyad_bin)
        .env("KRIYAD_BIND", bind)
        .env("KRIYAD_DB", &db_path)
        .env("KRIYAD_LICENSE", &license_path)
        .env("KRIYAD_CA_DIR", &ca_dir)
        // This proof predates P6 role-stamped certs — its `kriyd-ca.sh <dir> N` certs are role-LESS,
        // so it runs in the documented legacy-grace compensating mode (doc 22 §11-B2), which also
        // exercises that grace path end-to-end.
        .env("KRIYAD_ALLOW_LEGACY_CERTS", "1")
        .spawn()
        .expect("spawn kriyad");
    let _kriyad = KriyadProcess { child };

    // ── OPERATOR home: fleet-console + control-plane license, connect, author, publish ─────────────
    let operator_home = std::env::temp_dir().join(format!("kriya-p3-operator-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&operator_home);
    std::fs::create_dir_all(operator_home.join(".kriya/console")).unwrap();
    set_home(&operator_home);

    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present (dev-keys/issuer-dev-seed.hex)");
        return;
    };
    let operator_license = dev_issue(LicensePayload {
        holder: "P3 Manual Proof — Operator".into(),
        tier: "pro".into(),
        features: vec!["fleet-console".into(), "control-plane".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "p3-proof-operator".into(),
    })
    .expect("mint operator license");
    std::fs::write(
        operator_home.join(".kriya/console/license.json"),
        serde_json::to_string(&operator_license).unwrap(),
    )
    .unwrap();

    println!("\n== (a) operator: fleet_connect over real mTLS ==");
    let server_url = format!("https://{bind}");
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
    println!("fleet_connect: OK — real mTLS handshake against a live kriyad");
    println!("org_policy_pub = {org_key_pub_hex}  (constructed directly — see file header)");

    let operator_cfg = fleet_client::FleetConfig {
        server_url: server_url.clone(),
        client_identity_pem: operator_home.join(".kriya/console/fleet-identity.pem"),
        server_ca_pem: ca_dir.join("ca.pem"),
    };

    println!("\n== (a) operator: author + sign + publish v1 ==");
    let (status, resp, v1_version) = author_sign_publish(
        &operator_cfg,
        &org_key,
        serde_json::json!({ "rules": [{ "action": "delete_*", "allow": false }, { "action": "*", "allow": true }] }),
        serde_json::json!({ "max_actions_per_minute": 30 }),
        vec![kriya_verify::GovernDirective { target: "claude-code".into(), action: "wire".into() }],
        "extended",
    );
    println!("POST /v1/policy(v1) -> HTTP {status}: {resp}");
    assert_eq!(status, 200);
    assert_eq!(v1_version, 1);

    let v1_raw = fleet_client::fetch_policy_preview(&operator_cfg, "_fleet_console_preview_", None)
        .unwrap()
        .expect("v1 bundle exists");
    println!("fetched-back v1 bundle: {v1_raw}");

    // ── DEVICE home: enrolled, pinned to the operator's org key, pulls + applies ─────────────────
    let device_home = std::env::temp_dir().join(format!("kriya-p3-device-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&device_home);
    std::fs::create_dir_all(device_home.join(".kriya/console")).unwrap();
    std::fs::write(
        device_home.join(".kriya/console/enrollment.json"),
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
    set_home(&device_home);

    // push::PushTarget expects ONE concatenated PEM (cert+key) — build it once for this proof.
    let device_identity_pem = device_home.join(".kriya/console/device-identity.pem");
    std::fs::write(
        &device_identity_pem,
        format!(
            "{}\n{}",
            read_file(&ca_dir.join("client-2.pem")),
            read_file(&ca_dir.join("client-2.key"))
        ),
    )
    .unwrap();
    let device_target = push::PushTarget {
        server_url: server_url.clone(),
        client_identity_pem: device_identity_pem,
        server_ca_pem: ca_dir.join("ca.pem"),
    };

    println!("\n== (b) device: pull_and_apply v1 (verify + anti-rollback + apply) ==");
    policy::pull_and_apply(&device_target).expect("pull_and_apply v1");
    let state_after_v1 = policy::load_state();
    assert_eq!(state_after_v1.last_applied_version, Some(1));
    println!("applied version: {:?}", state_after_v1.last_applied_version);
    println!("applied policy YAML:\n{}", read_file(&enrollment_policy_path()));
    let events_after_v1 = read_file(&policy_events_path());
    println!("policy events log:\n{events_after_v1}");
    assert!(events_after_v1.contains("kriya.policy.applied"));

    println!("\n== (c) next envelope carries policy_state ==");
    compiler::compile_once((0, 60_000), 60_000).expect("compile_once");
    let outbox = read_file(&device_home.join(".kriya/console/outbox.jsonl"));
    let last_envelope_line = outbox.lines().last().expect("an envelope was emitted");
    let last_envelope: serde_json::Value = serde_json::from_str(last_envelope_line).unwrap();
    println!("latest envelope policy_state: {}", last_envelope["envelope"]["policy_state"]);
    assert_eq!(last_envelope["envelope"]["policy_state"]["version"], 1);
    assert!(kriya_verify::verify_envelope(&last_envelope).is_ok());

    // ── back to OPERATOR: publish v2 ─────────────────────────────────────────────────────────────
    set_home(&operator_home);
    println!("\n== (a) operator: publish v2 (a policy change) ==");
    let (status, resp, v2_version) = author_sign_publish(
        &operator_cfg,
        &org_key,
        serde_json::json!({ "rules": [{ "action": "*", "allow": false }] }),
        serde_json::json!({ "max_actions_per_minute": 10 }),
        vec![kriya_verify::GovernDirective { target: "claude-code".into(), action: "wire".into() }],
        "standard",
    );
    println!("POST /v1/policy(v2) -> HTTP {status}: {resp}");
    assert_eq!(status, 200);
    assert_eq!(v2_version, 2);

    // ── DEVICE: pull v2, show the diff, then prove anti-rollback + tamper rejection ─────────────
    set_home(&device_home);
    let policy_before_v2 = read_file(&enrollment_policy_path());
    println!("\n== (b) device: pull_and_apply v2 — policy file diff ==");
    policy::pull_and_apply(&device_target).expect("pull_and_apply v2");
    let policy_after_v2 = read_file(&enrollment_policy_path());
    println!("--- policy BEFORE v2 ---\n{policy_before_v2}");
    println!("--- policy AFTER v2 ---\n{policy_after_v2}");
    assert_ne!(policy_before_v2, policy_after_v2, "the policy file genuinely changed");
    assert_eq!(policy::load_state().last_applied_version, Some(2));

    compiler::compile_once((60_000, 120_000), 120_000).expect("compile_once after v2");
    let outbox2 = read_file(&device_home.join(".kriya/console/outbox.jsonl"));
    let last2: serde_json::Value = serde_json::from_str(outbox2.lines().last().unwrap()).unwrap();
    println!("next envelope policy_state after v2: {}", last2["envelope"]["policy_state"]);
    assert_eq!(last2["envelope"]["policy_state"]["version"], 2);

    println!("\n== (e) anti-rollback: replaying the OLD v1 bundle after v2 is applied ==");
    std::fs::write(device_home.join("v1-replay.json"), &v1_raw).unwrap();
    let replay_outcome =
        policy::policy_apply_file(device_home.join("v1-replay.json").to_string_lossy().into_owned())
            .expect("policy_apply_file must not error on a stale-but-honestly-signed bundle");
    println!("replaying v1 after v2 applied -> {replay_outcome:?}");
    assert!(replay_outcome.is_none(), "a lower version must NOT apply — anti-rollback");
    assert_eq!(policy::load_state().last_applied_version, Some(2), "device stays on v2");

    println!("\n== (d) tamper: forged bundle rejected by BOTH kriyad ingest and the device ==");
    let mut tampered: serde_json::Value = serde_json::from_str(&v1_raw).unwrap();
    tampered["bundle"]["policy"]["rules"][0]["allow"] = serde_json::json!(true); // flip after signing
    let tampered_str = tampered.to_string();

    let device_verdict = policy::verify_and_apply(&tampered_str, &org_key_pub_hex);
    println!("device verify_and_apply(tampered) -> {:?}", device_verdict.as_ref().err());
    assert!(device_verdict.is_err(), "the device must reject the tampered bundle");

    let (status, resp) = fleet_client::publish_policy(&operator_cfg, &tampered_str).unwrap();
    println!("kriyad POST /v1/policy(tampered) -> HTTP {status}: {resp}");
    assert_eq!(status, 400, "kriyad ingest must also reject the tampered bundle");

    println!(
        "\n✅ P3 end-to-end proof passed: author → publish v1 → device pull/verify/apply \
         → policy_state on the next envelope → publish v2 → diff shown → anti-rollback → tamper \
         rejected by both kriyad and the device."
    );

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&ca_dir);
    let _ = std::fs::remove_dir_all(&operator_home);
    let _ = std::fs::remove_dir_all(&device_home);
    let _ = std::fs::remove_file(&db_path);
}

fn enrollment_policy_path() -> PathBuf {
    kriya_console_lib::govern::agent_policy_path()
}
fn policy_events_path() -> PathBuf {
    kriya_console_lib::audit::default_audit_dir().join("kriya-console-policy.jsonl")
}
