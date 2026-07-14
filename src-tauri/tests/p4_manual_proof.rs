//! P4 end-to-end proof (not part of the CI suite) — self-contained, mirrors `p3_manual_proof.rs`'s
//! technique exactly (real `kriyad` subprocess, real dev mTLS certs, real Tauri commands + device
//! functions; the org key constructed directly rather than pulled from the OS keychain — see that
//! file's header for why that substitution is safe). This proof adds the ONE thing P3 didn't need:
//! actually POSTing device envelopes to a live kriyad (`push::push_envelopes`), because P4's
//! `/v1/coverage` drift fields (`applied_policy_version`/`applied_bundle_hash`) are read from each
//! device's LATEST STORED envelope — proving them requires envelopes that really reached the server,
//! not just ones sitting in a local outbox.
//!
//! Scenario (doc 22 v2.1 §9-CM's acceptance line, run for real):
//!   publish v1 -> both devices pull + apply + report -> publish v2 -> only device A pulls ->
//!   coverage shows "one green one amber" -> device B (the laggard) stops reporting entirely ->
//!   once `KRIYAD_SILENT_AFTER_MS` elapses, B flips to silent+behind (the red case) while A, which
//!   keeps reporting, stays current+green.
//!
//! Run with:
//!   cargo test --features control-plane --test p4_manual_proof -- --ignored --nocapture
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")) // src-tauri/
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

/// Same stand-in as `p3_manual_proof::author_sign_publish` — see that file's header for why the org
/// key is constructed directly here instead of pulled from the OS keychain. Also returns
/// `policy::bundle_hash(&bundle)` — the SAME function the device side calls on apply — so the caller
/// can assert kriyad's echoed `applied_bundle_hash` against a real, independently-computed content
/// hash rather than merely against itself.
fn author_sign_publish(
    cfg: &fleet_client::FleetConfig,
    org_key: &SigningKey,
    policy_json: serde_json::Value,
    budgets_json: serde_json::Value,
) -> (u16, String, u64, String) {
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
        io_verbosity: "off".into(),
        purpose_statement: None,
    };
    let hash = policy::bundle_hash(&bundle);
    let signed = kriya_verify::sign_policy_bundle(org_key, bundle);
    let body = serde_json::to_string(&signed).unwrap();
    let (status, resp) = fleet_client::publish_policy(cfg, &body).unwrap();
    (status, resp, next_version, hash)
}

/// Device home setup: enrollment.json pinned to `org_key_pub_hex`, transport identity from
/// `client-N.pem`/`.key`. Returns the device's outbox path and its `push::PushTarget`.
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

/// `compile_once` only writes the signed envelope to the device's LOCAL outbox (doc 22 §2.7's
/// online-transport wiring is Phase-3 scope — see `policy.rs`'s own "Scope note", which this proof
/// mirrors exactly, the same way `p3_manual_proof` stands in for `org_key::sign_with_org_key`). This
/// proof needs the envelope to actually reach kriyad (P4's coverage fields are read from STORED
/// envelopes), so — like P3 constructing the org key directly — it drives the real
/// `push::push_envelopes` function itself. `INSERT OR IGNORE` on `(device_pub, seq)` (kriyad's
/// `store.rs`) makes re-posting the whole outbox on every call safe: already-seen lines are no-ops.
fn compile_and_push(window: (u64, u64), produced_ms: u64, home: &Path, target: &push::PushTarget) {
    compiler::compile_once(window, produced_ms).expect("compile_once");
    let outbox = read_file(&home.join(".kriya/console/outbox.jsonl"));
    let ndjson = outbox.trim_end();
    assert!(!ndjson.is_empty(), "compile_once must have produced at least one line");
    let report = push::push_envelopes(target, &format!("{ndjson}\n")).expect("push_envelopes");
    println!("push_envelopes -> {report}");
}

fn last_envelope(home: &Path) -> serde_json::Value {
    let outbox = read_file(&home.join(".kriya/console/outbox.jsonl"));
    let last_line = outbox.lines().last().expect("outbox has at least one line");
    serde_json::from_str(last_line).unwrap()
}

fn last_envelope_policy_state(home: &Path) -> serde_json::Value {
    last_envelope(home)["envelope"]["policy_state"].clone()
}

/// The device's own public key, as carried (and self-verified: `device_pub == public_key`) in its own
/// last envelope — read directly from this device's home rather than guessed from a shared coverage
/// listing, so device A/B identity in this test is never ambiguous even though both apply the same v1
/// bundle first.
fn last_envelope_device_pub(home: &Path) -> String {
    last_envelope(home)["envelope"]["device_pub"]
        .as_str()
        .expect("envelope carries device_pub")
        .to_string()
}

fn find_row<'a>(rows: &'a [fleet_client::DeviceCoverage], device_pub: &str) -> &'a fleet_client::DeviceCoverage {
    rows.iter()
        .find(|r| r.device_pub == device_pub)
        .unwrap_or_else(|| panic!("no coverage row for {device_pub}"))
}

#[test]
#[ignore = "self-contained manual e2e proof: builds + spawns a real kriyad; see file header"]
fn p4_end_to_end_drift_view_proof() {
    let root = workspace_root();
    let ca_dir = std::env::temp_dir().join(format!("kriya-p4-ca-{}", std::process::id()));
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
            .arg("3"), // client-1 = operator, client-2 = device A, client-3 = device B
        "kriyd-ca.sh",
    );
    assert!(ca_dir.join("client-3.pem").exists());

    let db_path = std::env::temp_dir().join(format!("kriya-p4-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let bind = "127.0.0.1:8467";
    let kriyad_bin = root.join("target/debug/kriyad");
    let license_path = root.join("crates/kriya-aggregator/fixtures/dev-control-plane-license.json");

    let org_key = SigningKey::from_bytes(&[0x5Au8; 32]);
    let org_key_pub_hex = hex::encode(org_key.verifying_key().to_bytes());
    std::fs::write(ca_dir.join("org-policy.pub"), format!("{org_key_pub_hex}\n")).unwrap();

    // A SHORT silent threshold (doc 22 §B.3.1's pilot default is 3h — see `config.rs`'s
    // `KRIYAD_SILENT_AFTER_MS`) is what makes "stop the laggard -> silent" demonstrable in a test run
    // rather than a real multi-hour wait. Nothing about kriyad's silent-detection LOGIC changes; only
    // the threshold is dialed down for this proof. Long enough that the real HTTP round trips earlier
    // in this same test (both devices pulling/applying/pushing v1, then v2) don't themselves cross it.
    let silent_after_ms: u64 = 8_000;
    println!("== spawn kriyad (mTLS, {bind}), KRIYAD_SILENT_AFTER_MS={silent_after_ms} ==");
    let child = Command::new(&kriyad_bin)
        .env("KRIYAD_BIND", bind)
        .env("KRIYAD_DB", &db_path)
        .env("KRIYAD_LICENSE", &license_path)
        .env("KRIYAD_CA_DIR", &ca_dir)
        .env("KRIYAD_SILENT_AFTER_MS", silent_after_ms.to_string())
        // Predates P6 role-stamped certs (its certs are role-less) → documented legacy-grace mode.
        .env("KRIYAD_ALLOW_LEGACY_CERTS", "1")
        .spawn()
        .expect("spawn kriyad");
    let _kriyad = KriyadProcess { child };

    // ── OPERATOR home ────────────────────────────────────────────────────────────────────────────
    let operator_home = std::env::temp_dir().join(format!("kriya-p4-operator-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&operator_home);
    std::fs::create_dir_all(operator_home.join(".kriya/console")).unwrap();
    set_home(&operator_home);

    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present (dev-keys/issuer-dev-seed.hex)");
        return;
    };
    let operator_license = dev_issue(LicensePayload {
        holder: "P4 Manual Proof — Operator".into(),
        tier: "pro".into(),
        features: vec!["fleet-console".into(), "control-plane".into()],
        issued_ms: 1,
        expires_ms: None,
        license_id: "p4-proof-operator".into(),
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
    let (status, _resp, v1, v1_hash) = author_sign_publish(
        &operator_cfg,
        &org_key,
        serde_json::json!({ "rules": [{ "action": "*", "allow": true }] }),
        serde_json::json!({ "max_actions_per_minute": 30 }),
    );
    assert_eq!(status, 200);
    assert_eq!(v1, 1);
    println!("published v1, content hash = {v1_hash}");

    // ── device A + device B homes: both enroll, pin the same org key ───────────────────────────────
    let device_a_home = std::env::temp_dir().join(format!("kriya-p4-device-a-{}", std::process::id()));
    let device_b_home = std::env::temp_dir().join(format!("kriya-p4-device-b-{}", std::process::id()));
    let target_a = setup_device_home(&device_a_home, &server_url, &org_key_pub_hex, &ca_dir, 2);
    let target_b = setup_device_home(&device_b_home, &server_url, &org_key_pub_hex, &ca_dir, 3);

    println!("\n== (b) device A: pull_and_apply v1, compile + push envelope ==");
    set_home(&device_a_home);
    policy::pull_and_apply(&target_a).expect("device A pull_and_apply v1");
    compile_and_push((0, 60_000), 60_000, &device_a_home, &target_a);
    let a_policy_state_v1 = last_envelope_policy_state(&device_a_home);
    println!("device A envelope policy_state: {a_policy_state_v1}");
    assert_eq!(a_policy_state_v1["version"], 1);
    assert_eq!(a_policy_state_v1["bundle_hash"], v1_hash);
    let device_a_pub = last_envelope_device_pub(&device_a_home);

    println!("\n== (b) device B: pull_and_apply v1, compile + push envelope ==");
    set_home(&device_b_home);
    policy::pull_and_apply(&target_b).expect("device B pull_and_apply v1");
    compile_and_push((0, 60_000), 60_000, &device_b_home, &target_b);
    let b_policy_state_v1 = last_envelope_policy_state(&device_b_home);
    println!("device B envelope policy_state: {b_policy_state_v1}");
    assert_eq!(b_policy_state_v1["version"], 1);
    assert_eq!(b_policy_state_v1["bundle_hash"], v1_hash);
    let device_b_pub = last_envelope_device_pub(&device_b_home);
    assert_ne!(device_a_pub, device_b_pub, "device A and device B must be distinct identities");

    // ── operator: coverage after both devices report v1 — both should be "current" + applied==latest
    set_home(&operator_home);
    let cov = fleet::fleet_coverage().expect("fleet_coverage after v1");
    println!("\n== coverage after v1 (both devices reported) ==\n{}", serde_json::to_string_pretty(&cov).unwrap());
    assert_eq!(cov.len(), 2, "both devices have reported at least one envelope");
    for row in &cov {
        assert_eq!(row.status, "current");
        assert_eq!(row.applied_policy_version, Some(1));
        assert_eq!(row.latest_bundle_version, Some(1));
        assert_eq!(
            row.applied_bundle_hash.as_deref(),
            Some(v1_hash.as_str()),
            "kriyad's echoed hash must match the real v1 bundle content hash, not just itself"
        );
        println!(
            "  {} -> applied v{:?} == latest v{:?}, hash matches  => GREEN (both in sync)",
            row.device_pub, row.applied_policy_version, row.latest_bundle_version
        );
    }

    println!("\n== (a) operator: publish v2 (only device A will pull it) ==");
    let (status, _resp, v2, v2_hash) = author_sign_publish(
        &operator_cfg,
        &org_key,
        serde_json::json!({ "rules": [{ "action": "delete_*", "allow": false }, { "action": "*", "allow": true }] }),
        serde_json::json!({ "max_actions_per_minute": 10 }),
    );
    assert_eq!(status, 200);
    assert_eq!(v2, 2);

    println!("\n== (b) device A pulls + applies v2; device B does nothing (the laggard) ==");
    set_home(&device_a_home);
    policy::pull_and_apply(&target_a).expect("device A pull_and_apply v2");
    compile_and_push((60_000, 120_000), 120_000, &device_a_home, &target_a);
    let a_policy_state_v2 = last_envelope_policy_state(&device_a_home);
    assert_eq!(a_policy_state_v2["version"], 2);
    assert_eq!(a_policy_state_v2["bundle_hash"], v2_hash);

    set_home(&operator_home);
    let cov = fleet::fleet_coverage().expect("fleet_coverage after v2 (one pulled, one didn't)");
    println!(
        "\n== coverage after v2 — one pulls, one doesn't ==\n{}",
        serde_json::to_string_pretty(&cov).unwrap()
    );
    let row_a = find_row(&cov, &device_a_pub);
    assert_eq!(row_a.status, "current");
    assert_eq!(row_a.applied_policy_version, Some(2));
    assert_eq!(row_a.latest_bundle_version, Some(2));
    assert_eq!(row_a.applied_bundle_hash.as_deref(), Some(v2_hash.as_str()));
    println!("  device A: applied v2 == latest v2, hash matches, status=current  => GREEN");

    let row_b = find_row(&cov, &device_b_pub);
    assert_eq!(row_b.status, "current", "not enough time has passed for B to be silent yet");
    assert_eq!(row_b.applied_policy_version, Some(1), "B never pulled v2");
    assert_eq!(row_b.latest_bundle_version, Some(2));
    assert_eq!(
        row_b.applied_bundle_hash.as_deref(),
        Some(v1_hash.as_str()),
        "B is still frozen on v1's hash, not v2's"
    );
    println!(
        "  device B: applied v1 < latest v2, status=current  => AMBER \"behind (v1 < v2)\""
    );

    println!("\n== (c) stop the laggard: device B posts nothing further; device A keeps reporting ==");
    std::thread::sleep(Duration::from_millis(silent_after_ms + 1_500));
    // Device A refreshes its own last_seen so it stays "current" while B ages past the threshold —
    // this is what makes the demo show ONE device going silent, not both.
    set_home(&device_a_home);
    compile_and_push((120_000, 180_000), 180_000, &device_a_home, &target_a);

    set_home(&operator_home);
    let cov = fleet::fleet_coverage().expect("fleet_coverage after the laggard goes silent");
    println!(
        "\n== coverage after device B goes silent ==\n{}",
        serde_json::to_string_pretty(&cov).unwrap()
    );
    let row_a = find_row(&cov, &device_a_pub);
    assert_eq!(row_a.status, "current", "device A kept reporting, so it stays current");
    assert_eq!(row_a.applied_policy_version, Some(2));
    assert_eq!(row_a.latest_bundle_version, Some(2));
    println!("  device A: still applied v2 == latest v2, status=current  => GREEN");

    let row_b = find_row(&cov, &device_b_pub);
    assert_eq!(row_b.status, "silent", "device B exceeded the (short, configured) silent threshold");
    assert_eq!(row_b.applied_policy_version, Some(1), "B is still frozen on v1");
    assert_eq!(row_b.latest_bundle_version, Some(2));
    println!(
        "  device B: status=silent AND applied v1 < latest v2  => RED \"silent + behind\" (the tamper/dormancy story)"
    );

    println!("\n== (d) local re-verification is the proof, kriyad's coverage row is only the hint ==");
    let evidence_b = fleet::fleet_device_evidence(device_b_pub.clone(), 0, 100).expect("fleet_device_evidence B");
    assert!(!evidence_b.envelopes.is_empty());
    assert!(
        evidence_b.envelopes.iter().all(|e| e.verified),
        "every envelope kriyad returns for device B must independently re-verify locally"
    );
    let last_b_state = evidence_b
        .envelopes
        .last()
        .and_then(|e| serde_json::from_str::<serde_json::Value>(&e.raw).ok())
        .map(|v| v["envelope"]["policy_state"].clone())
        .expect("device B's last envelope carries policy_state");
    println!("device B's LAST RE-VERIFIED envelope policy_state: {last_b_state}");
    assert_eq!(
        last_b_state["version"], 1,
        "the locally re-verified envelope confirms kriyad's hint (applied_policy_version=1) independently"
    );

    println!(
        "\n✅ P4 end-to-end proof passed: publish v1 -> both devices apply+report (green/green) -> \
         publish v2 -> only device A pulls (green/amber) -> device B stops reporting -> once the \
         (configured, short) silent threshold elapses, device B flips to silent+behind (red) while \
         device A, which kept reporting, stays current+green -- and the verdict was confirmed by \
         locally re-verifying device B's actual stored envelope, not by trusting kriyad's coverage hint."
    );

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&ca_dir);
    let _ = std::fs::remove_dir_all(&operator_home);
    let _ = std::fs::remove_dir_all(&device_a_home);
    let _ = std::fs::remove_dir_all(&device_b_home);
    let _ = std::fs::remove_file(&db_path);
}
