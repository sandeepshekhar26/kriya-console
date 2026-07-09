//! Dormancy firewall (1.4 ⭐) — the NEGATIVE half of "the free offline tier stays byte-for-byte
//! unchanged." Only built/run under `--features control-plane` on unix; the BUILD-TIME half (a default
//! build links no reqwest/rustls) is `scripts/check-dormancy-build.sh`. The POSITIVE control
//! (licensed+enrolled → evidence.key / pepper / outbox appear) landed in `tests/positive_control.rs`
//! (1.18, once the Compiler existed).
//!
//! P0 (fleet cockpit) extends BOTH halves along the SAME two mechanisms — there is no third
//! technique (no symbol/`nm`/`strings` inspection anywhere in this repo, by design: the compile-time
//! module gate already makes the question moot):
//!   * build-time: `fleet_client`/`fleet` are declared inside `control_plane.rs`'s module tree, which
//!     itself hangs off the single `#[cfg(feature = "control-plane")] pub mod control_plane;` in
//!     `lib.rs` (1.1) — a default build's compiler input simply does not contain these modules, so
//!     there is no symbol for `fleet_connect`/`fleet_coverage`/`fleet_device_evidence` to compile to.
//!     `fleet_client`'s outbound calls go through `reqwest` (the SAME optional, `control-plane`-only
//!     dependency `push.rs` already uses — BC-1: one dormancy gate covers both push AND pull), so
//!     `check-dormancy-build.sh`'s existing `reqwest`/`rustls` grep already covers fleet pull traffic
//!     with no new dependency name to add.
//!   * runtime: unlike `control_plane_active()` (which gates the device-side Compiler on BOTH a
//!     `control-plane` license AND `enrollment.json`), the fleet cockpit's gate is the single
//!     `license::require_fleet_console()` check every one of the three new commands calls FIRST —
//!     proven as a POSITIVE control below (a control-plane BUILD without a `fleet-console` license
//!     grant still cleanly refuses all three commands; see also `tests/positive_control.rs` for the
//!     mirror-image "licensed → the gate opens" proof).
#![cfg(all(feature = "control-plane", unix))]

use kriya_console_lib::control_plane::enrollment::control_plane_active;
use kriya_console_lib::control_plane::fleet;
use kriya_console_lib::license::{dev_issue, dev_issuer_seed, LicensePayload};

/// Guards every `$HOME`-mutating test in this file from racing its siblings — this binary now runs
/// FOUR such tests (it used to run exactly one, per the older comment this replaces), and `cargo test`
/// runs tests within one binary on parallel threads by default. Same pattern as `govern.rs`'s own
/// `ENV_LOCK` for its `$HOME`-sandboxed tests.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// With no license and no enrollment.json (a clean, empty HOME), the control plane is INERT:
/// `control_plane_active()` is false and no control-plane artifacts are minted under `~/.kriya/console`.
#[test]
fn dormant_without_license_and_enrollment() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join(format!("kriya-dormancy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    // Point HOME at the empty temp dir so console_dir() (license + enrollment) resolves there, instead
    // of the developer's real ~/.kriya. Safe under ENV_LOCK (see above).
    std::env::set_var("HOME", &tmp);

    assert!(
        !control_plane_active(),
        "a clean env (no license, no enrollment) must NOT activate the control plane"
    );

    // No control-plane artifacts were minted (there is no Compiler yet, 1.13+) — this guards the gate,
    // not merely an unexercised path.
    let console = tmp.join(".kriya").join("console");
    for artifact in ["evidence.key", "pepper", "outbox"] {
        assert!(
            !console.join(artifact).exists(),
            "a dormant console must not create {artifact}"
        );
    }

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// With no license installed at all (a clean, empty HOME — the same negative-control shape as
/// [`dormant_without_license_and_enrollment`]), every fleet-cockpit command refuses cleanly via
/// `require_fleet_console()` — never a panic, never a silent success, and (for `fleet_connect`)
/// never a network call: no `fleet.json` / `fleet-identity.pem` is written under `~/.kriya/console`.
#[test]
fn fleet_commands_dormant_without_a_fleet_console_license() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join(format!("kriya-dormancy-fleet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    std::env::set_var("HOME", &tmp);

    let err = fleet::fleet_connect(
        "https://kriyad.invalid:8443".into(),
        "/nonexistent/ca.pem".into(),
        "/nonexistent/cert.pem".into(),
        "/nonexistent/key.pem".into(),
    )
    .expect_err("fleet_connect must refuse without a fleet-console license");
    assert!(
        err.contains("fleet-console") || err.contains("fleet cockpit"),
        "must be the license gate, not a network/file error: {err}"
    );
    assert!(fleet::fleet_coverage().is_err(), "fleet_coverage must refuse");
    assert!(
        fleet::fleet_device_evidence("devpub".into(), 0, 100).is_err(),
        "fleet_device_evidence must refuse"
    );

    // No control-plane artifacts were minted by the (refused) fleet_connect attempt — proves the
    // license gate runs BEFORE any filesystem/network I/O, not merely that the command returned an
    // error after doing work.
    let console = tmp.join(".kriya").join("console");
    for artifact in ["fleet.json", "fleet-identity.pem"] {
        assert!(
            !console.join(artifact).exists(),
            "a dormant fleet cockpit must not create {artifact}"
        );
    }

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// A valid `control-plane` license WITHOUT the `fleet-console` feature string still dormant for the
/// fleet cockpit (BC-2 — the two are independent grants; `control-plane` alone never implies
/// `fleet-console`). Skips without the dev issuer seed, mirroring every other dev-issued-license test.
#[test]
fn fleet_commands_dormant_with_control_plane_license_but_no_fleet_console_flag() {
    let Some(_) = dev_issuer_seed() else {
        eprintln!("skipping: no dev issuer seed present");
        return;
    };
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join(format!("kriya-dormancy-fleet-cp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let console = tmp.join(".kriya").join("console");
    std::fs::create_dir_all(&console).unwrap();
    std::env::set_var("HOME", &tmp);

    let token = dev_issue(LicensePayload {
        holder: "Acme Regulated Co".into(),
        tier: "pro".into(),
        features: vec!["control-plane".into()], // NOT fleet-console
        issued_ms: 1,
        expires_ms: None,
        license_id: "dormancy-fleet-cp".into(),
    })
    .expect("mint a control-plane-only license");
    std::fs::write(
        console.join("license.json"),
        serde_json::to_string(&token).unwrap(),
    )
    .unwrap();

    assert!(
        fleet::fleet_coverage().is_err(),
        "control-plane alone must not grant fleet-console"
    );
    assert!(
        fleet::fleet_device_evidence("devpub".into(), 0, 100).is_err(),
        "control-plane alone must not grant fleet-console"
    );

    std::env::remove_var("HOME");
    let _ = std::fs::remove_dir_all(&tmp);
}
