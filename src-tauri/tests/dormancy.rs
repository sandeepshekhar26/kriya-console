//! Dormancy firewall (1.4 ⭐) — the NEGATIVE half of "the free offline tier stays byte-for-byte
//! unchanged." Only built/run under `--features control-plane` on unix; the BUILD-TIME half (a default
//! build links no reqwest/rustls) is `scripts/check-dormancy-build.sh`. The POSITIVE control
//! (licensed+enrolled → evidence.key / pepper / outbox appear) lands in 1.18, once the Compiler exists.
#![cfg(all(feature = "control-plane", unix))]

use kriya_console_lib::control_plane::enrollment::control_plane_active;

/// With no license and no enrollment.json (a clean, empty HOME), the control plane is INERT:
/// `control_plane_active()` is false and no control-plane artifacts are minted under `~/.kriya/console`.
#[test]
fn dormant_without_license_and_enrollment() {
    let tmp = std::env::temp_dir().join(format!("kriya-dormancy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    // Point HOME at the empty temp dir so console_dir() (license + enrollment) resolves there, instead
    // of the developer's real ~/.kriya. Safe: this integration binary runs exactly one test.
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
