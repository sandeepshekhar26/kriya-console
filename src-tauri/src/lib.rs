//! Kriya Console — the compiled Rust backend of the on-device control-plane app (D-018).
//!
//! The webview (the existing React views) is a thin viewer; the value and the gate live here:
//! - [`audit`] — auto-discovers + tails `~/.kriya/audit/` and streams verified receipts to the UI;
//! - [`receipts`] — the authoritative, compiled Ed25519 receipt verifier (R20/R21 format);
//! - [`coverage`] — the Coverage Map: lane classification + the signed coverage-snapshot chain (W1);
//! - [`onboarding`] — bundled-gateway resolution, privacy panes, MCP-client config wiring;
//! - [`license`] — offline Ed25519 license verification (the paid gate, R29);
//! - [`paid`] — license-gated fleet correlation + compliance evidence, generated in Rust.

pub mod audit;
pub mod coverage;
pub mod govern;
pub mod license;
pub mod onboarding;
pub mod paid;
pub mod receipts;

// Control-plane device modules — compiled ONLY under the off-by-default `control-plane` feature
// (build-time dormancy, 1.1). `pub` so the dormancy integration test (1.4) can reach the gate; the
// whole subtree is absent from a default/free build.
#[cfg(feature = "control-plane")]
pub mod control_plane;

/// The ONE shared lock every `$HOME`-mutating unit test in this crate must take before touching the
/// process-global `HOME` env var. `cargo test` runs every module's unit tests within ONE binary on
/// parallel threads by default; a per-module `static ENV_LOCK` only serializes tests WITHIN that
/// module — it does nothing to stop `govern.rs`'s tests from racing `control_plane::policy`'s, since
/// each had its own independent mutex. This crate-wide lock is the actual fix (found live: P3 added
/// enough new `$HOME`-touching tests, e.g. `control_plane::policy`'s ~10, to make the pre-existing gap
/// trigger a real, reproducible failure in `control_plane::org_key`'s tests).
#[cfg(test)]
pub(crate) static HOME_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Build + run the Tauri app. On launch it starts the audit-dir watcher so the cockpit shows live
/// governance the moment the window opens.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            audit::spawn_watcher(app.handle().clone());
            // Coverage heartbeat (free tier): classify lanes every minute, sign a
            // `kriya.coverage.snapshot` on state change or daily — visible-by-absence liveness.
            coverage::spawn_heartbeat();
            // Control-plane Evidence Compiler — spawned ONLY in a feature build AND only when the
            // license grants `control-plane` AND the device is enrolled (the runtime dormancy gate;
            // the free build can't even reach this branch). No license/enrollment ⇒ inert.
            #[cfg(feature = "control-plane")]
            if control_plane::enrollment::control_plane_active() {
                control_plane::compiler::spawn();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Free: live monitor + verify (auto-discover + tail ~/.kriya/audit/).
            audit::audit_location,
            audit::read_audit,
            audit::read_audit_file,
            // Free: the Coverage Map (W1) — six lanes, three states, one signed heartbeat chain.
            coverage::coverage_status,
            // Free: onboarding (perms + MCP-client wiring; bundled gateway).
            onboarding::onboarding_status,
            onboarding::open_settings_pane,
            onboarding::list_candidate_apps,
            onboarding::wire_claude_config,
            // Free: govern-all (GA-0) — detect the governable surface + install/uninstall the hook.
            govern::governable_surface,
            govern::install_hook,
            govern::uninstall_hook,
            // Free: the Console-authored policy file every seam above wires via --policy (B0).
            govern::save_agent_policy,
            govern::load_agent_policy,
            // Free: govern-all orchestrator (GA-1) — preview → apply → revert, idempotent.
            govern::govern_preview,
            govern::govern_all,
            govern::ungovern_all,
            govern::ungovern,
            // License (R29).
            license::license_status,
            license::install_license,
            license::remove_license,
            // Paid (Rust, license-gated).
            paid::fleet_correlation,
            paid::export_compliance,
            // Fleet cockpit (P0, license-gated on `fleet-console` — separate from `control-plane`,
            // which gates the device-side subtree these commands live under). Present in the
            // generated handler ONLY in a control-plane build; a default/free build has neither the
            // `control_plane` module nor these three entries (BC-1).
            #[cfg(feature = "control-plane")]
            control_plane::fleet::fleet_connect,
            #[cfg(feature = "control-plane")]
            control_plane::fleet::fleet_coverage,
            #[cfg(feature = "control-plane")]
            control_plane::fleet::fleet_device_evidence,
            // Fleet cockpit (P3, license-gated on `fleet-console`) — org policy keygen (the operator's
            // signing identity for PolicyBundles; kriyad never holds it) + author/preview/publish.
            #[cfg(feature = "control-plane")]
            control_plane::org_key::org_policy_keygen,
            #[cfg(feature = "control-plane")]
            control_plane::fleet::fleet_policy_preview,
            #[cfg(feature = "control-plane")]
            control_plane::fleet::fleet_publish_policy,
            // Device policy downlink (P3) — air-gap apply. Gated on enrollment + a pinned org key, NOT
            // on `fleet-console` (a device-side act any enrolled device can do, not an operator-only one).
            #[cfg(feature = "control-plane")]
            control_plane::policy::policy_apply_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Kriya Console");
}
