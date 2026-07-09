//! Fleet cockpit Tauri IPC (P0) — the operator-facing commands over [`fleet_client`]'s outbound mTLS
//! pull client. Every command here calls [`crate::license::require_fleet_console`] FIRST, before any
//! network I/O or disk read of the connection config, so an unlicensed build fails fast and cleanly
//! (BC-1/positive-control) rather than leaking a network error or a "config not found" error that
//! would hint at functionality the license doesn't grant.
//!
//! Persisted operator connection config lives at `~/.kriya/console/fleet.json` — the OPERATOR-side
//! analog of `enrollment.json` (which is the DEVICE-side binding). There is no doc-specified wire
//! shape for this file (it never crosses the network — `fleet_client::FleetConfig` is its in-memory
//! mirror); its shape is derived from [`fleet_connect`]'s own argument list. Kept deliberately
//! independent of `enrollment.json`: this is the console operator's own connection, not the device's.
//!
//! BC-5 (the security-critical part): [`fleet_device_evidence`] re-verifies EVERY returned envelope
//! locally via `kriya_verify::verify_envelope`, over the RAW per-envelope string `fleet_client`
//! returned (itself the raw stored `signed_bytes` line kriyad sent, never a re-serialization — see
//! `fleet_client::Readback`'s doc comment). A server that returns bytes it never actually stored, or a
//! MITM despite mTLS, still can't produce a `verified: true` row without a real device signature.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::fleet_client::{self, DeviceCoverage, FleetConfig};
use crate::license::require_fleet_console;

/// Where the operator's fleet connection config is persisted (`~/.kriya/console/fleet.json`).
fn fleet_config_path() -> PathBuf {
    crate::audit::console_dir().join("fleet.json")
}

/// The on-disk shape of the operator's fleet connection — the persisted form of [`FleetConfig`], with
/// cert and key kept as SEPARATE paths (matching `fleet_connect`'s own 4-arg signature) rather than
/// the single concatenated PEM `FleetConfig`/`mtls_client` expects. [`to_fleet_config`] does the
/// one-time concatenation into a temp file at call time, so this module owns that seam rather than
/// silently mutating the caller's own cert/key files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FleetConnection {
    server_url: String,
    ca_pem_path: String,
    cert_path: String,
    key_path: String,
}

/// Concatenate `cert_path` + `key_path` into one PEM (what `reqwest::Identity::from_pem` /
/// `FleetConfig::client_identity_pem` expects — mirrors `push.rs`'s single-PEM convention) and write
/// it under `~/.kriya/console/fleet-identity.pem`. Re-derived from the persisted connection's cert/key
/// paths on every call rather than persisted itself, so a cert/key ROTATION (replacing the files on
/// disk at the same paths) is picked up automatically on the next command — no separate "reconnect"
/// step required.
fn to_fleet_config(conn: &FleetConnection) -> Result<FleetConfig, String> {
    let cert = std::fs::read_to_string(&conn.cert_path)
        .map_err(|e| format!("read client cert {}: {e}", conn.cert_path))?;
    let key = std::fs::read_to_string(&conn.key_path)
        .map_err(|e| format!("read client key {}: {e}", conn.key_path))?;
    let mut identity_pem = cert;
    if !identity_pem.ends_with('\n') {
        identity_pem.push('\n');
    }
    identity_pem.push_str(&key);

    let identity_path = crate::audit::console_dir().join("fleet-identity.pem");
    std::fs::write(&identity_path, &identity_pem)
        .map_err(|e| format!("writing {}: {e}", identity_path.display()))?;
    restrict_perms(&identity_path);

    Ok(FleetConfig {
        server_url: conn.server_url.clone(),
        client_identity_pem: identity_path,
        server_ca_pem: PathBuf::from(&conn.ca_pem_path),
    })
}

#[cfg(unix)]
fn restrict_perms(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_path: &std::path::Path) {}

/// Load the persisted fleet connection, or a clear "not connected" error (never a panic) if
/// [`fleet_connect`] hasn't succeeded yet.
fn load_connection() -> Result<FleetConnection, String> {
    let path = fleet_config_path();
    let text = std::fs::read_to_string(&path).map_err(|_| {
        "no fleet connection configured — call fleet_connect first".to_string()
    })?;
    serde_json::from_str(&text).map_err(|e| format!("fleet.json is malformed: {e}"))
}

// ── Tauri commands ───────────────────────────────────────────────────────────────────────────────

/// Probe `url`'s `/healthz` over mTLS with the given CA + client cert/key, and ONLY on success
/// persist the connection to `~/.kriya/console/fleet.json`. Requires `fleet-console` — checked FIRST,
/// before any network I/O, so an unlicensed caller never even touches the filesystem for certs.
#[tauri::command]
#[cfg(feature = "control-plane")]
pub fn fleet_connect(
    url: String,
    ca_pem_path: String,
    cert_path: String,
    key_path: String,
) -> Result<(), String> {
    require_fleet_console()?;

    let conn = FleetConnection {
        server_url: url,
        ca_pem_path,
        cert_path,
        key_path,
    };
    let cfg = to_fleet_config(&conn)?;
    fleet_client::fetch_healthz(&cfg)?;

    let path = fleet_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&conn).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(())
}

/// `GET /v1/coverage` — the per-device liveness/completeness dashboard. Requires `fleet-console`.
#[tauri::command]
#[cfg(feature = "control-plane")]
pub fn fleet_coverage() -> Result<Vec<DeviceCoverage>, String> {
    require_fleet_console()?;
    let conn = load_connection()?;
    let cfg = to_fleet_config(&conn)?;
    fleet_client::fetch_coverage(&cfg)
}

/// One re-verified envelope: the raw signed line as returned by kriyad, plus whether it verifies
/// locally against `kriya-verify` right now (BC-5). `verified: false` is returned, not an error — a
/// forged/tampered row is itself the finding the operator needs to see, not a reason to hide the rest
/// of the window.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedEnvelope {
    pub raw: String,
    pub verified: bool,
    /// `Some` only when verification failed — the reason, for the operator's investigation.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEvidence {
    pub envelopes: Vec<VerifiedEnvelope>,
    /// The device's most-recent signed heartbeat line, if any — re-verified the same way envelopes
    /// are (raw bytes through `kriya_verify`), surfaced separately since it isn't an
    /// `AttestationEnvelope` (a different signed schema — see `kriya_verify::heartbeat_canonical_bytes`).
    pub heartbeat: Option<VerifiedEnvelope>,
}

/// `GET /v1/verify?device_pub=…&from_seq=…&to_seq=…` — the trustless read-back, re-verified LOCALLY
/// over the raw returned bytes before this command returns anything to the UI (BC-5: never trust the
/// wire, never re-verify a re-serialization). Requires `fleet-console`.
#[tauri::command]
#[cfg(feature = "control-plane")]
pub fn fleet_device_evidence(
    device_pub: String,
    from_seq: u64,
    to_seq: u64,
) -> Result<DeviceEvidence, String> {
    require_fleet_console()?;
    let conn = load_connection()?;
    let cfg = to_fleet_config(&conn)?;
    let resp = fleet_client::fetch_device_envelopes(&cfg, &device_pub, from_seq, to_seq)?;

    // BC-5: walk `parsed.envelopes` — each element IS the raw signed line kriyad stored, never a
    // re-serialization of it (see fleet_client::Readback's doc comment). Verify with the SAME
    // kriya-verify entry point the rest of the Console uses (paid.rs::collect, envelope.rs's own
    // builder round-trip test), over a Value parsed straight from that raw string.
    let envelopes = resp
        .parsed
        .envelopes
        .into_iter()
        .map(|raw| {
            let (verified, error) = match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(v) => match kriya_verify::verify_envelope(&v) {
                    Ok(()) => (true, None),
                    Err(e) => (false, Some(e)),
                },
                Err(e) => (false, Some(format!("not valid JSON: {e}"))),
            };
            VerifiedEnvelope { raw, verified, error }
        })
        .collect();

    let heartbeat = resp.parsed.heartbeat.map(|raw| {
        let (verified, error) = match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => match kriya_verify::verify_heartbeat(&v) {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e)),
            },
            Err(e) => (false, Some(format!("not valid JSON: {e}"))),
        };
        VerifiedEnvelope { raw, verified, error }
    });

    Ok(DeviceEvidence { envelopes, heartbeat })
}

#[cfg(all(test, feature = "control-plane"))]
mod tests {
    use super::*;

    /// Guards these `$HOME`-mutating tests from racing each other (cargo runs tests within one
    /// binary on parallel threads by default) — same pattern as `govern.rs`'s `ENV_LOCK`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Every command must reach `require_fleet_console` before touching disk/network — proven by
    /// pointing HOME at an empty temp dir (no license installed at all ⇒ definitely no `fleet-console`
    /// grant) and asserting a clean error, never a panic, for each of the three commands.
    fn with_empty_home<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "kriya-fleet-cmd-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("HOME", &tmp);
        let result = f();
        std::env::remove_var("HOME");
        let _ = std::fs::remove_dir_all(&tmp);
        result
    }

    #[test]
    fn fleet_connect_requires_license_before_any_io() {
        with_empty_home(|| {
            let err = fleet_connect(
                "https://kriyad.invalid:8443".into(),
                "/nonexistent/ca.pem".into(),
                "/nonexistent/cert.pem".into(),
                "/nonexistent/key.pem".into(),
            )
            .unwrap_err();
            assert!(
                err.contains("fleet-console") || err.contains("fleet cockpit"),
                "must fail on the license gate, not a missing-file error: {err}"
            );
        });
    }

    #[test]
    fn fleet_coverage_requires_license() {
        with_empty_home(|| {
            let err = fleet_coverage().unwrap_err();
            assert!(
                err.contains("fleet-console") || err.contains("fleet cockpit"),
                "must fail on the license gate: {err}"
            );
        });
    }

    #[test]
    fn fleet_device_evidence_requires_license() {
        with_empty_home(|| {
            let err = fleet_device_evidence("devpub".into(), 0, 100).unwrap_err();
            assert!(
                err.contains("fleet-console") || err.contains("fleet cockpit"),
                "must fail on the license gate: {err}"
            );
        });
    }

    #[test]
    fn load_connection_errors_cleanly_when_unconfigured() {
        with_empty_home(|| {
            let err = load_connection().unwrap_err();
            assert!(err.contains("fleet_connect"), "clear, actionable error: {err}");
        });
    }
}
