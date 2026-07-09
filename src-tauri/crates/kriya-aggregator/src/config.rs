//! kriyad runtime config — all from env (declarative, container-friendly), with sane defaults. Operate
//! it like self-hosted Vault/GitLab: config in, no outbound calls.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind (mTLS when the CA dir holds certs).
    pub bind: SocketAddr,
    /// SQLite file (the whole store = one file; backup = copy it).
    pub db_path: PathBuf,
    /// Offline `control-plane` license the server gates ingest on (2.2).
    pub license_path: PathBuf,
    /// Directory holding the server cert/key + the pinned client CA (2.4).
    pub ca_dir: PathBuf,
    /// A device is `silent` once `now - last_seen_ms` exceeds this (LLD §B.3.1's pilot default:
    /// `N=3, H=1h` → 3h). Configurable (`KRIYAD_SILENT_AFTER_MS`) so an operator can tune liveness
    /// sensitivity to their fleet's real heartbeat cadence, and so tests can exercise the silent
    /// transition without an actual multi-hour wait — the DEFAULT is unchanged from the pilot's
    /// original hardcoded constant.
    pub silent_after_ms: u64,
}

impl Config {
    pub fn from_env() -> Self {
        let bind = std::env::var("KRIYAD_BIND")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8443".parse().expect("default bind"));
        let silent_after_ms = std::env::var("KRIYAD_SILENT_AFTER_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3 * 60 * 60 * 1000);
        Config {
            bind,
            db_path: env_path("KRIYAD_DB", "kriyad.sqlite"),
            license_path: env_path("KRIYAD_LICENSE", "kriyad-license.json"),
            ca_dir: env_path("KRIYAD_CA_DIR", "ca"),
            silent_after_ms,
        }
    }

    /// The pinned **org policy public key** (P3, doc 22 §3/§5) — kriyad's trust anchor for verifying a
    /// `POST /v1/policy` bundle. Resolved fresh on every call (cheap: an env read + a small file read)
    /// rather than cached at startup, so an operator can drop `org-policy.pub` into the CA dir (or set
    /// the env var) without restarting kriyad. Two sources, `KRIYAD_ORG_POLICY_PUB` taking priority:
    /// - the env var holding the raw lowercase-hex key directly (container/K8s-secret friendly), or
    /// - `<ca_dir>/org-policy.pub` (mirrors how the server cert/key/CA already live under `ca_dir`).
    ///
    /// `None` when neither source is configured — policy distribution is simply not set up yet; kriyad
    /// still authors nothing (doc 22 §3), it just has nothing to verify a bundle against.
    ///
    /// Takes `ca_dir` directly (rather than `&self`) so `AppState` (`main.rs`), which threads only
    /// `ca_dir` through to route handlers rather than a whole `Config`, can share this exact logic.
    pub fn resolve_org_policy_pub(ca_dir: &Path) -> Option<String> {
        if let Ok(v) = std::env::var("KRIYAD_ORG_POLICY_PUB") {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
        std::fs::read_to_string(ca_dir.join("org-policy.pub"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

fn env_path(key: &str, default: &str) -> PathBuf {
    std::env::var(key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}
