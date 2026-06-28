//! kriyad runtime config — all from env (declarative, container-friendly), with sane defaults. Operate
//! it like self-hosted Vault/GitLab: config in, no outbound calls.

use std::net::SocketAddr;
use std::path::PathBuf;

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
}

impl Config {
    pub fn from_env() -> Self {
        let bind = std::env::var("KRIYAD_BIND")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8443".parse().expect("default bind"));
        Config {
            bind,
            db_path: env_path("KRIYAD_DB", "kriyad.sqlite"),
            license_path: env_path("KRIYAD_LICENSE", "kriyad-license.json"),
            ca_dir: env_path("KRIYAD_CA_DIR", "ca"),
        }
    }
}

fn env_path(key: &str, default: &str) -> PathBuf {
    std::env::var(key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}
