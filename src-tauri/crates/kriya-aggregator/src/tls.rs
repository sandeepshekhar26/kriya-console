//! mTLS (2.4) — a rustls `ServerConfig` that REQUIRES every client to present a cert chaining to the
//! pinned CA. The customer's own CA pins both ends; a stolen client cert still can't forge an envelope
//! (it lacks the evidence key — the SAN→`device_pub` binding is Phase 3). Certs come from the
//! `kriyd-ca` dev script (the enrollment stub).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

/// Build the mTLS server config from `<ca_dir>/{server.pem,server.key,ca.pem}`. Every client must
/// present a cert chaining to the pinned CA. `Err` when the cert files are absent (kriyad then falls
/// back to plain HTTP for local/dev use).
pub fn server_config(ca_dir: &Path) -> Result<Arc<ServerConfig>, String> {
    // Install the process crypto provider (idempotent — Err just means already installed).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certs = load_certs(&ca_dir.join("server.pem"))?;
    let key = load_key(&ca_dir.join("server.key"))?;
    let mut roots = RootCertStore::empty();
    for c in load_certs(&ca_dir.join("ca.pem"))? {
        roots.add(c).map_err(|e| format!("ca: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("client verifier: {e}"))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server cert: {e}"))?;
    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse {}: {e}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    rustls_pemfile::private_key(&mut &data[..])
        .map_err(|e| format!("parse key {}: {e}", path.display()))?
        .ok_or_else(|| format!("no private key in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_ca_certs_build_an_mtls_config() {
        let dir = std::env::temp_dir().join(format!("kriyad-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/kriyd-ca.sh");
        let out = std::process::Command::new("bash")
            .arg(script)
            .arg(&dir)
            .arg("2")
            .output();
        let Ok(out) = out else {
            eprintln!("skip: no bash");
            return;
        };
        if !out.status.success() {
            eprintln!(
                "skip: kriyd-ca failed (no openssl?): {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        // The pinned CA + server cert/key build a valid mTLS server config, and N client certs exist.
        server_config(&dir).expect("mTLS config builds from dev CA certs");
        assert!(dir.join("client-1.pem").exists() && dir.join("client-2.pem").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
