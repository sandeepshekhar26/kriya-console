//! mTLS (2.4) — a rustls `ServerConfig` that REQUIRES every client to present a cert chaining to the
//! pinned CA. The customer's own CA pins both ends. **P6 (doc 22 §11-B2):** the handshake verifier is
//! unchanged (still `WebPkiClientVerifier`, chain-to-CA), but [`RoleAcceptor`] now reads the verified
//! peer leaf cert AFTER the handshake, parses its role SAN (`crate::peer`), and injects a
//! `PeerAuth` into every request's extensions on that connection — so the route table can gate a device
//! cert out of fleet reads and an operator cert out of evidence POSTs. Certs come from the `kriyd-ca`
//! dev script (the enrollment stub; real CSR-binding is Phase 3, doc 13).

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower_service::Service;

use crate::peer::{self, PeerAuth};

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

/// The mTLS acceptor that layers P6 role identity on top of the standard rustls handshake. It defers
/// the handshake to the inner [`RustlsAcceptor`] (chain-to-CA verification, unchanged), then reads the
/// verified peer leaf cert and injects the parsed [`PeerAuth`] into the per-connection service via
/// [`SetPeerAuth`], so every request on the connection carries its client's role.
#[derive(Clone)]
pub struct RoleAcceptor {
    inner: RustlsAcceptor,
    allow_legacy: bool,
}

impl RoleAcceptor {
    pub fn new(config: RustlsConfig, allow_legacy: bool) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
            allow_legacy,
        }
    }
}

impl<I, S> Accept<I, S> for RoleAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = SetPeerAuth<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let fut = self.inner.accept(stream, service);
        let allow_legacy = self.allow_legacy;
        Box::pin(async move {
            let (tls, service) = fut.await?;
            // The handshake succeeded, so mTLS already proved the cert chains to the pinned CA; here we
            // additionally derive the ROLE. `peer_certificates()` is `Some` because the verifier
            // requires client auth — but if it were somehow absent, reject rather than fall open.
            let auth = {
                let (_io, conn) = tls.get_ref();
                match conn.peer_certificates().and_then(|c| c.first()) {
                    Some(leaf) => peer::auth_from_leaf(leaf.as_ref(), allow_legacy),
                    None => PeerAuth::Rejected("no client certificate presented".into()),
                }
            };
            Ok((tls, SetPeerAuth { inner: service, auth }))
        })
    }
}

/// Wraps the per-connection service to inject the connection's [`PeerAuth`] into each request's
/// extensions before the router sees it. The route handlers read it back via the `FromRequestParts`
/// impl in `crate::peer`.
#[derive(Clone)]
pub struct SetPeerAuth<S> {
    inner: S,
    auth: PeerAuth,
}

impl<S, B> Service<axum::http::Request<B>> for SetPeerAuth<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.auth.clone());
        self.inner.call(req)
    }
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

    /// Read the leaf DER out of a PEM the kriyd-ca script wrote.
    fn leaf_der(pem_path: &Path) -> Vec<u8> {
        let data = std::fs::read(pem_path).unwrap();
        let cert = rustls_pemfile::certs(&mut &data[..]).next().unwrap().unwrap();
        cert.as_ref().to_vec()
    }

    /// P6: REAL role-stamped certs minted by `kriyd-ca.sh` parse to the expected [`PeerAuth`] — the
    /// end-to-end cert→role path the unit tests in `crate::peer` can only approximate with strings.
    /// Also proves grace semantics on a real legacy (role-less) cert. Skips cleanly without bash/openssl.
    #[test]
    fn role_stamped_certs_parse_to_the_expected_peer_auth() {
        let dir = std::env::temp_dir().join(format!("kriyad-role-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/kriyd-ca.sh");
        let device_pub = "a".repeat(64);

        // One operator + one device cert in the same CA dir.
        let out = std::process::Command::new("bash")
            .arg(script)
            .arg(&dir)
            .args(["--operator", "--device", &device_pub])
            .output();
        let Ok(out) = out else {
            eprintln!("skip: no bash");
            return;
        };
        if !out.status.success() {
            eprintln!("skip: kriyd-ca failed (no openssl?): {}", String::from_utf8_lossy(&out.stderr));
            return;
        }

        let op = crate::peer::auth_from_leaf(&leaf_der(&dir.join("operator.pem")), false);
        assert_eq!(op, PeerAuth::Role(crate::peer::PeerRole::Operator));

        let dev = crate::peer::auth_from_leaf(&leaf_der(&dir.join("device.pem")), false);
        assert_eq!(dev, PeerAuth::Role(crate::peer::PeerRole::Device(device_pub)));

        // A legacy (role-less) cert: Rejected with grace off, Legacy with grace on.
        let legacy_dir = std::env::temp_dir().join(format!("kriyad-legacy-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&legacy_dir);
        let out = std::process::Command::new("bash")
            .arg(script)
            .arg(&legacy_dir)
            .arg("1")
            .output()
            .unwrap();
        assert!(out.status.success());
        let legacy_leaf = leaf_der(&legacy_dir.join("client-1.pem"));
        assert!(matches!(crate::peer::auth_from_leaf(&legacy_leaf, false), PeerAuth::Rejected(_)));
        assert_eq!(crate::peer::auth_from_leaf(&legacy_leaf, true), PeerAuth::Legacy);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&legacy_dir);
    }
}
