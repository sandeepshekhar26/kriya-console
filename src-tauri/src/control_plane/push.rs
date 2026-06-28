//! Device transport (2.7) — how the Compiler drains the outbox to the aggregator. Two equal paths,
//! because the verifier is transport-agnostic (the bytes the device signed are re-verified server-side
//! either way):
//!
//!   * **Online (mTLS):** POST the signed envelopes to `/v1/envelopes` and heartbeats to
//!     `/v1/heartbeat` over mTLS — the customer's own CA pins both ends.
//!   * **Air-gap:** write the same signed lines to a file an operator carries across on approved media;
//!     the server side-loads them (`kriyad ingest-file`). Sneaker-net == network, to the verifier.
//!
//! A stolen client cert still can't forge an envelope: forgery needs the device evidence key, which
//! never leaves the device and isn't the transport identity.

use std::path::{Path, PathBuf};

/// Air-gap export: write `lines` (already-signed envelopes or heartbeats, one JSON object per line) to
/// `dest` as NDJSON for sneaker-net transfer. The server ingests the identical bytes.
pub fn write_airgap(lines: &[String], dest: &Path) -> Result<(), String> {
    if lines.is_empty() {
        return Err("nothing to export (outbox tail empty)".into());
    }
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(dest, body).map_err(|e| format!("write air-gap file {}: {e}", dest.display()))
}

/// Where the device's transport identity + the pinned server CA live (provisioned by enrollment; the
/// dev `kriyd-ca` script emits `client-N.pem`/`client-N.key` + `ca.pem`).
pub struct PushTarget {
    /// Base URL of the aggregator, e.g. `https://kriyad.corp.internal:8443`.
    pub server_url: String,
    /// The device client cert + its private key, PEM (concatenated — `reqwest::Identity::from_pem`).
    pub client_identity_pem: PathBuf,
    /// The pinned server CA (PEM) — the ONLY root the client trusts (no public-CA fallback).
    pub server_ca_pem: PathBuf,
}

/// POST an NDJSON batch of signed envelopes to `/v1/envelopes` over mTLS. Blocking — it runs in the
/// Compiler's own `std::thread`, so no async runtime is needed. Returns the server's `IngestReport`
/// body (caller logs accepted/duplicates/rejected).
#[cfg(feature = "control-plane")]
pub fn push_envelopes(target: &PushTarget, ndjson: &str) -> Result<String, String> {
    let resp = mtls_client(target)?
        .post(format!("{}/v1/envelopes", target.server_url))
        .body(ndjson.to_owned())
        .send()
        .map_err(|e| format!("POST /v1/envelopes: {e}"))?;
    resp.text().map_err(|e| format!("read ingest report: {e}"))
}

/// POST one signed heartbeat to `/v1/heartbeat` over mTLS.
#[cfg(feature = "control-plane")]
pub fn push_heartbeat(target: &PushTarget, body: &str) -> Result<(), String> {
    let resp = mtls_client(target)?
        .post(format!("{}/v1/heartbeat", target.server_url))
        .body(body.to_owned())
        .send()
        .map_err(|e| format!("POST /v1/heartbeat: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("heartbeat rejected: HTTP {}", resp.status()))
    }
}

/// Build the mTLS client: present the device cert, and trust ONLY the pinned server CA.
#[cfg(feature = "control-plane")]
fn mtls_client(target: &PushTarget) -> Result<reqwest::blocking::Client, String> {
    let identity_pem = std::fs::read(&target.client_identity_pem).map_err(|e| {
        format!(
            "read client identity {}: {e}",
            target.client_identity_pem.display()
        )
    })?;
    let ca_pem = std::fs::read(&target.server_ca_pem)
        .map_err(|e| format!("read server CA {}: {e}", target.server_ca_pem.display()))?;
    reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false) // no public-CA fallback — pin the customer CA only
        .add_root_certificate(
            reqwest::Certificate::from_pem(&ca_pem).map_err(|e| format!("parse server CA: {e}"))?,
        )
        .identity(
            reqwest::Identity::from_pem(&identity_pem)
                .map_err(|e| format!("parse client identity: {e}"))?,
        )
        .build()
        .map_err(|e| format!("build mTLS client: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn airgap_round_trips_the_signed_lines() {
        let dir = std::env::temp_dir().join(format!("kriya-airgap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("outbox.ndjson");

        let lines = vec![
            r#"{"envelope":{"seq":1},"signature":"aa"}"#.to_string(),
            r#"{"envelope":{"seq":2},"signature":"bb"}"#.to_string(),
        ];
        write_airgap(&lines, &dest).unwrap();

        // The file is exactly the signed lines + trailing newline — the server reads them back verbatim.
        let read = std::fs::read_to_string(&dest).unwrap();
        assert_eq!(read, format!("{}\n{}\n", lines[0], lines[1]));
        assert_eq!(read.lines().count(), 2);

        // Empty tail is a no-op error, never a 0-byte file masquerading as evidence.
        assert!(write_airgap(&[], &dest).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "control-plane")]
    #[test]
    fn mtls_client_errors_cleanly_on_missing_certs() {
        let target = PushTarget {
            server_url: "https://kriyad.invalid:8443".into(),
            client_identity_pem: "/nonexistent/client.pem".into(),
            server_ca_pem: "/nonexistent/ca.pem".into(),
        };
        let err = push_envelopes(&target, "{}\n").unwrap_err();
        assert!(
            err.contains("client identity"),
            "graceful, not a panic: {err}"
        );
    }
}
