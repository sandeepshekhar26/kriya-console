//! Fleet uplink (P0) — the OPERATOR cockpit's OUTBOUND mTLS client to a `kriyad` aggregator: pull-only,
//! read-only counterpart to [`push`]'s device-side push. Same trust shape as `push.rs` (the customer's
//! own CA pins both ends; a stolen transport cert still can't forge evidence — these routes only ever
//! return bytes the device already signed, and the caller re-verifies them locally, never trusting the
//! wire). Gated under the SAME `control-plane` feature as `push` (BC-1) — there is no separate "pull"
//! feature; one dormancy gate covers both directions.
//!
//! Windowed by construction (doc 22 §11 DoS): [`fetch_device_envelopes`] ALWAYS sends `from_seq`/
//! `to_seq` as explicit query params (never omitted, so kriyad never falls back to its own
//! `0..u64::MAX` default) and refuses client-side to even issue a request for a window wider than
//! [`MAX_WINDOW`] — a courtesy cap; kriyad enforces its own server-side cap independently (P0 item 2),
//! so this is defense in depth, not the only guard.
//!
//! BC-5 (raw-bytes verification): [`fetch_device_envelopes`] returns the RAW response body alongside
//! the parsed [`store::Readback`]-shaped struct. The caller (the Tauri command layer) MUST re-verify
//! signatures over the raw bytes of each envelope line as returned by the server, never over a
//! re-serialization of the parsed struct — re-serializing (e.g. via `serde_json::to_string` on a
//! deserialized `Value`) can silently reorder keys or change whitespace, which would make a real forgery
//! verify (false negative on tamper-detection) or a genuine envelope fail (false positive). We keep the
//! per-envelope strings exactly as kriyad sent them (kriyad's own `Readback.envelopes: Vec<String>` are
//! themselves already the raw stored `signed_bytes` lines — see `kriya-aggregator/src/store.rs` — so no
//! double-parse is needed there; but we ALSO expose the full undecoded response body for callers that
//! want to hash/diff/audit the exact bytes that hit the wire).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The largest `to_seq - from_seq` window this client will request in one call. Mirrors kriyad's own
/// server-side cap (P0 item 2, doc 22 §11) — kept as an independent client-side courtesy check so a
/// misbehaving caller fails fast locally instead of round-tripping to find out the server said no.
pub const MAX_WINDOW: u64 = 10_000;

/// Where the operator's fleet connection lives: the aggregator's base URL + this Console's mTLS
/// transport identity + the pinned server CA. Structurally the operator-side mirror of `push::PushTarget`
/// (same three-field shape: url, client identity PEM, server CA PEM) — deliberately NOT reusing
/// `PushTarget` itself, since the device-push and operator-pull configs are persisted/sourced
/// independently (`enrollment.json` vs. the P0 `fleet.json` operator config) and BC-1/BC-2 keep those
/// two concerns from becoming implicitly coupled by sharing a type.
#[derive(Debug, Clone)]
pub struct FleetConfig {
    /// Base URL of the aggregator, e.g. `https://kriyad.corp.internal:8443`.
    pub server_url: String,
    /// This Console's client cert + private key, PEM (concatenated — `reqwest::Identity::from_pem`).
    pub client_identity_pem: PathBuf,
    /// The pinned server CA (PEM) — the ONLY root the client trusts (no public-CA fallback).
    pub server_ca_pem: PathBuf,
}

/// Parsed `GET /v1/coverage` response — mirrors `kriya_aggregator::store::DeviceCoverage` field-for-field
/// (kept as an independent local type, not a cross-crate dep on kriya-aggregator, since the Console
/// never links the aggregator binary — only its documented wire shape). `#[serde(default)]`-free on the
/// original P0 fields (every one of those is present in kriyad's response today); the doc-22 §7 P1
/// inventory passthrough fields below are ALL `#[serde(default)]` — kriyad omits them entirely for a
/// device that has never posted a `DeviceInfo` beacon (pre-P1 devices, or ones that simply haven't
/// beaconed yet), and BC-4 additive-only evolution means a future kriyad may add still-newer optional
/// fields, which `serde` ignores by default on a struct deserialize (unknown fields are tolerated unless
/// `deny_unknown_fields` is set, which we deliberately never set here).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceCoverage {
    pub device_pub: String,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub business_unit: Option<String>,
    pub last_seq: i64,
    pub max_seq_seen: i64,
    pub last_seen_ms: i64,
    /// `current` · `behind` · `silent` — kept as a raw `String` (not an enum) so an unrecognized future
    /// status value from a newer kriyad still deserializes cleanly (BC-4: parsers unknown-field/-value
    /// tolerant) instead of hard-failing the whole coverage fetch.
    pub status: String,

    // --- doc 22 §7 device-inventory passthrough (P1) — ADDITIVE, optional, ABSENT (not null) when a
    // device hasn't posted a DeviceInfo beacon yet. Mirrors `kriya_aggregator::store::DeviceCoverage`'s
    // own P1 fields field-for-field; the Tauri command layer (`fleet.rs::fleet_coverage`) surfaces these
    // straight through to the cockpit UI, which renders "inventory: n/a" for anything absent (BC-4).
    #[serde(default)]
    pub console_version: Option<String>,
    #[serde(default)]
    pub runtime_version: Option<String>,
    #[serde(default)]
    pub verify_crate_version: Option<String>,
    #[serde(default)]
    pub os_platform: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub os_arch: Option<String>,
    #[serde(default)]
    pub policy_applied_version: Option<i64>,
    #[serde(default)]
    pub policy_bundle_hash: Option<String>,
    #[serde(default)]
    pub outbox_pending: Option<i64>,
    #[serde(default)]
    pub enrolled_ms: Option<i64>,
    #[serde(default)]
    pub device_label: Option<String>,
    /// The full `agents[]` array (doc 22 §7), kept as opaque JSON — not worth its own struct for a pure
    /// passthrough; the cockpit already has `kriya_verify::AgentInfo`-shaped TS types to render it.
    #[serde(default)]
    pub agents: Option<serde_json::Value>,
    #[serde(default)]
    pub info_collected_ms: Option<i64>,
}

/// The parsed shape of `GET /v1/coverage`'s response: a JSON array of `DeviceCoverage` rows.
pub type CoverageResponse = Vec<DeviceCoverage>;

/// Parsed `GET /v1/verify` response — mirrors `kriya_aggregator::store::Readback` field-for-field.
/// `envelopes` are kriyad's own stored `signed_bytes` lines returned verbatim as strings (kriyad never
/// re-serializes them either — see `store.rs::read_back`'s doc comment) — so these ARE already the raw
/// per-envelope bytes; the CALLER of this module additionally gets [`DeviceEnvelopesResponse::raw_body`]
/// for hashing/logging the exact wire bytes of the whole response if desired, but per-envelope
/// re-verification should walk `parsed.envelopes` (each element IS the raw signed line, not a
/// re-serialization of it) rather than re-encoding the parsed struct.
#[derive(Debug, Clone, Deserialize)]
pub struct Readback {
    pub envelopes: Vec<String>,
    #[serde(default)]
    pub heartbeat: Option<String>,
}

/// The result of [`fetch_device_envelopes`]: the parsed [`Readback`] (for convenience — iterate
/// `envelopes`/`heartbeat` directly, each already the raw signed line) PLUS the complete undecoded
/// response body (`raw_body`, the exact bytes kriyad sent over the wire, before any JSON parsing at
/// all). BC-5: re-verification MUST walk `parsed.envelopes` (or, for whole-response provenance/logging,
/// `raw_body`) — never `serde_json::to_string(&parsed)`, which would re-serialize and could silently
/// diverge from what was actually signed/transmitted.
#[derive(Debug, Clone)]
pub struct DeviceEnvelopesResponse {
    pub parsed: Readback,
    /// The exact response body bytes, undecoded — for whole-payload hashing/audit-logging or as a
    /// fallback if a caller ever needs to re-parse independently of this module's `Readback` shape.
    pub raw_body: Vec<u8>,
}

/// GET `/v1/coverage` over the pinned-CA + client-cert mTLS client (mirrors `push::mtls_client` exactly:
/// pinned CA, client-cert identity, `tls_built_in_root_certs(false)`). No per-row signature to
/// re-verify — coverage rows are SERVER-DERIVED aggregates (`Store::coverage` computes `status` from
/// `now_ms`/`last_seen_ms`/`max_seq_seen` at query time; see `kriya-aggregator/src/store.rs`), not
/// individually signed artifacts, so there is no raw-bytes-signature concern here the way there is for
/// `fetch_device_envelopes` (BC-5 only binds artifacts that carry a device signature). Coverage is a
/// liveness/completeness DASHBOARD view, not evidence; the actual evidence (the envelopes themselves)
/// is what `fetch_device_envelopes` returns and what gets re-verified. Trusting kriyad's arithmetic here
/// is the same trust boundary the operator already accepts by connecting to their own on-prem kriyad at
/// all — kriyad itself re-verifies every envelope offline before it ever lands in the store (see
/// `main.rs::post_envelopes`), so a coverage row reflects only already-verified data.
#[cfg(feature = "control-plane")]
pub fn fetch_coverage(cfg: &FleetConfig) -> Result<CoverageResponse, String> {
    let resp = mtls_client(cfg)?
        .get(format!("{}/v1/coverage", cfg.server_url))
        .send()
        .map_err(|e| format!("GET /v1/coverage: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET /v1/coverage rejected: HTTP {}", resp.status()));
    }
    let bytes = resp
        .bytes()
        .map_err(|e| format!("read /v1/coverage response: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse /v1/coverage response: {e}"))
}

/// GET `/v1/verify?device_pub=…&from_seq=…&to_seq=…` over mTLS — the trustless read-back. `from_seq`/
/// `to_seq` are ALWAYS sent explicitly (never omitted), so this client never relies on kriyad's own
/// `0..u64::MAX` default-when-absent behavior. Refuses client-side (before making any request) if the
/// requested window exceeds [`MAX_WINDOW`] — matches kriyad's own server-side cap (P0 item 2) as
/// defense in depth, not a substitute for it.
///
/// Returns both the parsed [`Readback`] and the exact `raw_body` bytes (BC-5) — see
/// [`DeviceEnvelopesResponse`]'s doc comment for which one callers should walk for re-verification.
#[cfg(feature = "control-plane")]
pub fn fetch_device_envelopes(
    cfg: &FleetConfig,
    device_pub: &str,
    from_seq: u64,
    to_seq: u64,
) -> Result<DeviceEnvelopesResponse, String> {
    if to_seq < from_seq {
        return Err(format!(
            "invalid window: to_seq ({to_seq}) < from_seq ({from_seq})"
        ));
    }
    if to_seq - from_seq > MAX_WINDOW {
        return Err(format!(
            "window too large: to_seq - from_seq ({}) exceeds the {MAX_WINDOW}-row client-side cap",
            to_seq - from_seq
        ));
    }

    let resp = mtls_client(cfg)?
        .get(format!("{}/v1/verify", cfg.server_url))
        .query(&[
            ("device_pub", device_pub.to_string()),
            ("from_seq", from_seq.to_string()),
            ("to_seq", to_seq.to_string()),
        ])
        .send()
        .map_err(|e| format!("GET /v1/verify: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET /v1/verify rejected: HTTP {}", resp.status()));
    }
    let raw_body = resp
        .bytes()
        .map_err(|e| format!("read /v1/verify response: {e}"))?
        .to_vec();
    let parsed: Readback =
        serde_json::from_slice(&raw_body).map_err(|e| format!("parse /v1/verify response: {e}"))?;
    Ok(DeviceEnvelopesResponse { parsed, raw_body })
}

/// GET `/healthz` over the pinned-CA + client-cert mTLS client — the connectivity probe
/// `fleet_connect` (the Tauri IPC layer) uses before persisting a new operator connection config, so a
/// typo'd URL or an unreachable/untrusted server is caught at connect time, not on the first real
/// query. No body to parse (kriyad's `/healthz` returns a bare `"ok\n"` text response); success is
/// purely "the mTLS handshake completed and the server answered 2xx".
#[cfg(feature = "control-plane")]
pub fn fetch_healthz(cfg: &FleetConfig) -> Result<(), String> {
    let resp = mtls_client(cfg)?
        .get(format!("{}/healthz", cfg.server_url))
        .send()
        .map_err(|e| format!("GET /healthz: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("GET /healthz rejected: HTTP {}", resp.status()))
    }
}

/// GET `/v1/policy?device_pub=…&business_unit=…` (P3) — the operator cockpit's OWN preview fetch, used
/// to seed the authoring editor and diff a draft against what's currently published. Uses a synthetic
/// `device_pub` (the cockpit isn't a device) so this only sees an ALL-scoped (or matching-BU-scoped)
/// bundle — a narrowly device-list-scoped bundle may not show up here. That's an accepted v1 rough edge
/// (documented, not silently wrong): building a scope-BYPASS "show me the true latest regardless of
/// scope" route is deliberately deferred to P6 (cert-role separation), which is what would let kriyad
/// trust "this caller is the operator" from the TLS layer itself rather than from a shared dev CA any
/// cert can present today. `404` (nothing published, or an old kriyad lacking the route) → `Ok(None)`,
/// never an error — mirrors the device downlink's own BC-4 handling of the identical route.
#[cfg(feature = "control-plane")]
pub fn fetch_policy_preview(
    cfg: &FleetConfig,
    device_pub: &str,
    business_unit: Option<&str>,
) -> Result<Option<String>, String> {
    let mut req = mtls_client(cfg)?
        .get(format!("{}/v1/policy", cfg.server_url))
        .query(&[("device_pub", device_pub)]);
    if let Some(bu) = business_unit {
        req = req.query(&[("business_unit", bu)]);
    }
    let resp = req.send().map_err(|e| format!("GET /v1/policy: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("GET /v1/policy rejected: HTTP {}", resp.status()));
    }
    resp.text().map(Some).map_err(|e| format!("read /v1/policy response: {e}"))
}

/// POST `/v1/policy` (P3) — publish an org-key-signed `PolicyBundle`. `body` is the ALREADY-SIGNED
/// bundle JSON (signed operator-side via the OS-keychain-held org key, `org_key::sign_with_org_key`) —
/// this function only transports it; kriyad does the real verification on ingest (this Console never
/// needs to trust its own POST succeeding as proof of anything — the publish result it returns is a
/// convenience echo, not the source of truth). Returns kriyad's raw response body (the ingest
/// `{version, duplicate}` JSON on success) alongside the HTTP status, so the caller can distinguish a
/// clean 200 from a 400 (rejected — should be impossible for a bundle THIS Console just signed, unless
/// the pinned org key on kriyad doesn't match) or a 409 (version collision with different content).
#[cfg(feature = "control-plane")]
pub fn publish_policy(cfg: &FleetConfig, signed_bundle_json: &str) -> Result<(u16, String), String> {
    let resp = mtls_client(cfg)?
        .post(format!("{}/v1/policy", cfg.server_url))
        .body(signed_bundle_json.to_owned())
        .send()
        .map_err(|e| format!("POST /v1/policy: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().map_err(|e| format!("read publish response: {e}"))?;
    Ok((status, body))
}

/// Build the mTLS client: present this Console's client cert, and trust ONLY the pinned server CA.
/// Verbatim mirror of `push::mtls_client` (same builder calls, same error-message shape) — the ONE
/// difference is the config type (`FleetConfig` vs. `PushTarget`), since the two are deliberately kept
/// as separate structs (see [`FleetConfig`]'s doc comment) even though their fields are identical today.
#[cfg(feature = "control-plane")]
fn mtls_client(cfg: &FleetConfig) -> Result<reqwest::blocking::Client, String> {
    let identity_pem = std::fs::read(&cfg.client_identity_pem).map_err(|e| {
        format!(
            "read client identity {}: {e}",
            cfg.client_identity_pem.display()
        )
    })?;
    let ca_pem = std::fs::read(&cfg.server_ca_pem)
        .map_err(|e| format!("read server CA {}: {e}", cfg.server_ca_pem.display()))?;
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

#[cfg(all(test, feature = "control-plane"))]
mod tests {
    use super::*;

    fn missing_target() -> FleetConfig {
        FleetConfig {
            server_url: "https://kriyad.invalid:8443".into(),
            client_identity_pem: "/nonexistent/client.pem".into(),
            server_ca_pem: "/nonexistent/ca.pem".into(),
        }
    }

    #[test]
    fn fetch_policy_preview_errors_cleanly_on_missing_certs() {
        let err = fetch_policy_preview(&missing_target(), "_fleet_console_preview_", None).unwrap_err();
        assert!(err.contains("client identity"), "graceful, not a panic: {err}");
    }

    #[test]
    fn publish_policy_errors_cleanly_on_missing_certs() {
        let err = publish_policy(&missing_target(), "{}").unwrap_err();
        assert!(err.contains("client identity"), "graceful, not a panic: {err}");
    }

    #[test]
    fn fetch_coverage_errors_cleanly_on_missing_certs() {
        let err = fetch_coverage(&missing_target()).unwrap_err();
        assert!(
            err.contains("client identity"),
            "graceful, not a panic: {err}"
        );
    }

    #[test]
    fn fetch_device_envelopes_errors_cleanly_on_missing_certs() {
        let err = fetch_device_envelopes(&missing_target(), "devpub", 0, 100).unwrap_err();
        assert!(
            err.contains("client identity"),
            "graceful, not a panic: {err}"
        );
    }

    #[test]
    fn fetch_device_envelopes_refuses_oversized_window_before_any_request() {
        // A window > MAX_WINDOW must be rejected WITHOUT attempting to build a client or hit the
        // network — proven here by using a target with certs that don't even exist yet the error is
        // about the window, not the missing certs (i.e. the window check runs first).
        let err = fetch_device_envelopes(&missing_target(), "devpub", 0, MAX_WINDOW + 1).unwrap_err();
        assert!(
            err.contains("window too large"),
            "must reject an oversized window client-side before touching the network: {err}"
        );
    }

    #[test]
    fn fetch_device_envelopes_refuses_inverted_window() {
        let err = fetch_device_envelopes(&missing_target(), "devpub", 500, 100).unwrap_err();
        assert!(err.contains("invalid window"), "must reject to_seq < from_seq: {err}");
    }

    #[test]
    fn fetch_device_envelopes_allows_window_at_exactly_the_cap() {
        // Exactly MAX_WINDOW must NOT be rejected by the client-side check (only the network call, which
        // fails on the missing certs, should error here) — proves the boundary is inclusive (<=, not <).
        let err = fetch_device_envelopes(&missing_target(), "devpub", 0, MAX_WINDOW).unwrap_err();
        assert!(
            err.contains("client identity"),
            "at exactly MAX_WINDOW the window check must pass, failing only on certs: {err}"
        );
    }

    #[test]
    fn coverage_response_deserializes_the_documented_shape() {
        let body = r#"[{"device_pub":"ab12","org_id":"acme","business_unit":null,
            "last_seq":5,"max_seq_seen":5,"last_seen_ms":1000,"status":"current"}]"#;
        let rows: CoverageResponse = serde_json::from_str(body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_pub, "ab12");
        assert_eq!(rows[0].status, "current");
    }

    #[test]
    fn coverage_response_tolerates_unknown_future_fields() {
        // BC-4: additive wire evolution — a newer kriyad may add fields; the parser must not choke.
        let body = r#"[{"device_pub":"ab12","org_id":null,"business_unit":null,
            "last_seq":0,"max_seq_seen":0,"last_seen_ms":0,"status":"current",
            "future_field":"something-p1-adds"}]"#;
        let rows: CoverageResponse = serde_json::from_str(body).unwrap();
        assert_eq!(rows.len(), 1, "unknown field must not break parsing");
    }

    #[test]
    fn readback_round_trips_raw_envelope_lines_unmodified() {
        // Simulates kriyad's actual response shape: `envelopes` are raw stored signed-bytes strings.
        let raw_line = r#"{"envelope":{"seq":1},"signature":"aa"}"#;
        let body = format!(
            r#"{{"envelopes":["{}"],"heartbeat":null}}"#,
            raw_line.replace('"', "\\\"")
        );
        let parsed: Readback = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.envelopes.len(), 1);
        assert_eq!(
            parsed.envelopes[0], raw_line,
            "the envelope string must be the exact raw line, not a re-serialization"
        );
    }
}
