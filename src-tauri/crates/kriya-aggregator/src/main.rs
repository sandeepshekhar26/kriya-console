//! kriyad — the kriya-aggregator server (single static binary; single-tenant; runs inside the
//! customer's own boundary). Ingests signed `AttestationEnvelope`s over mTLS, re-verifies them OFFLINE
//! with `kriya-verify` (it never trusts the device), stores ONLY signed metadata in append-only SQLite,
//! and serves trustless read-back + coverage. No outbound calls; no kriya-cloud dependency.

mod config;
mod license;
mod peer;
mod store;
mod tls;

use peer::PeerAuth;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Value};

/// Prometheus counters (the SQLite store lands in 2.3).
#[derive(Default)]
pub struct Metrics {
    pub envelopes_total: AtomicU64,
    pub envelopes_rejected_total: AtomicU64,
    pub heartbeats_total: AtomicU64,
}

pub struct AppState {
    pub metrics: Metrics,
    pub store: store::Store,
    /// Only `ca_dir` (not a full `Config`) is threaded through — the one field route handlers actually
    /// need, to resolve the pinned org policy public key (P3, `config::Config::org_policy_pub`).
    pub ca_dir: PathBuf,
    /// `silent` when a device hasn't been seen for this long (LLD §B.6 pilot default: 3h) —
    /// `config::Config::silent_after_ms`'s doc comment explains why this is configurable.
    pub silent_after_ms: u64,
}

impl AppState {
    pub fn new(store: store::Store, ca_dir: PathBuf, silent_after_ms: u64) -> Self {
        Self {
            metrics: Metrics::default(),
            store,
            ca_dir,
            silent_after_ms,
        }
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self::new(
            store::Store::open_in_memory().expect("in-memory store"),
            PathBuf::from("."),
            3 * 60 * 60 * 1000,
        )
    }

    /// Resolve the pinned org policy public key for this server — see
    /// `config::Config::org_policy_pub`'s doc comment for the two-source precedence
    /// (`KRIYAD_ORG_POLICY_PUB` env, else `<ca_dir>/org-policy.pub`).
    pub fn org_policy_pub(&self) -> Option<String> {
        config::Config::resolve_org_policy_pub(&self.ca_dir)
    }
}

/// The HTTP app (transport-agnostic, so it's testable without a socket via `oneshot`).
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/v1/envelopes", post(post_envelopes))
        .route("/v1/heartbeat", post(post_heartbeat))
        .route("/v1/device-info", post(post_device_info))
        .route("/v1/policy", post(post_policy).get(get_policy))
        .route("/v1/coverage", get(get_coverage))
        .route("/v1/verify", get(get_verify))
        .with_state(state)
}

/// GET /v1/coverage[?org_id=…] — per-device current/behind/silent. **Operator-only (P6):** reading the
/// whole fleet's liveness is a cockpit action; a device cert is 403'd (closes the "any fleet cert reads
/// the whole fleet" hole, doc 22 §11-B2).
async fn get_coverage(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Vec<store::DeviceCoverage>>, (StatusCode, String)> {
    peer.require_operator()?;
    let org = q.get("org_id").map(String::as_str);
    Ok(Json(state.store.coverage(now_ms(), state.silent_after_ms, org)))
}

/// The maximum `to_seq - from_seq` window this route accepts from an EXPLICIT range (doc 22 §11 DoS
/// hardening). Mirrors `store::READ_BACK_ROW_CAP` — kept as its own constant (rather than reusing the
/// store's) because this one gates the wire contract (what the route rejects), not the data layer.
const MAX_VERIFY_WINDOW: u64 = 10_000;

/// GET /v1/verify?device_pub=…&from_seq=…&to_seq=… — trustless read-back: the EXACT stored signed
/// bytes for the contiguous slice + the device's most-recent signed heartbeat (the tail anchor).
///
/// DoS hardening (doc 22 §11): an EXPLICITLY supplied window wider than `MAX_VERIFY_WINDOW` is
/// rejected with 400 + a JSON error body. A caller that omits `to_seq` (legacy behavior: defaults to
/// `u64::MAX`, i.e. "everything from `from_seq` on") is NOT rejected here — that's an implicit
/// unbounded request, not an explicit oversized one, so it keeps working exactly as before (BC-4) and
/// is instead capped at the data layer by `store::read_back`'s row limit (defense in depth).
async fn get_verify(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<store::Readback>, (StatusCode, String)> {
    // Operator-only (P6): trustless read-back of any device's evidence is an auditor/cockpit action.
    peer.require_operator()?;
    let device_pub = q
        .get("device_pub")
        .ok_or((StatusCode::BAD_REQUEST, "device_pub required\n".to_string()))?;
    let from_seq: u64 = q.get("from_seq").and_then(|s| s.parse().ok()).unwrap_or(0);
    let to_seq_explicit: Option<u64> = q.get("to_seq").and_then(|s| s.parse().ok());
    if let Some(to_seq) = to_seq_explicit {
        if to_seq.saturating_sub(from_seq) > MAX_VERIFY_WINDOW {
            return Err((
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "window_too_large",
                    "message": format!(
                        "to_seq - from_seq exceeds the maximum window of {MAX_VERIFY_WINDOW}"
                    ),
                    "max_window": MAX_VERIFY_WINDOW,
                })
                .to_string(),
            ));
        }
    }
    let to_seq = to_seq_explicit.unwrap_or(u64::MAX);
    Ok(Json(state.store.read_back(device_pub, from_seq, to_seq)))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Serialize)]
struct IngestReport {
    accepted: u32,
    duplicates: u32,
    rejected: Vec<Value>,
}

fn reject(report: &mut IngestReport, metrics: &Metrics, line: usize, reason: String) {
    report
        .rejected
        .push(json!({ "line": line, "reason": reason }));
    metrics
        .envelopes_rejected_total
        .fetch_add(1, Ordering::Relaxed);
}

/// POST /v1/envelopes — NDJSON batch. **Device-only (P6):** a device pushes its OWN evidence; an
/// operator cert is 403'd. Every envelope in the batch is additionally bound to the cert's
/// `device_pub` — a line for any other device is rejected (counted, like a forged one), closing the
/// evidence-injection vector (doc 22 §11-B2 / doc 13's two-key binding). Under legacy grace / plain
/// HTTP there is no binding to enforce (`None`), exactly as pre-P6.
async fn post_envelopes(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
    body: String,
) -> Result<Json<IngestReport>, (StatusCode, String)> {
    let bound = peer.require_device()?;
    Ok(Json(ingest_ndjson(&state, &body, bound)))
}

/// Verify + ingest an NDJSON batch. Shared by the HTTP handler (online mode) and the `ingest-file`
/// subcommand (air-gap side-load) — the verifier is transport-agnostic, so both run the SAME offline
/// re-verification + gap-tolerant idempotent insert. Only forged/malformed/incoherent lines are
/// rejected (counted, not dropped); out-of-order / missing seqs are a coverage gap, never an error.
///
/// `bound_device_pub` (P6): when `Some`, every envelope's own `device_pub` MUST equal it (the cert
/// binding); a mismatched line is rejected. `None` for air-gap side-load (sneaker-net has no live cert;
/// the operator carrying the media is the trust boundary) and for legacy-grace / plain-HTTP requests.
fn ingest_ndjson(state: &AppState, body: &str, bound_device_pub: Option<&str>) -> IngestReport {
    let mut report = IngestReport {
        accepted: 0,
        duplicates: 0,
        rejected: Vec::new(),
    };
    for (i, line) in body.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let line_no = i + 1;
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                reject(&mut report, &state.metrics, line_no, format!("parse: {e}"));
                continue;
            }
        };
        if let Err(reason) = kriya_verify::verify_envelope(&v) {
            reject(&mut report, &state.metrics, line_no, reason);
            continue;
        }
        let signed: kriya_verify::SignedEnvelope = match serde_json::from_value(v) {
            Ok(s) => s,
            Err(e) => {
                reject(&mut report, &state.metrics, line_no, format!("decode: {e}"));
                continue;
            }
        };
        // P6: a device cert may only introduce evidence for its OWN device_pub. (verify_envelope
        // already proved `envelope.device_pub == public_key`, so this binds the transport cert to the
        // envelope's signer — a stolen cert still can't forge, and now can't even replay another
        // device's real envelopes into the store under its own connection.)
        if let Some(bound) = bound_device_pub {
            if signed.envelope.device_pub != bound {
                reject(
                    &mut report,
                    &state.metrics,
                    line_no,
                    format!(
                        "device_pub {} does not match the client certificate's bound device_pub",
                        signed.envelope.device_pub
                    ),
                );
                continue;
            }
        }
        match state
            .store
            .insert_envelope(&signed, line.as_bytes(), now_ms())
        {
            Ok(store::Ingest::Accepted) => {
                report.accepted += 1;
                state
                    .metrics
                    .envelopes_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            Ok(store::Ingest::Duplicate) => report.duplicates += 1,
            Err(e) => reject(&mut report, &state.metrics, line_no, e),
        }
    }
    report
}

/// POST /v1/heartbeat — one signed heartbeat. **Device-only (P6)**, bound to the cert's `device_pub`:
/// this closes the coverage-poisoning vector (a cert could otherwise post heartbeats — the liveness
/// tail anchor — for arbitrary devices). Verify, append to the liveness log, update coverage.
async fn post_heartbeat(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
    body: String,
) -> (StatusCode, String) {
    let bound = match peer.require_device() {
        Ok(b) => b,
        Err((code, msg)) => return (code, msg),
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("parse: {e}\n")),
    };
    if let Err(reason) = kriya_verify::verify_heartbeat(&v) {
        return (StatusCode::BAD_REQUEST, format!("{reason}\n"));
    }
    let signed: kriya_verify::SignedHeartbeat = match serde_json::from_value(v) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("decode: {e}\n")),
    };
    if let Some(bound) = bound {
        if signed.heartbeat.device_pub != bound {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "device_pub {} does not match the client certificate's bound device_pub\n",
                    signed.heartbeat.device_pub
                ),
            );
        }
    }
    match state
        .store
        .insert_heartbeat(&signed, body.as_bytes(), now_ms())
    {
        Ok(()) => {
            state
                .metrics
                .heartbeats_total
                .fetch_add(1, Ordering::Relaxed);
            (StatusCode::OK, "ok\n".into())
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}\n")),
    }
}

/// POST /v1/device-info — doc 22 §7's signed device-inventory beacon (P1). Mirrors
/// `post_heartbeat`'s shape exactly: parse the raw body bytes, verify the signature via
/// `kriya_verify::verify_device_info` (BC-5 — canonicalization is over the PARSED fields' recursively
/// key-sorted JSON, which is reorder-safe, so this is the raw-received-bytes check, never a
/// deserialize-drop-unknown-field-reserialize one; a byte flipped anywhere in the signed payload changes
/// the parsed value and therefore the recomputed canonical bytes, so tampering is caught), then upsert.
/// An unknown `device_pub` is NOT rejected — mirrors `insert_envelope`/`insert_heartbeat`: this may be
/// the device's very FIRST beacon, posted before it has ever pushed an envelope.
async fn post_device_info(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
    body: String,
) -> (StatusCode, String) {
    // Device-only (P6), bound to the cert's device_pub — closes the inventory-poisoning vector.
    let bound = match peer.require_device() {
        Ok(b) => b,
        Err((code, msg)) => return (code, msg),
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("parse: {e}\n")),
    };
    if let Err(reason) = kriya_verify::verify_device_info(&v) {
        return (StatusCode::BAD_REQUEST, format!("{reason}\n"));
    }
    let signed: kriya_verify::SignedDeviceInfo = match serde_json::from_value(v) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("decode: {e}\n")),
    };
    if let Some(bound) = bound {
        if signed.device_pub != bound {
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "device_pub {} does not match the client certificate's bound device_pub\n",
                    signed.device_pub
                ),
            );
        }
    }
    match state
        .store
        .insert_device_info(&signed, body.as_bytes(), now_ms())
    {
        Ok(()) => (StatusCode::OK, "ok\n".into()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}\n")),
    }
}

/// POST /v1/policy (P3, doc 22 §5) — the operator's cockpit publishes a `PolicyBundle` here.
/// **kriyad authors nothing** (doc 22 §3): it verifies the org signature ON THE RAW BODY BYTES against
/// the PINNED `org_policy_pub` (never a key the payload itself asserts — a bundle carries none) and, on
/// success, appends to the `policy_bundles` table verbatim. Garbage — an unparseable body, a forged
/// signature, or (with no org key pinned at all) ANY body — never enters the store.
async fn post_policy(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
    body: String,
) -> (StatusCode, String) {
    // Operator-only (P6): publishing a fleet policy is a cockpit action. (Security does NOT rest on
    // this — a forged bundle still dies twice, at kriyad ingest-verify below and at each device's own
    // verify; but a device cert has no business POSTing policy, so gate it out cleanly.)
    if let Err((code, msg)) = peer.require_operator() {
        return (code, msg);
    }
    let Some(org_pub) = state.org_policy_pub() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no org policy public key is pinned on this server \
             (set KRIYAD_ORG_POLICY_PUB or drop org-policy.pub in the CA dir) — \
             policy distribution is not configured yet\n"
                .to_string(),
        );
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("parse: {e}\n")),
    };
    if let Err(reason) = kriya_verify::verify_policy_bundle(&v, &org_pub) {
        return (StatusCode::BAD_REQUEST, format!("{reason}\n"));
    }
    let signed: kriya_verify::SignedPolicyBundle = match serde_json::from_value(v) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("decode: {e}\n")),
    };
    let version = signed.bundle.version;
    match state.store.insert_policy_bundle(&signed, body.as_bytes(), now_ms()) {
        Ok(store::PolicyIngest::Accepted) => {
            (StatusCode::OK, json!({ "version": version, "duplicate": false }).to_string())
        }
        Ok(store::PolicyIngest::DuplicateSameContent) => {
            (StatusCode::OK, json!({ "version": version, "duplicate": true }).to_string())
        }
        // A version collision with DIFFERENT content — never silently overwritten (store.rs); the
        // operator must bump the version. 409, not 400: the bundle itself is validly signed, the
        // conflict is with server-side state, not the request's own well-formedness.
        Err(e) => (StatusCode::CONFLICT, format!("{e}\n")),
    }
}

/// GET /v1/policy?device_pub=…&business_unit=… (P3) — serve the LATEST bundle whose `scope` covers
/// this device (scope filtering is SERVING, not deciding: the device re-verifies the signature and its
/// own anti-rollback check regardless). `404` when nothing is published in scope — deliberately
/// indistinguishable from an old kriyad lacking this route at all (BC-4): either way the device does
/// the same thing, skip this cycle, so no separate signal is needed.
async fn get_policy(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
    Query(q): Query<HashMap<String, String>>,
) -> Result<String, (StatusCode, String)> {
    // P6: a DEVICE pulls its OWN scoped bundle — bound to its cert's device_pub, so it can't fetch
    // another device's policy. An OPERATOR is ALSO permitted here (with no binding): the cockpit reads
    // this route for its publish-preview and org-evidence bundle fetch (P3–P5), which must keep
    // working — so this route allows device-or-operator, unlike the strictly-operator reads above.
    let bound = peer.require_device_or_operator()?;
    let device_pub = q
        .get("device_pub")
        .ok_or((StatusCode::BAD_REQUEST, "device_pub required\n".to_string()))?;
    if let Some(bound) = bound {
        if device_pub != bound {
            return Err((
                StatusCode::FORBIDDEN,
                "a device certificate may only pull policy for its own device_pub\n".to_string(),
            ));
        }
    }
    let business_unit = q.get("business_unit").map(String::as_str);
    state
        .store
        .latest_policy_bundle(device_pub, business_unit)
        .ok_or((StatusCode::NOT_FOUND, String::new()))
}

/// `/healthz` — any authenticated role (P6): a validly-role-stamped device OR operator cert (or a
/// legacy-grace / plain-HTTP peer). Only an outright-rejected cert is 403'd. The operator cockpit's
/// `fleet_connect` probes this before persisting a connection, and devices may liveness-check too.
async fn healthz(peer: PeerAuth) -> Result<&'static str, (StatusCode, String)> {
    peer.require_any()?;
    Ok("ok\n")
}

async fn metrics(
    State(state): State<Arc<AppState>>,
    peer: PeerAuth,
) -> Result<String, (StatusCode, String)> {
    peer.require_any()?;
    let m = &state.metrics;
    Ok(format!(
        "# HELP kriyad_envelopes_total Accepted envelopes.\n\
         # TYPE kriyad_envelopes_total counter\n\
         kriyad_envelopes_total {}\n\
         kriyad_envelopes_rejected_total {}\n\
         kriyad_heartbeats_total {}\n",
        m.envelopes_total.load(Ordering::Relaxed),
        m.envelopes_rejected_total.load(Ordering::Relaxed),
        m.heartbeats_total.load(Ordering::Relaxed),
    ))
}

#[tokio::main]
async fn main() {
    let config = config::Config::from_env();
    // Offline license gate (2.2) — refuse to serve ingest without a valid control-plane license.
    if let Err(e) = license::gate(&config.license_path) {
        eprintln!("kriyad: refusing to start — {e}");
        std::process::exit(1);
    }
    let store = store::Store::open(&config.db_path).expect("open store");
    let state = AppState::new(store, config.ca_dir.clone(), config.silent_after_ms);

    // Air-gap receive: `kriyad ingest-file <outbox.ndjson>` side-loads signed bytes carried across on
    // approved media, runs the SAME offline re-verification as the wire path, then exits (no serve).
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(i) = args.iter().position(|a| a == "ingest-file") {
        let path = args
            .get(i + 1)
            .expect("usage: kriyad ingest-file <file.ndjson>");
        let body = std::fs::read_to_string(path).expect("read ingest file");
        // Air-gap side-load: no live client cert, so no device_pub binding to enforce (`None`) — the
        // operator carrying the approved media is the trust boundary; every line is still re-verified.
        let report = ingest_ndjson(&state, &body, None);
        println!(
            "ingest-file {path}: accepted={} duplicates={} rejected={}",
            report.accepted,
            report.duplicates,
            report.rejected.len()
        );
        return;
    }

    let router = app(Arc::new(state));

    // mTLS when the CA dir holds certs (the BOX/online modes); plain HTTP otherwise (local/dev).
    match tls::server_config(&config.ca_dir) {
        Ok(tls_config) => {
            eprintln!(
                "kriyad listening on https://{} (mTLS, role-gated{})",
                config.bind,
                if config.allow_legacy_certs {
                    "; KRIYAD_ALLOW_LEGACY_CERTS=1 — legacy role-less certs honored during migration"
                } else {
                    ""
                }
            );
            // P6: RoleAcceptor extracts each connection's client-cert role (post-handshake) and injects
            // it, so the route table can gate device vs operator. The handshake verifier is unchanged.
            let acceptor = tls::RoleAcceptor::new(
                axum_server::tls_rustls::RustlsConfig::from_config(tls_config),
                config.allow_legacy_certs,
            );
            axum_server::bind(config.bind)
                .acceptor(acceptor)
                .serve(router.into_make_service())
                .await
                .expect("serve mTLS");
        }
        Err(e) => {
            eprintln!(
                "kriyad: no mTLS certs ({e}); serving plain HTTP on {}",
                config.bind
            );
            let listener = tokio::net::TcpListener::bind(config.bind)
                .await
                .expect("bind");
            axum::serve(listener, router).await.expect("serve");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// `config::Config::silent_after_ms` (env `KRIYAD_SILENT_AFTER_MS`) actually reaches the route —
    /// a SHORT threshold flips a just-reported device to `silent` almost immediately, without waiting
    /// out the pilot's real 3h default. This is what the P4 e2e proof relies on to demonstrate
    /// "stop the laggard -> silent+red" in seconds rather than hours.
    #[tokio::test]
    async fn silent_after_ms_is_configurable_via_app_state() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[91u8; 32]);
        let state = Arc::new(AppState::new(
            store::Store::open_in_memory().unwrap(),
            PathBuf::from("."),
            50, // 50ms — a device is "silent" almost the instant it stops reporting
        ));
        let env_line = serde_json::to_string(&build_envelope(&key, 1, None)).unwrap();
        post(state.clone(), "/v1/envelopes", env_line).await;

        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        assert_eq!(cov[0]["status"], "current", "fresh report is current, even with a short threshold");

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let cov: Value = serde_json::from_slice(&get(state, "/v1/coverage").await).unwrap();
        assert_eq!(cov[0]["status"], "silent", "a short configured threshold flips it to silent quickly");
    }

    #[tokio::test]
    async fn healthz_and_metrics_respond() {
        let state = Arc::new(AppState::in_memory());

        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok\n");

        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("kriyad_envelopes_total"));
    }

    async fn post(state: Arc<AppState>, uri: &str, body: String) -> (StatusCode, Vec<u8>) {
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, bytes)
    }

    #[tokio::test]
    async fn post_envelopes_verifies_dedups_and_rejects_forged() {
        let state = Arc::new(AppState::in_memory());
        let fixture: Value =
            serde_json::from_str(include_str!("../../../../src/sample/sample-envelope.json"))
                .unwrap();
        let line = serde_json::to_string(&fixture).unwrap();

        let (_, body) = post(state.clone(), "/v1/envelopes", line.clone()).await;
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 1, "a verified envelope is accepted");

        let (_, body) = post(state.clone(), "/v1/envelopes", line).await;
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["duplicates"], 1, "re-post is an idempotent no-op");

        let mut bad = fixture.clone();
        bad["envelope"]["org_id"] = json!("evil-corp");
        let (_, body) = post(state, "/v1/envelopes", serde_json::to_string(&bad).unwrap()).await;
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 0);
        assert_eq!(
            r["rejected"].as_array().unwrap().len(),
            1,
            "forged rejected + counted"
        );
    }

    /// BC-5 cross-version parity (P3, doc 22 §5/§8): `POST /v1/envelopes` accepts a genuine v1.1
    /// envelope (carrying `policy_state`) exactly like a v1.0 one — the ingest path never special-cases
    /// the new field, it flows through the same `kriya_verify::verify_envelope` + `insert_envelope`.
    #[tokio::test]
    async fn post_envelopes_accepts_a_v1_1_envelope_with_policy_state() {
        let state = Arc::new(AppState::in_memory());
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../src/sample/sample-envelope-v1.1.json"
        ))
        .unwrap();
        assert!(
            fixture["envelope"]["policy_state"]["version"] == json!(13),
            "fixture sanity: must genuinely carry policy_state"
        );
        let line = serde_json::to_string(&fixture).unwrap();

        let (_, body) = post(state.clone(), "/v1/envelopes", line.clone()).await;
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 1, "a v1.1 envelope is accepted like any other");

        let device_pub = fixture["envelope"]["device_pub"].as_str().unwrap();
        let rb: Value = serde_json::from_slice(
            &get(state, &format!("/v1/verify?device_pub={device_pub}")).await,
        )
        .unwrap();
        let returned = rb["envelopes"][0].as_str().unwrap();
        assert_eq!(returned, line, "the served bytes are exactly what was stored, policy_state intact");
    }

    #[tokio::test]
    async fn post_heartbeat_verifies_and_rejects_forged() {
        use ed25519_dalek::{Signer, SigningKey};
        let state = Arc::new(AppState::in_memory());
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let hb = kriya_verify::Heartbeat {
            device_pub: pk.clone(),
            seq_seen: 9,
            ts_ms: 1,
        };
        let sig = hex::encode(
            key.sign(&kriya_verify::heartbeat_canonical_bytes(&hb))
                .to_bytes(),
        );
        let signed = json!({ "heartbeat": hb, "public_key": pk, "signature": sig });

        let (status, _) = post(state.clone(), "/v1/heartbeat", signed.to_string()).await;
        assert_eq!(status, StatusCode::OK, "a valid heartbeat is accepted");

        let mut bad = signed.clone();
        bad["heartbeat"]["seq_seen"] = json!(999); // forge a higher anchor after signing
        let (status, _) = post(state, "/v1/heartbeat", bad.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a forged heartbeat is rejected"
        );
    }

    /// A real signed DeviceInfo beacon (doc 22 §7), keyed by `key`, ready to POST.
    fn sample_signed_device_info(key: &ed25519_dalek::SigningKey) -> kriya_verify::SignedDeviceInfo {
        use kriya_verify::{AgentInfo, DeviceInfo, OsInfo, PolicyEcho};
        let info = DeviceInfo {
            console_version: "0.2.1".into(),
            runtime_version: "kriya-host 0.4.2".into(),
            verify_crate_version: "kriya-verify 0.1.0".into(),
            os: OsInfo {
                platform: "macos".into(),
                version: "15.5".into(),
                arch: "aarch64".into(),
            },
            agents: vec![AgentInfo {
                id: "claude-code".into(),
                version: "2.1.x".into(),
                adapter: "kriya-hook".into(),
                adapter_version: "r30".into(),
                wired: true,
            }],
            policy: Some(PolicyEcho {
                applied_version: 13,
                bundle_hash: "deadbeef".into(),
            }),
            outbox_pending: 2,
            enrolled_ms: 1_783_400_000_000,
            device_label: Some("ENG-1234".into()),
        };
        kriya_verify::sign_device_info(key, 1_783_500_000_000, info)
    }

    /// Happy path: a validly signed DeviceInfo beacon is accepted (200) and then shows up as ADDITIVE
    /// fields on the SAME device's `GET /v1/coverage` row.
    #[tokio::test]
    async fn post_device_info_accepted_then_visible_in_coverage() {
        use ed25519_dalek::SigningKey;
        let state = Arc::new(AppState::in_memory());
        let key = SigningKey::from_bytes(&[21u8; 32]);
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let signed = sample_signed_device_info(&key);
        let line = serde_json::to_string(&signed).unwrap();

        let (status, body) = post(state.clone(), "/v1/device-info", line).await;
        assert_eq!(status, StatusCode::OK, "valid device-info beacon accepted: {body:?}");

        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        let row = cov
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["device_pub"] == json!(device_pub))
            .expect("device row present");
        assert_eq!(row["console_version"], "0.2.1");
        assert_eq!(row["runtime_version"], "kriya-host 0.4.2");
        assert_eq!(row["verify_crate_version"], "kriya-verify 0.1.0");
        assert_eq!(row["os_platform"], "macos");
        assert_eq!(row["os_version"], "15.5");
        assert_eq!(row["os_arch"], "aarch64");
        assert_eq!(row["policy_applied_version"], 13);
        assert_eq!(row["policy_bundle_hash"], "deadbeef");
        assert_eq!(row["outbox_pending"], 2);
        assert_eq!(row["enrolled_ms"], 1_783_400_000_000_i64);
        assert_eq!(row["device_label"], "ENG-1234");
        assert_eq!(row["agents"][0]["id"], "claude-code");
        assert_eq!(row["agents"][0]["adapter_version"], "r30");

        // The stored bytes re-verify offline — proves `signed_bytes` round-trips correctly (BC-5).
        let stored_raw: Vec<u8> = {
            use rusqlite::params;
            let conn = state.store.lock();
            conn.query_row(
                "SELECT info_signed_bytes FROM devices WHERE device_pub=?1",
                params![device_pub],
                |r| r.get(0),
            )
            .unwrap()
        };
        let stored_val: Value = serde_json::from_slice(&stored_raw).unwrap();
        assert!(
            kriya_verify::verify_device_info(&stored_val).is_ok(),
            "the verbatim stored bytes re-verify offline"
        );
    }

    /// A byte flipped anywhere inside a validly-shaped signed DeviceInfo payload must be rejected with
    /// 400 — the real BC-5 negative test (not a trivial malformed-JSON case): the JSON stays well-formed,
    /// only a value inside `info` changes after signing, so this exercises the actual signature check.
    #[tokio::test]
    async fn post_device_info_rejects_tampered_signature() {
        use ed25519_dalek::SigningKey;
        let state = Arc::new(AppState::in_memory());
        let key = SigningKey::from_bytes(&[22u8; 32]);
        let signed = sample_signed_device_info(&key);
        let mut v = serde_json::to_value(&signed).unwrap();

        // Flip a value inside `info` post-signing — well-formed JSON, forged content.
        v["info"]["outbox_pending"] = json!(9999);
        let (status, body) = post(state.clone(), "/v1/device-info", v.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "tampered device-info payload rejected: {body:?}"
        );

        // A device_pub swap (claiming another key's identity) must also fail.
        let other = SigningKey::from_bytes(&[23u8; 32]);
        let mut swapped = serde_json::to_value(&signed).unwrap();
        swapped["device_pub"] = json!(hex::encode(other.verifying_key().to_bytes()));
        let (status, _) = post(state, "/v1/device-info", swapped.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "device_pub swap rejected");
    }

    /// Unknown `device_pub` handling: a DeviceInfo beacon may be the FIRST thing kriyad ever hears from
    /// a device (posted before any envelope/heartbeat) — mirrors `insert_envelope`/`insert_heartbeat`'s
    /// convention of creating the device row rather than rejecting.
    #[tokio::test]
    async fn post_device_info_creates_row_for_unknown_device() {
        use ed25519_dalek::SigningKey;
        let state = Arc::new(AppState::in_memory());
        let key = SigningKey::from_bytes(&[24u8; 32]);
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let signed = sample_signed_device_info(&key);

        // Confirm the device is genuinely unknown before the beacon.
        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        assert!(cov.as_array().unwrap().is_empty(), "no devices yet");

        let (status, body) = post(
            state.clone(),
            "/v1/device-info",
            serde_json::to_string(&signed).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "first-ever beacon accepted: {body:?}");

        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        let rows = cov.as_array().unwrap();
        assert_eq!(rows.len(), 1, "a device row was created from the beacon alone");
        assert_eq!(rows[0]["device_pub"], device_pub);
        assert_eq!(rows[0]["console_version"], "0.2.1");
    }

    /// BC-4 regression guard: a device that has ONLY ever posted envelopes/heartbeats (pre-P1 shape, or
    /// simply never beaconed) must still serialize on `GET /v1/coverage` exactly as it did before this
    /// change — the new fields absent, not null, not erroring, not affecting old fields.
    #[tokio::test]
    async fn coverage_serializes_old_device_rows_unaffected_by_device_info_fields() {
        use ed25519_dalek::{Signer, SigningKey};
        let state = Arc::new(AppState::in_memory());
        let key = SigningKey::from_bytes(&[25u8; 32]);
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let env_line = serde_json::to_string(&build_envelope(&key, 1, None)).unwrap();
        let (_, body) = post(state.clone(), "/v1/envelopes", env_line).await;
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 1);

        let hb = kriya_verify::Heartbeat {
            device_pub: device_pub.clone(),
            seq_seen: 1,
            ts_ms: 1500,
        };
        let hb_line = json!({
            "heartbeat": hb,
            "public_key": device_pub,
            "signature": hex::encode(key.sign(&kriya_verify::heartbeat_canonical_bytes(&hb)).to_bytes()),
        })
        .to_string();
        let (status, _) = post(state.clone(), "/v1/heartbeat", hb_line).await;
        assert_eq!(status, StatusCode::OK);

        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        let row = &cov.as_array().unwrap()[0];
        assert_eq!(row["device_pub"], device_pub);
        assert_eq!(row["status"], "current");
        assert_eq!(row["last_seq"], 1);
        assert_eq!(row["max_seq_seen"], 1);
        // The new device-inventory fields must be ABSENT (not null) — `skip_serializing_if` — so an old
        // cockpit client's unknown-field-tolerant parser sees exactly the same shape as before P1.
        let obj = row.as_object().unwrap();
        for new_field in [
            "console_version",
            "runtime_version",
            "verify_crate_version",
            "os_platform",
            "os_version",
            "os_arch",
            "policy_applied_version",
            "policy_bundle_hash",
            "outbox_pending",
            "enrolled_ms",
            "device_label",
            "agents",
            "info_collected_ms",
            // P4 (doc 22 §9-CM) additions — likewise absent, never null, when nothing has ever been
            // published/applied.
            "applied_policy_version",
            "applied_bundle_hash",
            "latest_bundle_version",
        ] {
            assert!(
                !obj.contains_key(new_field),
                "field {new_field:?} must be absent (not null) on a device with no DeviceInfo beacon: {row}"
            );
        }
    }

    /// P4 (doc 22 §9-CM): a device's LATEST accepted envelope's `policy_state` is what `applied_*`
    /// reflects — even when the P1 device-info echo is stale/absent (fresher: it updates every window,
    /// not just on a content-hash-gated DeviceInfo re-beacon).
    #[tokio::test]
    async fn coverage_applied_policy_prefers_the_latest_envelopes_policy_state() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[26u8; 32]);
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let state = Arc::new(AppState::in_memory());

        // seq 1: no policy_state yet (pre-apply).
        let e1 = build_envelope(&key, 1, None);
        let (_, body) = post(state.clone(), "/v1/envelopes", serde_json::to_string(&e1).unwrap()).await;
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["accepted"], 1);

        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        let row = &cov.as_array().unwrap()[0];
        assert!(
            !row.as_object().unwrap().contains_key("applied_policy_version"),
            "no policy_state anywhere yet -> absent, never a fabricated value: {row}"
        );

        // seq 2: the device applied v7 — its envelope now carries policy_state.
        let prev = kriya_verify::sha256_hex(&kriya_verify::canonical_json_bytes(
            &serde_json::to_value(&e1).unwrap(),
        ));
        let mut e2 = build_envelope(&key, 2, Some(prev));
        e2.envelope.policy_state = Some(kriya_verify::PolicyStateEcho {
            version: 7,
            bundle_hash: "cafef00d".into(),
            applied_ms: 1_783_500_000_000,
        });
        let e2 = resign(e2, &key);
        let (_, body) = post(state.clone(), "/v1/envelopes", serde_json::to_string(&e2).unwrap()).await;
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["accepted"], 1);

        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        let row = &cov.as_array().unwrap()[0];
        assert_eq!(row["device_pub"], device_pub);
        assert_eq!(row["applied_policy_version"], 7);
        assert_eq!(row["applied_bundle_hash"], "cafef00d");
    }

    /// P4: `latest_bundle_version` reflects the highest `PolicyBundle` version this kriyad has EVER
    /// accepted, across every device row (a pure fleet-wide aggregate) — `None`/absent until the first
    /// bundle is published.
    #[tokio::test]
    async fn coverage_latest_bundle_version_reflects_the_highest_published_version() {
        let _guard = ENV_LOCK.lock().await;
        let org_key = ed25519_dalek::SigningKey::from_bytes(&[27u8; 32]);
        let org_pub = hex::encode(org_key.verifying_key().to_bytes());
        std::env::set_var("KRIYAD_ORG_POLICY_PUB", &org_pub);
        let state = Arc::new(AppState::in_memory());

        // Before any device or bundle: an empty coverage list (nothing to assert per-row, but the
        // aggregate must not panic on an empty policy_bundles table).
        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        assert_eq!(cov.as_array().unwrap().len(), 0);

        // One device reports in.
        let device_key = ed25519_dalek::SigningKey::from_bytes(&[28u8; 32]);
        let env_line = serde_json::to_string(&build_envelope(&device_key, 1, None)).unwrap();
        post(state.clone(), "/v1/envelopes", env_line).await;

        // Publish v1 then v2.
        for version in [1u64, 2] {
            let bundle = kriya_verify::sign_policy_bundle(
                &org_key,
                kriya_verify::PolicyBundle {
                    org_id: "acme".into(),
                    version,
                    issued_ms: 1000 + version,
                    expires_ms: None,
                    scope: kriya_verify::PolicyScope::all(),
                    policy: json!({}),
                    budgets: json!({}),
                    govern: vec![],
                    envelope_verbosity: "standard".into(),
                    kill_switch: false,
                },
            );
            let (status, _) =
                post(state.clone(), "/v1/policy", serde_json::to_string(&bundle).unwrap()).await;
            assert_eq!(status, StatusCode::OK);
        }

        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        let row = &cov.as_array().unwrap()[0];
        assert_eq!(row["latest_bundle_version"], 2, "reflects the HIGHEST published version");

        std::env::remove_var("KRIYAD_ORG_POLICY_PUB");
    }

    /// BC-5 cross-version fixture (a): a NEW verifier reading an OLD (pre-DeviceInfo) heartbeat
    /// artifact. `pilot-heartbeat.json` predates P1 — it was minted by `emit_pilot_fixtures` before
    /// `DeviceInfo`/`/v1/device-info` existed and carries none of the new fields. The schema-bump rule
    /// (doc 22 §8 BC-5: "cross-version fixtures per schema bump") requires proving the post-bump
    /// verifier still accepts pre-bump artifacts unchanged — no crash, no spurious rejection, and (since
    /// a heartbeat is device-info-independent) posting it to the live `/v1/device-info`-aware route
    /// still works exactly as it always did.
    #[tokio::test]
    async fn new_verifier_accepts_old_shape_heartbeat_fixture() {
        let raw = include_str!("../test-fixtures/pilot-heartbeat.json");
        let v: Value = serde_json::from_str(raw.trim()).expect("committed fixture is valid JSON");
        // No P1 fields exist anywhere in this artifact — it genuinely predates the schema bump.
        assert!(v.get("info").is_none(), "fixture must be pre-DeviceInfo shaped");
        assert!(
            kriya_verify::verify_heartbeat(&v).is_ok(),
            "the NEW kriya-verify must still accept an OLD-shape heartbeat artifact unchanged"
        );

        // And it still round-trips through the live route exactly as before.
        let state = Arc::new(AppState::in_memory());
        let (status, body) = post(state, "/v1/heartbeat", raw.trim().to_string()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an old-shape heartbeat is accepted by the new server: {body:?}"
        );
    }

    // ── P3: POST/GET /v1/policy (doc 22 §5) ─────────────────────────────────────────────────────────

    /// `KRIYAD_ORG_POLICY_PUB` is process-global state; cargo runs tests within one binary on parallel
    /// threads by default, so every test below that sets/clears it takes this lock first (mirrors the
    /// `ENV_LOCK` pattern already used for `$HOME`-mutating tests elsewhere in this codebase, e.g.
    /// `control_plane::fleet::tests`). A `tokio::sync::Mutex` (not `std::sync::Mutex`) since these are
    /// `#[tokio::test]` async tests that hold the guard across `.await` points by design (the whole
    /// point is serializing these tests against each other, including their awaited HTTP calls).
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn org_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[51u8; 32])
    }

    fn signed_bundle_json(key: &ed25519_dalek::SigningKey, version: u64, scope: Value) -> String {
        let scope: kriya_verify::PolicyScope = serde_json::from_value(scope).unwrap();
        let signed = kriya_verify::sign_policy_bundle(
            key,
            kriya_verify::PolicyBundle {
                org_id: "acme".into(),
                version,
                issued_ms: 1000 + version,
                expires_ms: None,
                scope,
                policy: json!({ "rules": [{ "action": "*", "allow": true }] }),
                budgets: json!({ "max_actions_per_minute": 60 }),
                govern: vec![kriya_verify::GovernDirective {
                    target: "claude-code".into(),
                    action: "wire".into(),
                }],
                envelope_verbosity: "standard".into(),
                kill_switch: false,
            },
        );
        serde_json::to_string(&signed).unwrap()
    }

    /// With NO org key pinned at all, `POST /v1/policy` refuses ANY body — garbage never enters the
    /// store even when it's honestly signed by SOME key, because kriyad has nothing to check it against.
    #[tokio::test]
    async fn post_policy_without_a_pinned_org_key_refuses_everything() {
        let _guard = ENV_LOCK.lock().await;
        let state = Arc::new(AppState::in_memory()); // ca_dir "." with no org-policy.pub — and the env
        std::env::remove_var("KRIYAD_ORG_POLICY_PUB"); // var must be absent too, or a parallel test leaks it
        let body = signed_bundle_json(&org_key(), 1, json!({}));
        let (status, _) = post(state, "/v1/policy", body).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The real ingest path: a genuinely org-key-signed bundle is accepted, and is then served back by
    /// `GET /v1/policy` — kriyad never modifies it (the served bytes re-verify against the same pinned
    /// key, byte-for-byte).
    #[tokio::test]
    async fn post_then_get_policy_round_trips_and_reverifies() {
        let _guard = ENV_LOCK.lock().await;
        let key = org_key();
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        std::env::set_var("KRIYAD_ORG_POLICY_PUB", &pub_hex);
        let state = Arc::new(AppState::in_memory());

        let body = signed_bundle_json(&key, 1, json!({}));
        let (status, resp_body) = post(state.clone(), "/v1/policy", body).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&resp_body));
        let report: Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(report["version"], 1);
        assert_eq!(report["duplicate"], false);

        let served = get(state.clone(), "/v1/policy?device_pub=devA").await;
        let served_v: Value = serde_json::from_slice(&served).unwrap();
        assert_eq!(served_v["bundle"]["version"], 1);
        assert!(
            kriya_verify::verify_policy_bundle(&served_v, &pub_hex).is_ok(),
            "the served bytes re-verify against the pinned org key"
        );

        std::env::remove_var("KRIYAD_ORG_POLICY_PUB");
    }

    /// THE forged-signature rejection test: a bundle "signed" by a DIFFERENT key than the one pinned on
    /// this server must be rejected 400 and never enter the store (proving the ingest-time verify is
    /// real, not a rubber stamp).
    #[tokio::test]
    async fn post_policy_rejects_a_bundle_signed_by_the_wrong_key() {
        let _guard = ENV_LOCK.lock().await;
        let pinned = org_key();
        let pub_hex = hex::encode(pinned.verifying_key().to_bytes());
        std::env::set_var("KRIYAD_ORG_POLICY_PUB", &pub_hex);
        let state = Arc::new(AppState::in_memory());

        let attacker = ed25519_dalek::SigningKey::from_bytes(&[52u8; 32]);
        let forged = signed_bundle_json(&attacker, 1, json!({}));
        let (status, body) = post(state.clone(), "/v1/policy", forged).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&body));

        // Nothing was ingested — a subsequent GET has nothing to serve.
        let (status, _) = get_raw(state, "/v1/policy?device_pub=devA").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the forged bundle must not have been stored");

        std::env::remove_var("KRIYAD_ORG_POLICY_PUB");
    }

    /// A bundle that's well-formed JSON but whose signature was tampered with AFTER signing (not just
    /// "wrong key") must also be rejected — the same guarantee, exercised via post-signing mutation
    /// rather than a different signer.
    #[tokio::test]
    async fn post_policy_rejects_tampered_bundle_content() {
        let _guard = ENV_LOCK.lock().await;
        let key = org_key();
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        std::env::set_var("KRIYAD_ORG_POLICY_PUB", &pub_hex);
        let state = Arc::new(AppState::in_memory());

        let body = signed_bundle_json(&key, 1, json!({}));
        let mut v: Value = serde_json::from_str(&body).unwrap();
        v["bundle"]["policy"]["rules"][0]["allow"] = json!(false); // tamper after signing
        let (status, resp) = post(state, "/v1/policy", v.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&resp));

        std::env::remove_var("KRIYAD_ORG_POLICY_PUB");
    }

    /// `GET /v1/policy` 404s when nothing has been published in scope — the SAME response an old
    /// kriyad (no route at all) would give, so a device's uniform "404 ⇒ skip this cycle" handling
    /// covers both cases without needing to tell them apart (BC-4).
    #[tokio::test]
    async fn get_policy_404s_when_nothing_published() {
        let state = Arc::new(AppState::in_memory());
        let (status, _) = get_raw(state, "/v1/policy?device_pub=devA").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// `GET /v1/policy` requires `device_pub` (mirrors `/v1/verify`) — a caller that omits it gets a
    /// clear 400, not a panic or an unscoped "serve everything".
    #[tokio::test]
    async fn get_policy_requires_device_pub() {
        let state = Arc::new(AppState::in_memory());
        let (status, _) = get_raw(state, "/v1/policy").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Re-publishing an EXISTING version with DIFFERENT content is a loud 409 — never a silent
    /// overwrite of a version devices may already have applied.
    #[tokio::test]
    async fn post_policy_conflicting_republish_of_a_version_is_409() {
        let _guard = ENV_LOCK.lock().await;
        let key = org_key();
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        std::env::set_var("KRIYAD_ORG_POLICY_PUB", &pub_hex);
        let state = Arc::new(AppState::in_memory());

        let (status, _) = post(state.clone(), "/v1/policy", signed_bundle_json(&key, 1, json!({}))).await;
        assert_eq!(status, StatusCode::OK);

        let conflicting = signed_bundle_json(&key, 1, json!({ "business_unit": "different-bu" }));
        let (status, body) = post(state, "/v1/policy", conflicting).await;
        assert_eq!(status, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&body));

        std::env::remove_var("KRIYAD_ORG_POLICY_PUB");
    }

    /// BC-5 cross-version fixture (b): an OLD-shape `/v1/coverage` response (pre-P1: only
    /// `device_pub/org_id/business_unit/last_seq/max_seq_seen/last_seen_ms/status` — none of the P1
    /// device-inventory fields exist yet) still parses correctly against the NEW `store::DeviceCoverage`
    /// shape. Proves additive-only evolution from the OLD-artifact side (BC-4): a response that predates
    /// the new optional fields is a valid, unsurprising `Vec<DeviceCoverage>` on the new server/cockpit
    /// code — every new field simply deserializes to `None`. The companion TS-side proof (the same
    /// committed fixture, parsed as the new `DeviceCoverageRow` type) lives in
    /// `test/device-info-fixture.test.ts`.
    #[test]
    fn old_shape_coverage_fixture_parses_as_new_device_coverage_shape() {
        let raw = include_str!("../test-fixtures/pre-p1-coverage-sample.json");
        let rows: Vec<store::DeviceCoverage> =
            serde_json::from_str(raw).expect("old-shape coverage fixture parses as the new shape");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.device_pub, "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c");
        assert_eq!(row.org_id.as_deref(), Some("acme"));
        assert_eq!(row.status, "current");
        // Every P1 device-inventory field is genuinely absent from the old artifact, so it must
        // deserialize to None rather than erroring or defaulting to something misleading.
        assert!(row.console_version.is_none());
        assert!(row.runtime_version.is_none());
        assert!(row.verify_crate_version.is_none());
        assert!(row.os_platform.is_none());
        assert!(row.os_version.is_none());
        assert!(row.os_arch.is_none());
        assert!(row.policy_applied_version.is_none());
        assert!(row.policy_bundle_hash.is_none());
        assert!(row.outbox_pending.is_none());
        assert!(row.enrolled_ms.is_none());
        assert!(row.device_label.is_none());
        assert!(row.agents.is_none());
        assert!(row.info_collected_ms.is_none());

        // Re-serializing must round-trip losslessly: the new fields stay absent (skip_serializing_if),
        // so a NEW server re-emitting an old-shaped row still looks old-shaped on the wire (BC-4).
        let reserialized = serde_json::to_value(row).unwrap();
        let obj = reserialized.as_object().unwrap();
        for new_field in [
            "console_version",
            "runtime_version",
            "verify_crate_version",
            "os_platform",
            "os_version",
            "os_arch",
            "policy_applied_version",
            "policy_bundle_hash",
            "outbox_pending",
            "enrolled_ms",
            "device_label",
            "agents",
            "info_collected_ms",
        ] {
            assert!(!obj.contains_key(new_field));
        }
    }

    /// P4's BC gate (doc 22 §9-CM's acceptance line): "coverage consumed by a P2-era cockpit build
    /// still parses (new fields optional)". A P2-era `/v1/coverage` row already carries every P1
    /// device-inventory field (P2 widened the Console's OWN pull client to declare them — see
    /// `fleet_client.rs`'s doc comment — but added nothing new to the wire shape itself) and predates
    /// P3/P4 entirely: no `policy_state`-derived fields exist yet. Proves the OLD-artifact side of
    /// additive-only evolution for P4 specifically, extending the pre-P1 fixture's proof
    /// (`old_shape_coverage_fixture_parses_as_new_device_coverage_shape`) up through P2. The companion
    /// Console-side proof (the SAME committed fixture, parsed as `fleet_client::DeviceCoverage`) lives
    /// in `fleet_client.rs`.
    #[test]
    fn p2_era_coverage_fixture_parses_as_new_device_coverage_shape() {
        let raw = include_str!("../test-fixtures/p2-era-coverage-sample.json");
        let rows: Vec<store::DeviceCoverage> =
            serde_json::from_str(raw).expect("P2-era coverage fixture parses as the P4 shape");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.device_pub, "8f3c1a2b4d5e6f7089abcdef0123456789abcdef0123456789abcdef01234567");
        assert_eq!(row.device_label.as_deref(), Some("laptop-east-07"), "P1 fields still parse");
        assert_eq!(row.policy_applied_version, Some(3), "the RAW P1 echo is untouched by P4");

        // The three P4 fields are genuinely absent from a P2-era artifact — None, not a default/error.
        assert!(row.applied_policy_version.is_none());
        assert!(row.applied_bundle_hash.is_none());
        assert!(row.latest_bundle_version.is_none());

        // Round-trips losslessly: a NEW server re-emitting a P2-era-shaped row still omits the P4
        // fields on the wire (skip_serializing_if), so it stays indistinguishable from true P2 output.
        let reserialized = serde_json::to_value(row).unwrap();
        let obj = reserialized.as_object().unwrap();
        for p4_field in ["applied_policy_version", "applied_bundle_hash", "latest_bundle_version"] {
            assert!(!obj.contains_key(p4_field), "{p4_field} must not reappear on the wire");
        }
    }

    async fn get(state: Arc<AppState>, uri: &str) -> Vec<u8> {
        let resp = app(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    /// Like `get`, but doesn't assert 200 — for exercising 4xx paths (e.g. the /v1/verify range cap).
    async fn get_raw(state: Arc<AppState>, uri: &str) -> (StatusCode, Vec<u8>) {
        let resp = app(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, bytes)
    }

    /// A real device-signed envelope (seq 1, genesis) the kriya-verify core accepts: coherent counts,
    /// well-formed merkle_root, no sealed `MinimizedAction` (empty actions). Signed with `key`.
    fn build_envelope(
        key: &ed25519_dalek::SigningKey,
        seq: u64,
        prev_hash: Option<String>,
    ) -> kriya_verify::SignedEnvelope {
        use ed25519_dalek::Signer;
        use kriya_verify::*;
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let env = AttestationEnvelope {
            schema: "kriya.attestation.v1".into(),
            device_pub: device_pub.clone(),
            org_id: "acme".into(),
            business_unit: None,
            operators: vec![],
            seq,
            prev_envelope_hash: prev_hash,
            window: Window {
                from_ms: 1000,
                to_ms: 2000,
            },
            signers: vec![],
            actions: vec![],
            counts: Counts {
                receipts: 1,
                verified: 1,
                failed: 0,
                destructive: 0,
                attestations: 0,
            },
            integrity: Integrity {
                merkle_root: "ab".repeat(32),
                chain_intact: true,
                broken_sources: vec![],
            },
            non_egress: NonEgress {
                attested: false,
                attestation_count: 0,
                proof_digest: None,
            },
            compiler: CompilerInfo {
                version: "e2e".into(),
                produced_ms: 2000,
            },
            policy_state: None,
        };
        let signature = hex::encode(key.sign(&envelope_canonical_bytes(&env)).to_bytes());
        SignedEnvelope {
            envelope: env,
            public_key: device_pub,
            signature,
        }
    }

    /// Re-sign a `SignedEnvelope` after test code mutates `.envelope` directly (e.g. to set
    /// `policy_state` post-construction) — the original signature no longer matches otherwise.
    fn resign(
        mut signed: kriya_verify::SignedEnvelope,
        key: &ed25519_dalek::SigningKey,
    ) -> kriya_verify::SignedEnvelope {
        use ed25519_dalek::Signer;
        signed.signature =
            hex::encode(key.sign(&kriya_verify::envelope_canonical_bytes(&signed.envelope)).to_bytes());
        signed
    }

    // ── P6 (doc 22 §11-B2): per-route cert-role matrix ────────────────────────────────────────────
    // These drive the REAL route table via `oneshot`, INJECTING the `PeerAuth` the mTLS acceptor would
    // inject on the wire (the acceptor's own cert→role SAN parsing is unit-tested in `peer`, and the
    // whole path is exercised live over real certs by `scripts/e2e-pilot.sh`). With no injection a
    // request defaults to `Plaintext` (dev mode) — which is exactly why every pre-P6 test above still
    // passes unchanged: role enforcement is a property of the mTLS layer, and plain HTTP stays open.
    use crate::peer::PeerRole;
    use ed25519_dalek::SigningKey;

    async fn post_as(state: Arc<AppState>, uri: &str, body: String, auth: PeerAuth) -> (StatusCode, Vec<u8>) {
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .extension(auth)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes)
    }

    async fn get_as(state: Arc<AppState>, uri: &str, auth: PeerAuth) -> (StatusCode, Vec<u8>) {
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .extension(auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, bytes)
    }

    fn device_auth(key: &ed25519_dalek::SigningKey) -> PeerAuth {
        PeerAuth::Role(PeerRole::Device(hex::encode(key.verifying_key().to_bytes())))
    }

    fn heartbeat_line(key: &ed25519_dalek::SigningKey, seq_seen: u64) -> String {
        use ed25519_dalek::Signer;
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let hb = kriya_verify::Heartbeat { device_pub: device_pub.clone(), seq_seen, ts_ms: 1500 };
        json!({
            "heartbeat": hb,
            "public_key": device_pub,
            "signature": hex::encode(key.sign(&kriya_verify::heartbeat_canonical_bytes(&hb)).to_bytes()),
        })
        .to_string()
    }

    /// A DEVICE cert is 403'd on every fleet-read route — it cannot read the whole fleet's coverage or
    /// any device's evidence (the core B2 hole).
    #[tokio::test]
    async fn device_cert_forbidden_on_operator_reads() {
        let state = Arc::new(AppState::in_memory());
        let dev = device_auth(&SigningKey::from_bytes(&[1u8; 32]));

        let (status, _) = get_as(state.clone(), "/v1/coverage", dev.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "device cert may not read fleet coverage");

        let (status, _) = get_as(state.clone(), "/v1/verify?device_pub=aa", dev.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "device cert may not read /v1/verify");

        let (status, _) = post_as(state, "/v1/policy", "{}".into(), dev).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "device cert may not publish policy");
    }

    /// An OPERATOR cert is 403'd on every evidence-POST route — it cannot inject/poison device evidence.
    /// The gate short-circuits BEFORE the body is parsed, so an empty body still 403s.
    #[tokio::test]
    async fn operator_cert_forbidden_on_device_posts() {
        let state = Arc::new(AppState::in_memory());
        let op = PeerAuth::Role(PeerRole::Operator);

        for route in ["/v1/envelopes", "/v1/heartbeat", "/v1/device-info"] {
            let (status, _) = post_as(state.clone(), route, "{}".into(), op.clone()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "operator cert may not POST to {route}");
        }
    }

    /// An OPERATOR cert is allowed on the fleet reads (the cockpit's normal path).
    #[tokio::test]
    async fn operator_cert_allowed_on_fleet_reads() {
        let state = Arc::new(AppState::in_memory());
        let op = PeerAuth::Role(PeerRole::Operator);

        let (status, _) = get_as(state.clone(), "/v1/coverage", op.clone()).await;
        assert_eq!(status, StatusCode::OK, "operator reads coverage");
        // /v1/verify with a device_pub that has no data still returns 200 (an empty read-back), not 403.
        let (status, _) = get_as(state, "/v1/verify?device_pub=deadbeef", op).await;
        assert_eq!(status, StatusCode::OK, "operator reads /v1/verify");
    }

    /// A DEVICE cert may POST its OWN evidence, and is bound to its own `device_pub`: a matching
    /// envelope is accepted, a mismatched one is rejected (counted, like a forgery), and a mismatched
    /// heartbeat/device-info is a hard 403 (single-payload routes).
    #[tokio::test]
    async fn device_cert_is_bound_to_its_own_device_pub() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let env_line = serde_json::to_string(&build_envelope(&key, 1, None)).unwrap();

        // Matching device cert → the device's own envelope is accepted.
        let state = Arc::new(AppState::in_memory());
        let (status, body) = post_as(state.clone(), "/v1/envelopes", env_line.clone(), device_auth(&key)).await;
        assert_eq!(status, StatusCode::OK);
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 1, "own envelope accepted under a matching device cert");

        // A cert bound to ANOTHER device_pub → the line is rejected, nothing enters the store.
        let state = Arc::new(AppState::in_memory());
        let (status, body) = post_as(state, "/v1/envelopes", env_line, device_auth(&other)).await;
        assert_eq!(status, StatusCode::OK, "batch route stays 200; the mismatched line is rejected in-report");
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 0);
        assert_eq!(r["rejected"].as_array().unwrap().len(), 1, "the cross-device envelope is rejected");

        // Heartbeat bound to another device → hard 403.
        let state = Arc::new(AppState::in_memory());
        let (status, _) = post_as(state, "/v1/heartbeat", heartbeat_line(&key, 1), device_auth(&other)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a device cert may not heartbeat for another device");

        // Device-info bound to another device → hard 403.
        let state = Arc::new(AppState::in_memory());
        let di = serde_json::to_string(&sample_signed_device_info(&key)).unwrap();
        let (status, _) = post_as(state, "/v1/device-info", di, device_auth(&other)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a device cert may not post inventory for another device");
    }

    /// A DEVICE may pull its OWN scoped policy but not another device's; an OPERATOR may pull any (the
    /// cockpit preview/evidence path).
    #[tokio::test]
    async fn get_policy_device_own_scope_operator_any() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let dev_pub = hex::encode(key.verifying_key().to_bytes());
        let state = Arc::new(AppState::in_memory());

        // Own scope: 404 (nothing published) — NOT 403. Reaching NOT_FOUND proves the gate let it through.
        let (status, _) = get_as(state.clone(), &format!("/v1/policy?device_pub={dev_pub}"), device_auth(&key)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "device pulling its OWN scope passes the gate");

        // Another device's scope → 403.
        let (status, _) = get_as(state.clone(), "/v1/policy?device_pub=someoneelse", device_auth(&key)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a device may not pull another device's policy");

        // Operator → allowed for any device_pub (the synthetic preview id included).
        let (status, _) = get_as(state, "/v1/policy?device_pub=_fleet_console_preview_", PeerAuth::Role(PeerRole::Operator)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "operator preview passes the gate (404 = nothing published)");
    }

    /// A Rejected cert (role-less with grace OFF, or a malformed role) is 403'd on EVERY route,
    /// including `/healthz`.
    #[tokio::test]
    async fn rejected_cert_is_forbidden_everywhere() {
        let state = Arc::new(AppState::in_memory());
        let bad = PeerAuth::Rejected("no role SAN, grace off".into());
        for route in ["/healthz", "/metrics", "/v1/coverage"] {
            let (status, _) = get_as(state.clone(), route, bad.clone()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "rejected cert is 403 on {route}");
        }
        let (status, _) = post_as(state, "/v1/envelopes", "{}".into(), bad).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "rejected cert is 403 on POST too");
    }

    /// BC-4 grace: a Legacy (role-less, grace-on) cert behaves exactly as pre-P6 — every route, no
    /// `device_pub` binding — so an un-migrated fleet keeps working during cert reissue.
    #[tokio::test]
    async fn legacy_grace_behaves_like_pre_p6() {
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let env_line = serde_json::to_string(&build_envelope(&key, 1, None)).unwrap();

        // A legacy cert may read the fleet (operator-ish) AND post evidence (device-ish) — both work,
        // and evidence for ANY device_pub is accepted (no binding), exactly as before P6.
        let state = Arc::new(AppState::in_memory());
        let (status, _) = get_as(state.clone(), "/v1/coverage", PeerAuth::Legacy).await;
        assert_eq!(status, StatusCode::OK, "legacy grace reads coverage");
        let (status, body) = post_as(state, "/v1/envelopes", env_line, PeerAuth::Legacy).await;
        assert_eq!(status, StatusCode::OK);
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 1, "legacy grace posts evidence with no device_pub binding");
    }

    /// The ⭐ end-to-end pilot demo (2.11): device emits a signed envelope + heartbeat → kriyad ingests
    /// and RE-VERIFIES offline → an auditor reads the bytes back over /v1/verify, re-verifies the SAME
    /// bytes, and checks the tail-truncation anchor → coverage reads current, then silent once the device
    /// goes quiet. Finally the air-gap variant proves sneaker-net == network: the identical signed bytes,
    /// side-loaded from a file, yield the identical stored bytes and verdict.
    #[tokio::test]
    async fn e2e_pilot_demo() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7u8; 32]); // deterministic (no RNG in tests)
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let env_line = serde_json::to_string(&build_envelope(&key, 1, None)).unwrap();

        let hb = kriya_verify::Heartbeat {
            device_pub: device_pub.clone(),
            seq_seen: 1,
            ts_ms: 1500,
        };
        let hb_line = json!({
            "heartbeat": hb,
            "public_key": device_pub,
            "signature": hex::encode(key.sign(&kriya_verify::heartbeat_canonical_bytes(&hb)).to_bytes()),
        })
        .to_string();

        // 1. Device → kriyad: ingest + offline re-verify (kriyad never trusts the device).
        let state = Arc::new(AppState::in_memory());
        let (_, body) = post(state.clone(), "/v1/envelopes", env_line.clone()).await;
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            r["accepted"], 1,
            "kriyad re-verified + ingested the envelope"
        );
        let (status, _) = post(state.clone(), "/v1/heartbeat", hb_line).await;
        assert_eq!(status, StatusCode::OK);

        // 2. Auditor → /v1/verify: byte-identical read-back, re-verified offline, tail anchored.
        let rb: Value = serde_json::from_slice(
            &get(
                state.clone(),
                &format!("/v1/verify?device_pub={device_pub}"),
            )
            .await,
        )
        .unwrap();
        let returned = rb["envelopes"][0].as_str().unwrap();
        assert_eq!(returned, env_line, "server returned the EXACT signed bytes");
        let returned_val: Value = serde_json::from_str(returned).unwrap();
        assert!(
            kriya_verify::verify_envelope(&returned_val).is_ok(),
            "auditor re-verifies the same bytes offline"
        );
        let hb_val: Value = serde_json::from_str(rb["heartbeat"].as_str().unwrap()).unwrap();
        assert!(kriya_verify::verify_heartbeat(&hb_val).is_ok());
        let top = returned_val["envelope"]["seq"].as_u64().unwrap();
        let seen = hb_val["heartbeat"]["seq_seen"].as_u64().unwrap();
        assert!(top >= seen, "tail anchor: returned_top_seq >= seq_seen");

        // 3. Coverage: current now; silent once the device goes quiet (past N·H).
        let cov: Value = serde_json::from_slice(&get(state.clone(), "/v1/coverage").await).unwrap();
        assert_eq!(cov[0]["status"], "current");
        assert_eq!(cov[0]["device_pub"], device_pub);
        let silent = state
            .store
            .coverage(now_ms() + 10 * 60 * 60 * 1000, state.silent_after_ms, None);
        assert_eq!(silent[0].status, "silent", "a quiet device flips to silent");

        // 4. Air-gap variant: the SAME signed bytes, side-loaded from a file, ingest identically.
        let airgap = AppState::in_memory();
        assert_eq!(
            ingest_ndjson(&airgap, &env_line, None).accepted,
            1,
            "sneaker-net == network"
        );
        let rb2 = airgap.store.read_back(&device_pub, 0, u64::MAX);
        assert_eq!(
            rb2.envelopes[0], env_line,
            "air-gap read-back is byte-identical to the wire path"
        );
    }

    /// doc 22 §11 DoS hardening: /v1/verify rejects an EXPLICIT window wider than `MAX_VERIFY_WINDOW`
    /// with 400 + a JSON error body, while a request with no range (or a small range) — the legacy
    /// caller's shape — keeps working exactly as before (BC-4: additive, never breaks an old client).
    #[tokio::test]
    async fn get_verify_rejects_oversized_window_but_keeps_legacy_callers_working() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let state = Arc::new(AppState::in_memory());
        let env_line = serde_json::to_string(&build_envelope(&key, 1, None)).unwrap();
        let (_, body) = post(state.clone(), "/v1/envelopes", env_line.clone()).await;
        let r: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(r["accepted"], 1);

        // An explicit window > 10_000 is rejected with 400 + a JSON error body.
        let (status, body) = get_raw(
            state.clone(),
            &format!("/v1/verify?device_pub={device_pub}&from_seq=0&to_seq=10001"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "oversized window rejected");
        let err: Value = serde_json::from_slice(&body)
            .expect("the 400 body is JSON, not the plain-text style used elsewhere");
        assert_eq!(err["error"], "window_too_large");
        assert_eq!(err["max_window"], 10_000);

        // A window exactly AT the cap is accepted (boundary — not off-by-one rejected).
        let (status, _) = get_raw(
            state.clone(),
            &format!("/v1/verify?device_pub={device_pub}&from_seq=0&to_seq=10000"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a window exactly at the cap is fine");

        // A legacy caller with NO range at all keeps working (defaults to 0..=u64::MAX server-side,
        // which is never rejected at the route layer — it's capped, not refused, at the data layer).
        let (status, body) =
            get_raw(state.clone(), &format!("/v1/verify?device_pub={device_pub}")).await;
        assert_eq!(status, StatusCode::OK, "no-range legacy request still works");
        let rb: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            rb["envelopes"][0].as_str().unwrap(),
            env_line,
            "legacy no-range read-back is unchanged"
        );

        // A small explicit range (the common case) is unaffected.
        let (status, _) = get_raw(
            state,
            &format!("/v1/verify?device_pub={device_pub}&from_seq=0&to_seq=5"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a small explicit range still works");
    }

    /// doc 22 §11 DoS hardening, data layer: `store::read_back` never returns more than
    /// `READ_BACK_ROW_CAP` rows, even when asked for an enormous (or fully unbounded) window — the
    /// defense-in-depth backstop behind the route-layer 400 in `get_verify`.
    #[test]
    fn read_back_row_cap_bounds_result_size_regardless_of_window() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let store = store::Store::open_in_memory().unwrap();

        // Insert more rows than the cap so the cap is actually exercised, not vacuously true.
        let n: u64 = store::READ_BACK_ROW_CAP as u64 + 25;
        let mut prev_hash: Option<String> = None;
        for seq in 1..=n {
            let env = build_envelope(&key, seq, prev_hash.clone());
            let line = serde_json::to_string(&env).unwrap();
            prev_hash = Some(kriya_verify::sha256_hex(&kriya_verify::canonical_json_bytes(
                &serde_json::to_value(&env).unwrap(),
            )));
            store
                .insert_envelope(&env, line.as_bytes(), seq)
                .expect("insert");
        }

        // Fully unbounded (the legacy no-range default) is capped, not exhaustive.
        let rb = store.read_back(&device_pub, 0, u64::MAX);
        assert_eq!(
            rb.envelopes.len(),
            store::READ_BACK_ROW_CAP as usize,
            "unbounded read-back is capped at READ_BACK_ROW_CAP, not the full {n} rows"
        );
        assert_eq!(
            rb.envelopes[0],
            serde_json::to_string(&build_envelope(&key, 1, None)).unwrap(),
            "capped read-back still returns the earliest rows in seq order, byte-identical"
        );

        // A small range well under the cap is returned in full, unaffected.
        let small = store.read_back(&device_pub, 1, 5);
        assert_eq!(small.envelopes.len(), 5, "a small range is unaffected by the cap");
    }

    /// Emitter (not a test): regenerate the committed pilot fixtures the real-binary demo
    /// (`scripts/e2e-pilot.sh`) drives — a matching device envelope + heartbeat from a fixed key.
    /// Run with `cargo test -p kriya-aggregator emit_pilot_fixtures -- --ignored`.
    #[tokio::test]
    #[ignore = "emitter: rewrites test-fixtures/pilot-*"]
    async fn emit_pilot_fixtures() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let device_pub = hex::encode(key.verifying_key().to_bytes());

        // A real 2-envelope hash chain: seq 1 (genesis) then seq 2 whose prev_envelope_hash is the
        // sha256 of seq 1's canonical signed bytes — so a server that drops seq 2 is provably hiding
        // the newest receipt (the tail-truncation demo beat).
        let env1 = build_envelope(&key, 1, None);
        let env1_line = serde_json::to_string(&env1).unwrap();
        let prev = kriya_verify::sha256_hex(&kriya_verify::canonical_json_bytes(
            &serde_json::to_value(&env1).unwrap(),
        ));
        let env2 = build_envelope(&key, 2, Some(prev));
        let env2_line = serde_json::to_string(&env2).unwrap();

        let hb = kriya_verify::Heartbeat {
            device_pub: device_pub.clone(),
            seq_seen: 2,
            ts_ms: 1500,
        };
        let hb_line = json!({
            "heartbeat": hb,
            "public_key": device_pub,
            "signature": hex::encode(key.sign(&kriya_verify::heartbeat_canonical_bytes(&hb)).to_bytes()),
        })
        .to_string();
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/test-fixtures");
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            format!("{dir}/pilot-outbox.ndjson"),
            format!("{env1_line}\n{env2_line}\n"),
        )
        .unwrap();
        std::fs::write(
            format!("{dir}/pilot-heartbeat.json"),
            format!("{hb_line}\n"),
        )
        .unwrap();
        std::fs::write(
            format!("{dir}/pilot-device-pub.txt"),
            format!("{device_pub}\n"),
        )
        .unwrap();
        eprintln!("wrote pilot fixtures for device {device_pub}");
    }
}
