//! kriyad — the kriya-aggregator server (single static binary; single-tenant; runs inside the
//! customer's own boundary). Ingests signed `AttestationEnvelope`s over mTLS, re-verifies them OFFLINE
//! with `kriya-verify` (it never trusts the device), stores ONLY signed metadata in append-only SQLite,
//! and serves trustless read-back + coverage. No outbound calls; no kriya-cloud dependency.

mod config;
mod license;
mod store;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Value};

/// `silent` when a device hasn't been seen for N·H (N=3, H=1h) — the coverage threshold (LLD §B.6).
const SILENT_AFTER_MS: u64 = 3 * 60 * 60 * 1000;

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
}

impl AppState {
    pub fn new(store: store::Store) -> Self {
        Self {
            metrics: Metrics::default(),
            store,
        }
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self::new(store::Store::open_in_memory().expect("in-memory store"))
    }
}

/// The HTTP app (transport-agnostic, so it's testable without a socket via `oneshot`).
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/v1/envelopes", post(post_envelopes))
        .route("/v1/heartbeat", post(post_heartbeat))
        .route("/v1/coverage", get(get_coverage))
        .route("/v1/verify", get(get_verify))
        .with_state(state)
}

/// GET /v1/coverage[?org_id=…] — per-device current/behind/silent.
async fn get_coverage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Vec<store::DeviceCoverage>> {
    let org = q.get("org_id").map(String::as_str);
    Json(state.store.coverage(now_ms(), SILENT_AFTER_MS, org))
}

/// GET /v1/verify?device_pub=…&from_seq=…&to_seq=… — trustless read-back: the EXACT stored signed
/// bytes for the contiguous slice + the device's most-recent signed heartbeat (the tail anchor).
async fn get_verify(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<store::Readback>, (StatusCode, String)> {
    let device_pub = q
        .get("device_pub")
        .ok_or((StatusCode::BAD_REQUEST, "device_pub required\n".to_string()))?;
    let from_seq = q.get("from_seq").and_then(|s| s.parse().ok()).unwrap_or(0);
    let to_seq = q
        .get("to_seq")
        .and_then(|s| s.parse().ok())
        .unwrap_or(u64::MAX);
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

/// POST /v1/envelopes — NDJSON batch. Re-verify each envelope OFFLINE (the anti-forgery guarantee),
/// then gap-tolerant idempotent insert. Out-of-order / missing seqs are a coverage gap (→ /v1/coverage),
/// never a 4xx; only forged/malformed/incoherent envelopes are rejected (and counted, not dropped).
async fn post_envelopes(State(state): State<Arc<AppState>>, body: String) -> Json<IngestReport> {
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
    Json(report)
}

/// POST /v1/heartbeat — one signed heartbeat. Verify, append to the liveness log, update coverage.
async fn post_heartbeat(State(state): State<Arc<AppState>>, body: String) -> (StatusCode, String) {
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

async fn healthz() -> &'static str {
    "ok\n"
}

async fn metrics(State(state): State<Arc<AppState>>) -> String {
    let m = &state.metrics;
    format!(
        "# HELP kriyad_envelopes_total Accepted envelopes.\n\
         # TYPE kriyad_envelopes_total counter\n\
         kriyad_envelopes_total {}\n\
         kriyad_envelopes_rejected_total {}\n\
         kriyad_heartbeats_total {}\n",
        m.envelopes_total.load(Ordering::Relaxed),
        m.envelopes_rejected_total.load(Ordering::Relaxed),
        m.heartbeats_total.load(Ordering::Relaxed),
    )
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
    let state = Arc::new(AppState::new(store));
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .expect("bind");
    eprintln!(
        "kriyad listening on http://{} (mTLS arrives in 2.4)",
        config.bind
    );
    axum::serve(listener, app(state)).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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
}
