//! kriyad — the kriya-aggregator server (single static binary; single-tenant; runs inside the
//! customer's own boundary). Ingests signed `AttestationEnvelope`s over mTLS, re-verifies them OFFLINE
//! with `kriya-verify` (it never trusts the device), stores ONLY signed metadata in append-only SQLite,
//! and serves trustless read-back + coverage. No outbound calls; no kriya-cloud dependency.

mod config;
mod license;
mod store;
mod tls;

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
    Json(ingest_ndjson(&state, &body))
}

/// Verify + ingest an NDJSON batch. Shared by the HTTP handler (online mode) and the `ingest-file`
/// subcommand (air-gap side-load) — the verifier is transport-agnostic, so both run the SAME offline
/// re-verification + gap-tolerant idempotent insert. Only forged/malformed/incoherent lines are
/// rejected (counted, not dropped); out-of-order / missing seqs are a coverage gap, never an error.
fn ingest_ndjson(state: &AppState, body: &str) -> IngestReport {
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
    report
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
    let state = AppState::new(store);

    // Air-gap receive: `kriyad ingest-file <outbox.ndjson>` side-loads signed bytes carried across on
    // approved media, runs the SAME offline re-verification as the wire path, then exits (no serve).
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(i) = args.iter().position(|a| a == "ingest-file") {
        let path = args
            .get(i + 1)
            .expect("usage: kriyad ingest-file <file.ndjson>");
        let body = std::fs::read_to_string(path).expect("read ingest file");
        let report = ingest_ndjson(&state, &body);
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
            eprintln!("kriyad listening on https://{} (mTLS)", config.bind);
            axum_server::bind_rustls(
                config.bind,
                axum_server::tls_rustls::RustlsConfig::from_config(tls_config),
            )
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
        };
        let signature = hex::encode(key.sign(&envelope_canonical_bytes(&env)).to_bytes());
        SignedEnvelope {
            envelope: env,
            public_key: device_pub,
            signature,
        }
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
            .coverage(now_ms() + 10 * 60 * 60 * 1000, SILENT_AFTER_MS, None);
        assert_eq!(silent[0].status, "silent", "a quiet device flips to silent");

        // 4. Air-gap variant: the SAME signed bytes, side-loaded from a file, ingest identically.
        let airgap = AppState::in_memory();
        assert_eq!(
            ingest_ndjson(&airgap, &env_line).accepted,
            1,
            "sneaker-net == network"
        );
        let rb2 = airgap.store.read_back(&device_pub, 0, u64::MAX);
        assert_eq!(
            rb2.envelopes[0], env_line,
            "air-gap read-back is byte-identical to the wire path"
        );
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
