//! kriyad — the kriya-aggregator server (single static binary; single-tenant; runs inside the
//! customer's own boundary). Ingests signed `AttestationEnvelope`s over mTLS, re-verifies them OFFLINE
//! with `kriya-verify` (it never trusts the device), stores ONLY signed metadata in append-only SQLite,
//! and serves trustless read-back + coverage. No outbound calls; no kriya-cloud dependency.

mod config;
mod license;
mod store;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{extract::State, routing::get, Router};

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
        .with_state(state)
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
}
