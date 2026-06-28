//! Control-plane device modules (Phase 1+) — DORMANT by construction.
//!
//! This whole subtree is compiled ONLY under the off-by-default `control-plane` Cargo feature, so a
//! default `tauri build` links none of it — and none of its deps (`hmac`, and `reqwest`/`rustls` via
//! [`push`]). That is the **build-time** half of the dormancy firewall (1.4). Within the feature build,
//! a second **runtime** gate ([`enrollment::control_plane_active`], 1.3) keeps everything inert unless
//! the license grants `control-plane` AND `~/.kriya/console/enrollment.json` exists.
//!
//! Modules: [`enrollment`] (1.3), [`envelope`] (1.8/1.10), [`redact`] (1.9), [`outbox`] (1.11),
//! [`compiler`] (1.14–1.18), [`push`] (2.7 — mTLS + air-gap transport).

pub mod compiler;
pub mod enrollment;
pub mod envelope;
pub mod outbox;
pub mod push;
pub mod redact;
