//! Control-plane device modules (Phase 1+) — DORMANT by construction.
//!
//! This whole subtree is compiled ONLY under the off-by-default `control-plane` Cargo feature, so a
//! default `tauri build` links none of it — and none of its deps (`hmac`, and `reqwest`/`rustls` via
//! [`push`]). That is the **build-time** half of the dormancy firewall (1.4). Within the feature build,
//! a second **runtime** gate ([`enrollment::control_plane_active`], 1.3) keeps everything inert unless
//! the license grants `control-plane` AND `~/.kriya/console/enrollment.json` exists.
//!
//! Modules: [`enrollment`] (1.3), [`envelope`] (1.8/1.10), [`redact`] (1.9), [`outbox`] (1.11),
//! [`compiler`] (1.14–1.18), [`push`] (2.7 — mTLS + air-gap transport), [`fleet_client`] (P0 — the
//! OPERATOR cockpit's outbound mTLS pull client), [`fleet`] (P0 — the Tauri IPC layer over it),
//! [`device_info`] (P1 — the signed DeviceInfo inventory beacon, doc 22 §7), [`org_key`] (P3 — the
//! operator-side org policy key, OS-keychain-backed), [`policy`] (P3 — the device policy downlink:
//! pull, verify, apply, anti-rollback), [`fleet_evidence`] (P5 — the org-wide, envelope-native
//! assessor-ready evidence export, doc 22 §9).

pub mod compiler;
pub mod device_info;
pub mod drilldown;
pub mod enrollment;
pub mod envelope;
pub mod fleet;
pub mod fleet_client;
pub mod fleet_evidence;
pub mod org_key;
pub mod outbox;
pub mod policy;
pub mod push;
pub mod redact;
