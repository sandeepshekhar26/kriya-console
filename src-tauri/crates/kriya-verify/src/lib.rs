//! kriya-verify — the shared, Tauri-free trust core for the kriya control plane.
//!
//! Extracted from the Console's compiled verifier so the device Console, the `kriyad` aggregator,
//! and the auditor CLI all verify the SAME bytes with the SAME code (the `kriya-verify` seam named in
//! CLAUDE.md). The canonical signed-byte format mirrors `crates/kriya/src/audit.rs` exactly (kept
//! honest by the `canonical_parity` test): a receipt is signed as `serde_json::to_vec(&receipt)` with
//! fields in declaration order — `step_id, action_id, params, success, ts_ms`, then optional `actor`
//! (R8), then optional `prev_hash` (R20) — both skipped when absent, and `params` object keys
//! recursively sorted (R21).
//!
//! Module map (grows across Phase 0–1): [`canonical`] (R21 key-sort + SHA-256), [`sig`] (the raw
//! Ed25519 check), [`receipts`] (receipt verification + the hash-chain). Merkle, the windowed-chain
//! helper, the license verifier, and the envelope schema land in later items.
#![forbid(unsafe_code)]

mod canonical;
mod receipts;
mod sig;

pub use canonical::{canonical_value, sha256_hex};
pub use receipts::{chain_break, load_rows, verify_value, Actor, AuditRow};
pub use sig::verify_detached;
