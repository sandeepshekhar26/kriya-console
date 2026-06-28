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
mod classify;
mod envelope;
mod heartbeat;
mod license;
mod merkle;
mod receipts;
pub mod redact;
mod sig;

pub use canonical::{canonical_json_bytes, canonical_value, sha256_hex};
pub use classify::is_destructive;
pub use envelope::{
    envelope_canonical_bytes, envelope_chain_break, verify_envelope, AttestationEnvelope,
    CompilerInfo, Counts, Integrity, NonEgress, OperatorRollup, SignedEnvelope, SignerRollup,
    Window,
};
pub use heartbeat::{heartbeat_canonical_bytes, verify_heartbeat, Heartbeat, SignedHeartbeat};
pub use license::{
    canonical_license_bytes, verify_token, LicensePayload, LicenseToken, ISSUER_PUBLIC_KEY_HEX,
};
pub use merkle::{merkle_proof, merkle_root, merkle_verify};
pub use receipts::{chain_break, chain_continues_from, load_rows, verify_value, Actor, AuditRow};
pub use redact::{minimize_window, Allowlist, MinimizedAction};
pub use sig::verify_detached;
