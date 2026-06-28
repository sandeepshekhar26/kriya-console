//! Re-export shim — the authoritative receipt verifier now lives in the shared `kriya-verify` crate
//! (extracted in 0.3). The Console keeps importing `crate::receipts::*` unchanged, but the symbols are
//! the SAME compiled code the `kriyad` server and the auditor CLI link, so there is exactly one
//! verifier implementation, not three (the `kriya-verify` seam in CLAUDE.md). The canonical
//! signed-byte format and the parity tests live with the code in `kriya-verify`.

pub use kriya_verify::{
    canonical_value, chain_break, load_rows, sha256_hex, verify_detached, verify_value, Actor,
    AuditRow,
};
