//! kriya-verify — the shared, Tauri-free trust core for the kriya control plane.
//!
//! Extracted from the Console's compiled verifier so the device Console, the `kriyad` aggregator,
//! and the auditor CLI all verify the SAME bytes with the SAME code (the `kriya-verify` seam named in
//! CLAUDE.md). Receipt + envelope + license verification, canonical JSON (R21), the SHA-256
//! hash-chain, and the RFC-6962 Merkle tree land here across Phase 0.
//!
//! This is the empty scaffold (roadmap 0.2); the receipt trust core moves in next (0.3).
#![forbid(unsafe_code)]
