//! The device's hash-chained OUTBOX (1.11) — undelivered signed envelopes append here, tamper-evident
//! (each envelope chains to the previous via `prev_envelope_hash`). The push client (2.7) drains it; in
//! an air gap it is literally the file an operator carries across on approved media. Append-only +
//! durable; the verifier is transport-agnostic, so sneaker-net and the wire are the same path.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::Value;

use kriya_verify::{canonical_json_bytes, envelope_chain_break, sha256_hex, SignedEnvelope};

fn outbox_path() -> PathBuf {
    crate::audit::console_dir().join("outbox.jsonl")
}

/// What the next envelope must carry to continue the chain.
pub struct OutboxHead {
    pub next_seq: u64,
    pub prev_envelope_hash: Option<String>,
}

/// Append a signed envelope to the outbox (one compact JSON line; creating the file + parents).
pub fn append(signed: &SignedEnvelope) -> Result<(), String> {
    append_to(&outbox_path(), signed)
}

/// Read the outbox tail → the seq + `prev_envelope_hash` the NEXT envelope must use. Genesis
/// (`next_seq = 1`, `prev = None`) when the outbox is absent/empty.
pub fn head() -> Result<OutboxHead, String> {
    head_from(&read_lines_from(&outbox_path())?)
}

/// The 1-based line of the first envelope-chain break in the outbox (deletion / reorder / forgery), or
/// `None` if intact.
pub fn chain_break() -> Result<Option<usize>, String> {
    chain_break_of(&read_lines_from(&outbox_path())?)
}

/// How many envelope lines currently sit in the outbox — a simple depth/health signal (P1's
/// `DeviceInfo.outbox_pending`). The outbox is append-only with no delivery-ack/truncate mechanism
/// today (that's the push client's concern, not this module's), so this is an upper bound on "truly
/// undelivered" rather than an exact count — see `device_info.rs::outbox_pending`'s doc comment for the
/// full reasoning. `Ok(0)` (never an error) when the outbox file doesn't exist yet.
pub fn line_count() -> Result<u64, String> {
    Ok(read_lines_from(&outbox_path())?.len() as u64)
}

// ── path-injected internals (so the logic is testable without touching $HOME) ─────────────────────

fn append_to(path: &Path, signed: &SignedEnvelope) -> Result<(), String> {
    let line = serde_json::to_string(signed).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("opening outbox {}: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("writing outbox: {e}"))?;
    Ok(())
}

fn read_lines_from(path: &Path) -> Result<Vec<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(t
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("reading outbox {}: {e}", path.display())),
    }
}

fn head_from(lines: &[String]) -> Result<OutboxHead, String> {
    match lines.last() {
        None => Ok(OutboxHead {
            next_seq: 1,
            prev_envelope_hash: None,
        }),
        Some(last) => {
            let v: Value =
                serde_json::from_str(last).map_err(|e| format!("outbox tail is malformed: {e}"))?;
            let seq = v
                .get("envelope")
                .and_then(|e| e.get("seq"))
                .and_then(Value::as_u64)
                .ok_or("outbox tail has no envelope.seq")?;
            Ok(OutboxHead {
                next_seq: seq + 1,
                prev_envelope_hash: Some(sha256_hex(&canonical_json_bytes(&v))),
            })
        }
    }
}

fn chain_break_of(lines: &[String]) -> Result<Option<usize>, String> {
    let values: Vec<Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("outbox parse: {e}"))?;
    Ok(envelope_chain_break(&values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::envelope::{build_signed_envelope, WindowInput};
    use ed25519_dalek::SigningKey;

    /// A minimal (empty-window) envelope at `seq`, chained to `prev`. Empty windows still verify.
    fn envelope(seq: u64, prev: Option<String>) -> SignedEnvelope {
        let input = WindowInput {
            org_id: "acme".into(),
            business_unit: None,
            window_from_ms: 0,
            window_to_ms: 1,
            seq,
            prev_envelope_hash: prev,
            produced_ms: 1,
            sources: vec![],
        };
        build_signed_envelope(&input, &SigningKey::from_bytes(&[11u8; 32]), &[3u8; 32]).unwrap()
    }

    #[test]
    fn append_chains_and_a_deletion_is_detected() {
        let dir = std::env::temp_dir().join(format!("kriya-outbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("outbox.jsonl");

        let e1 = envelope(1, None);
        let h1 = sha256_hex(&canonical_json_bytes(&serde_json::to_value(&e1).unwrap()));
        let e2 = envelope(2, Some(h1));
        append_to(&path, &e1).unwrap();
        append_to(&path, &e2).unwrap();

        let lines = read_lines_from(&path).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            chain_break_of(&lines).unwrap(),
            None,
            "an intact outbox chain"
        );

        // head tells the next envelope its seq + prev.
        let h = head_from(&lines).unwrap();
        assert_eq!(h.next_seq, 3);
        assert!(h.prev_envelope_hash.is_some());

        // Drop the genesis → the survivor declares a prev with nothing before it → break at line 1.
        assert_eq!(chain_break_of(&lines[1..]).unwrap(), Some(1));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
