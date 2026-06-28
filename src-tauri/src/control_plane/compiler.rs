//! The Evidence Compiler (1.14–1.18) — the device's window loop.
//!
//! `audit-changed` only marks receipts *pending*; the fixed, boundary-aligned window-W timer (1.14) is
//! what closes a window and emits an envelope. Each boundary the Compiler tails the NEW receipt lines
//! per source since the last window (1.15), windowed-chain-checks them (seeded from the prior tail),
//! builds + signs an envelope via the 1.10 builder, and — even when the window is empty — emits it so
//! `seq` stays dense (1.16). Time + the audit dir + the keys are injected, so the logic is testable
//! without a clock, Tauri, or `$HOME`. The `lib.rs` spawn loop (1.18) wires it to the real watcher.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::control_plane::envelope::{build_signed_envelope, SourceWindow, WindowInput};
use kriya_verify::{sha256_hex, SignedEnvelope};

/// Default window length W — the pilot's 1h cadence (LLD §B.3.1). Boundary-aligned.
pub const DEFAULT_WINDOW_MS: u64 = 60 * 60 * 1000;

/// The Compiler's window state (1.14).
pub struct Compiler {
    window_ms: u64,
    /// The `to_ms` of the last window the Compiler closed (0 = none closed yet).
    last_closed_to_ms: u64,
    /// New receipts have arrived since the last closed window.
    pending: bool,
}

impl Compiler {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms: window_ms.max(1),
            last_closed_to_ms: 0,
            pending: false,
        }
    }

    /// Mark that new receipts arrived (called on each `audit-changed` tick). Does NOT emit.
    pub fn mark_pending(&mut self) {
        self.pending = true;
    }

    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// The boundary-aligned window that has CLOSED at or before `now_ms` and not yet been emitted, if
    /// any: `(from_ms, to_ms)` where `to_ms` is the most recent W boundary ≤ `now_ms` and `from_ms =
    /// to_ms − W`. `None` while still inside the already-closed-through window. Windows tile with no
    /// gaps or overlaps (boundary-aligned, NOT first/last receipt timestamps).
    pub fn due_window(&self, now_ms: u64) -> Option<(u64, u64)> {
        let boundary = (now_ms / self.window_ms) * self.window_ms;
        (boundary > self.last_closed_to_ms)
            .then(|| (boundary.saturating_sub(self.window_ms), boundary))
    }

    /// Record that the window ending at `to_ms` has been emitted; clears `pending`.
    pub fn close_window(&mut self, to_ms: u64) {
        self.last_closed_to_ms = to_ms;
        self.pending = false;
    }
}

// ── Per-source compile + durable state (1.15) ─────────────────────────────────────────────────────

/// Per-source consumption state: how many lines we've already folded into an envelope, and the hash of
/// the last consumed line (to seed the next window's chain check).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceState {
    pub consumed: usize,
    pub tail_hash: Option<String>,
}

/// The Compiler's durable per-source consumption state. Persisted so a restart resumes the chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompilerState {
    pub sources: BTreeMap<String, SourceState>,
}

fn state_path() -> PathBuf {
    crate::audit::console_dir().join("compiler-state.json")
}

pub fn load_state() -> CompilerState {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_state(state: &CompilerState) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing compiler state: {e}"))
}

/// Read the NEW receipt lines per source since `state`, as `SourceWindow`s (each seeded with that
/// source's prior tail hash for the windowed chain check), plus the advanced state. Sources are the
/// `*.jsonl` files in `audit_dir`, in sorted (total-order) order. Pure read — no disk writes.
pub fn collect_new_windows(
    audit_dir: &Path,
    state: &CompilerState,
) -> (Vec<SourceWindow>, CompilerState) {
    let mut windows = Vec::new();
    let mut next = state.clone();

    let mut files: Vec<PathBuf> = std::fs::read_dir(audit_dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("jsonl"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();

    for path in files {
        let source = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let st = state.sources.get(&source).cloned().unwrap_or_default();
        let consumed = st.consumed.min(lines.len()); // tolerate truncation
        let new_lines: Vec<String> = lines[consumed..].iter().map(|s| s.to_string()).collect();
        // Advance: consumed = all lines; tail = sha256 of the last line (keep the old tail if empty).
        let tail_hash = lines
            .last()
            .map(|l| sha256_hex(l.as_bytes()))
            .or_else(|| st.tail_hash.clone());
        next.sources.insert(
            source.clone(),
            SourceState {
                consumed: lines.len(),
                tail_hash,
            },
        );
        if !new_lines.is_empty() {
            windows.push(SourceWindow {
                source,
                lines: new_lines,
                prev_tail_hash: st.tail_hash,
            });
        }
    }
    (windows, next)
}

/// Compile one window into a signed envelope (1.15). When no new receipts arrived, the window is empty
/// but the envelope is still built + signed so `seq` stays dense (1.16). Pure: reads `audit_dir`,
/// returns the envelope + the advanced state — the caller appends to the outbox and persists state.
#[allow(clippy::too_many_arguments)]
pub fn compile_window(
    audit_dir: &Path,
    state: &CompilerState,
    window: (u64, u64),
    seq: u64,
    prev_envelope_hash: Option<String>,
    org_id: &str,
    business_unit: Option<&str>,
    produced_ms: u64,
    key: &SigningKey,
    pepper: &[u8],
) -> Result<(SignedEnvelope, CompilerState), String> {
    let (sources, next) = collect_new_windows(audit_dir, state);
    let input = WindowInput {
        org_id: org_id.to_string(),
        business_unit: business_unit.map(str::to_string),
        window_from_ms: window.0,
        window_to_ms: window.1,
        seq,
        prev_envelope_hash,
        produced_ms,
        sources,
    };
    let signed = build_signed_envelope(&input, key, pepper)?;
    Ok((signed, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kriya_verify::{canonical_json_bytes, verify_envelope};

    #[test]
    fn pending_flag_and_boundary_aligned_windows() {
        let mut c = Compiler::new(1000); // W = 1s
        assert!(!c.is_pending());
        c.mark_pending();
        assert!(c.is_pending());

        assert_eq!(c.due_window(500), None, "still inside the first window");
        assert_eq!(
            c.due_window(1500),
            Some((0, 1000)),
            "the W boundary closes [0,1000)"
        );

        c.close_window(1000);
        assert!(!c.is_pending(), "closing a window clears pending");
        assert_eq!(
            c.due_window(1500),
            None,
            "already-closed window is not due again"
        );

        assert_eq!(
            c.due_window(2500),
            Some((1000, 2000)),
            "windows tile exactly"
        );
        c.close_window(2000);
        assert_eq!(c.due_window(2999), None);
        assert_eq!(c.due_window(3000), Some((2000, 3000)));
    }

    /// Plain (unsigned) but hash-chained receipt lines — enough to exercise tailing + the windowed
    /// chain check + state advance (the verified-receipt rollup is covered by the builder tests, 1.10).
    fn chained_lines(actions: &[&str]) -> Vec<String> {
        let mut lines = Vec::new();
        let mut prev: Option<String> = None;
        for a in actions {
            let line = match &prev {
                None => format!(r#"{{"action_id":"{a}","success":true}}"#),
                Some(h) => format!(r#"{{"action_id":"{a}","success":true,"prev_hash":"{h}"}}"#),
            };
            prev = Some(sha256_hex(line.as_bytes()));
            lines.push(line);
        }
        lines
    }

    fn write_source(dir: &Path, name: &str, lines: &[String]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn compile_tails_new_lines_and_advances_state() {
        let dir = std::env::temp_dir().join(format!("kriya-compile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_source(
            &dir,
            "notes.jsonl",
            &chained_lines(&["create_note", "delete_note"]),
        );
        let key = SigningKey::from_bytes(&[11u8; 32]);

        // Window 1: covers both new lines, builds a verifiable envelope, advances state to consumed=2.
        let (e1, st1) = compile_window(
            &dir,
            &CompilerState::default(),
            (0, 1000),
            1,
            None,
            "acme",
            None,
            1000,
            &key,
            &[3u8; 32],
        )
        .unwrap();
        assert!(verify_envelope(&serde_json::to_value(&e1).unwrap()).is_ok());
        assert_eq!(e1.envelope.counts.receipts, 2);
        assert!(e1.envelope.integrity.chain_intact, "chained lines → intact");
        assert_eq!(st1.sources["notes.jsonl"].consumed, 2);

        // Window 2 (no new receipts): an EMPTY but valid signed envelope keeps seq DENSE (1.16),
        // chained to window 1 — an idle device is distinguishable from a withholding one.
        let prev = sha256_hex(&canonical_json_bytes(&serde_json::to_value(&e1).unwrap()));
        let (e2, _st2) = compile_window(
            &dir,
            &st1,
            (1000, 2000),
            2,
            Some(prev),
            "acme",
            None,
            2000,
            &key,
            &[3u8; 32],
        )
        .unwrap();
        assert!(verify_envelope(&serde_json::to_value(&e2).unwrap()).is_ok());
        assert_eq!(e2.envelope.counts.receipts, 0, "empty window");
        assert_eq!(e2.envelope.seq, 2, "seq stays dense across an idle window");
        assert!(e2.envelope.actions.is_empty());

        // The two envelopes form an intact chain (dense + chained empties).
        let chain = kriya_verify::envelope_chain_break(&[
            serde_json::to_value(&e1).unwrap(),
            serde_json::to_value(&e2).unwrap(),
        ]);
        assert_eq!(chain, None, "consecutive (incl. empty) windows chain");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
