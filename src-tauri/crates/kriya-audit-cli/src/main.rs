//! kriya-audit-cli (`kriya-audit`) — the offline auditor re-prover.
//!
//! Re-verify kriya governance evidence with the SAME `kriya-verify` code the Console and `kriyad`
//! link — fully offline, no Tauri, no network. Two modes:
//!   kriya-audit <receipts.jsonl> ...              signature-gated (parity with the runtime verifier)
//!   kriya-audit --envelopes <outbox.jsonl> ...    AttestationEnvelopes: sig + envelope-chain + merkle
//! Exit 0 when everything verifies, 1 on any failure, 2 on a usage error.
//!
//! The over-the-wire read-back + the heartbeat tail-truncation anchor land in 2.10.

use std::process::ExitCode;

use kriya_verify::{chain_break, envelope_chain_break, load_rows, verify_envelope};
use serde_json::Value;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (envelope_mode, paths): (bool, Vec<String>) = match args.split_first() {
        Some((flag, rest)) if flag == "--envelopes" => (true, rest.to_vec()),
        _ => (false, args),
    };
    if paths.is_empty() {
        eprintln!("usage: kriya-audit [--envelopes] <file.jsonl> [more.jsonl ...]");
        return ExitCode::from(2);
    }
    let ok = if envelope_mode {
        verify_envelope_files(&paths)
    } else {
        verify_receipt_files(&paths)
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// Receipts mode (parity with the runtime's `verify-receipts`): exit is SIGNATURE-gated; the hash-chain
/// is reported as a completeness signal but does not gate (a log may be independently-signed receipts,
/// not one chained stream — e.g. `sample-audit.jsonl`).
fn verify_receipt_files(paths: &[String]) -> bool {
    let mut all_ok = true;
    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{path}: cannot read: {e}");
                all_ok = false;
                continue;
            }
        };
        let source = basename(path);
        let rows = load_rows(&source, &text);
        let total = rows.len();
        let failed: Vec<&_> = rows
            .iter()
            .filter(|r| r.outcome.get("ok").and_then(|v| v.as_bool()) != Some(true))
            .collect();
        for r in &failed {
            let reason = r
                .outcome
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("verification failed");
            eprintln!("{source}:{}: FAIL — {reason}", r.line_no);
        }
        let chain_note = match chain_break(&text) {
            None => "hash-chain intact".to_string(),
            Some(line) => format!("hash-chain break at line {line} (completeness — informational)"),
        };
        let sigs_ok = failed.is_empty();
        println!(
            "{source}: {total} receipt(s), {} signature(s) verified, {chain_note} — {}",
            total - failed.len(),
            if sigs_ok { "OK" } else { "FAIL" },
        );
        all_ok &= sigs_ok;
    }
    all_ok
}

/// Envelope mode: re-verify each `SignedEnvelope` (Ed25519 + count sanity), the envelope chain
/// (`prev_envelope_hash` continuity), and that each `merkle_root` is well-formed. The auditor cannot
/// recompute the Merkle root from the envelope alone (the raw receipt lines stay on the device); a
/// specific-receipt membership proof is the P3 spot-audit. Exit reflects sig + chain + merkle-format.
fn verify_envelope_files(paths: &[String]) -> bool {
    let mut all_ok = true;
    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{path}: cannot read: {e}");
                all_ok = false;
                continue;
            }
        };
        let source = basename(path);
        let mut values: Vec<Value> = Vec::new();
        let mut parse_ok = true;
        for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            match serde_json::from_str::<Value>(line) {
                Ok(v) => values.push(v),
                Err(e) => {
                    eprintln!("{source}:{}: parse error: {e}", i + 1);
                    parse_ok = false;
                }
            }
        }

        let mut sigs_ok = true;
        for (i, v) in values.iter().enumerate() {
            if let Err(reason) = verify_envelope(v) {
                eprintln!("{source}:{}: FAIL — {reason}", i + 1);
                sigs_ok = false;
            }
        }
        let chain = envelope_chain_break(&values);
        if let Some(line) = chain {
            eprintln!("{source}: ENVELOPE CHAIN BREAK at line {line} (deletion / reorder)");
        }
        let merkle_ok = values.iter().all(|v| {
            v.get("envelope")
                .and_then(|e| e.get("integrity"))
                .and_then(|i| i.get("merkle_root"))
                .and_then(Value::as_str)
                .map(|r| r.len() == 64 && r.chars().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or(false)
        });
        if !merkle_ok {
            eprintln!("{source}: an envelope merkle_root is missing or malformed");
        }

        let file_ok = parse_ok && sigs_ok && chain.is_none() && merkle_ok;
        println!(
            "{source}: {} envelope(s), sigs {}, chain {}, merkle {} — {}",
            values.len(),
            if sigs_ok { "ok" } else { "FAIL" },
            if chain.is_none() { "intact" } else { "BROKEN" },
            if merkle_ok { "ok" } else { "BAD" },
            if file_ok { "OK" } else { "FAIL" },
        );
        all_ok &= file_ok;
    }
    all_ok
}
