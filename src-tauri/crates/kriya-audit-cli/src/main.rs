//! kriya-audit-cli (`kriya-audit`) — the offline auditor re-prover.
//!
//! Skeleton (roadmap 0.9): re-verify one or more signed-receipt JSONL logs with the SAME
//! `kriya-verify` code the Console and `kriyad` link, so a third party can independently confirm the
//! receipts are authentic — fully offline, no Tauri, no network. **Parity with the runtime's
//! `verify-receipts`: the exit code is signature-gated** (0 when every receipt's Ed25519 signature
//! verifies, 1 when any fails or a line is malformed, 2 on a usage error).
//!
//! The hash-chain is reported as a COMPLETENESS signal but does not gate this skeleton's exit — a
//! log may be a set of independently-signed receipts rather than one chained stream (the committed
//! `sample-audit.jsonl` is exactly that). Window/chain completeness is gated by the envelope
//! re-prover: 1.13 (envelope-from-file: sig + envelope-chain + Merkle) and 2.10 (over-the-wire
//! read-back + the heartbeat tail-truncation anchor).

use std::process::ExitCode;

use kriya_verify::{chain_break, load_rows};

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: kriya-audit <receipts.jsonl> [more.jsonl ...]");
        return ExitCode::from(2);
    }

    let mut all_sigs_ok = true;
    for path in &paths {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{path}: cannot read: {e}");
                all_sigs_ok = false;
                continue;
            }
        };
        let source = std::path::Path::new(path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());

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

        // Completeness (informational; not part of the exit code for this receipts skeleton).
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
        all_sigs_ok &= sigs_ok;
    }

    if all_sigs_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
