//! kriya-audit-cli (`kriya-audit`) — the offline auditor re-prover.
//!
//! Re-verify kriya governance evidence with the SAME `kriya-verify` code the Console and `kriyad`
//! link — fully offline, no Tauri, no network. Three modes:
//!   kriya-audit <receipts.jsonl> ...              signature-gated (parity with the runtime verifier)
//!   kriya-audit --envelopes <outbox.jsonl> ...    AttestationEnvelopes: sig + envelope-chain + merkle
//!   kriya-audit --readback <readback.json> ...    a /v1/verify response: the above + the heartbeat
//!                                                  tail-truncation anchor (returned_top_seq ≥ seq_seen)
//! Exit 0 when everything verifies, 1 on any failure, 2 on a usage error.

use std::process::ExitCode;

use kriya_verify::{
    chain_break, envelope_chain_break, load_rows, verify_envelope, verify_heartbeat,
};
use serde_json::Value;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, paths): (Mode, Vec<String>) = match args.split_first() {
        Some((f, rest)) if f == "--envelopes" => (Mode::Envelopes, rest.to_vec()),
        Some((f, rest)) if f == "--readback" => (Mode::Readback, rest.to_vec()),
        _ => (Mode::Receipts, args),
    };
    if paths.is_empty() {
        eprintln!("usage: kriya-audit [--envelopes | --readback] <file> [more ...]");
        return ExitCode::from(2);
    }
    let ok = match mode {
        Mode::Receipts => verify_receipt_files(&paths),
        Mode::Envelopes => verify_envelope_files(&paths),
        Mode::Readback => {
            // Loop, not `.all` — verify EVERY file (report all failures), don't short-circuit.
            let mut all_ok = true;
            for p in &paths {
                all_ok &= verify_readback_file(p);
            }
            all_ok
        }
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

enum Mode {
    Receipts,
    Envelopes,
    Readback,
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

/// Re-verify a batch of `SignedEnvelope`s: each Ed25519 sig + count sanity (`verify_envelope`), the
/// envelope chain (`prev_envelope_hash` continuity), and each `merkle_root`'s format. The auditor can't
/// recompute the Merkle root from the envelope alone (the raw receipt lines stay on the device); a
/// specific-receipt membership proof is the P3 spot-audit. Prints a per-source summary; returns ok.
fn verify_envelope_batch(source: &str, values: &[Value]) -> bool {
    let mut sigs_ok = true;
    for (i, v) in values.iter().enumerate() {
        if let Err(reason) = verify_envelope(v) {
            eprintln!("{source}:{}: FAIL — {reason}", i + 1);
            sigs_ok = false;
        }
    }
    let chain = envelope_chain_break(values);
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
    let ok = sigs_ok && chain.is_none() && merkle_ok;
    println!(
        "{source}: {} envelope(s), sigs {}, chain {}, merkle {} — {}",
        values.len(),
        if sigs_ok { "ok" } else { "FAIL" },
        if chain.is_none() { "intact" } else { "BROKEN" },
        if merkle_ok { "ok" } else { "BAD" },
        if ok { "OK" } else { "FAIL" },
    );
    ok
}

/// Envelope mode: each path is an NDJSON file of `SignedEnvelope`s.
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
        all_ok &= parse_ok && verify_envelope_batch(&source, &values);
    }
    all_ok
}

/// The tail-truncation anchor. The device's most-recent SIGNED heartbeat claims "I had emitted up to
/// `seq_seen`". If the server returns envelopes only up to `returned_top_seq < seq_seen`, it is hiding
/// the most-recent envelopes — the one omission a redacted, append-only store can't otherwise reveal.
///   * top ≥ seen        → ok (the server proved it withheld nothing past the device's last claim)
///   * top < seen        → FAIL (suppressed tail)
///   * no heartbeat       → ok-but-unanchored (coverage gap; the caller already flags `silent`)
fn tail_anchor_ok(returned_top_seq: Option<u64>, seq_seen: Option<u64>) -> bool {
    match (returned_top_seq, seq_seen) {
        (_, None) => true, // nothing to anchor against
        (Some(top), Some(seen)) => top >= seen,
        (None, Some(_)) => false, // the device signed a claim, yet zero envelopes came back
    }
}

/// Read-back mode: a `/v1/verify` response `{ "envelopes": [<signed-envelope-json-string>, …],
/// "heartbeat": <signed-heartbeat-json-string>|null }`. Re-verify the envelopes (as above), verify the
/// heartbeat signature, enforce that the heartbeat is for the SAME device (no cross-device anchor
/// spoofing), and assert the tail-truncation anchor.
fn verify_readback_file(path: &str) -> bool {
    let source = basename(path);
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{path}: cannot read: {e}");
            return false;
        }
    };
    let obj: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{source}: not a /v1/verify response: {e}");
            return false;
        }
    };

    // Parse the embedded signed-envelope strings.
    let mut values: Vec<Value> = Vec::new();
    let mut parse_ok = true;
    if let Some(arr) = obj.get("envelopes").and_then(Value::as_array) {
        for (i, item) in arr.iter().enumerate() {
            let parsed = item
                .as_str()
                .ok_or_else(|| "envelope entry is not a string".to_string())
                .and_then(|s| serde_json::from_str::<Value>(s).map_err(|e| e.to_string()));
            match parsed {
                Ok(v) => values.push(v),
                Err(e) => {
                    eprintln!("{source}: envelopes[{i}]: {e}");
                    parse_ok = false;
                }
            }
        }
    } else {
        eprintln!("{source}: missing \"envelopes\" array");
        return false;
    }
    let envelopes_ok = parse_ok && verify_envelope_batch(&source, &values);

    let envelope_device = values
        .first()
        .and_then(|v| v.get("envelope"))
        .and_then(|e| e.get("device_pub"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let returned_top_seq = values
        .iter()
        .filter_map(|v| {
            v.get("envelope")
                .and_then(|e| e.get("seq"))
                .and_then(Value::as_u64)
        })
        .max();

    // The heartbeat: verify its signature, that it's the SAME device, and read its claimed seq.
    let mut heartbeat_ok = true;
    let mut seq_seen = None;
    match obj.get("heartbeat") {
        Some(Value::String(hb_str)) => match serde_json::from_str::<Value>(hb_str) {
            Ok(hb) => {
                if let Err(reason) = verify_heartbeat(&hb) {
                    eprintln!("{source}: heartbeat FAIL — {reason}");
                    heartbeat_ok = false;
                }
                let hb_device = hb
                    .get("heartbeat")
                    .and_then(|h| h.get("device_pub"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let (Some(ed), Some(hd)) = (&envelope_device, &hb_device) {
                    if ed != hd {
                        eprintln!("{source}: heartbeat is for a DIFFERENT device than the envelopes (anchor spoof)");
                        heartbeat_ok = false;
                    }
                }
                seq_seen = hb
                    .get("heartbeat")
                    .and_then(|h| h.get("seq_seen"))
                    .and_then(Value::as_u64);
            }
            Err(e) => {
                eprintln!("{source}: heartbeat is not valid JSON: {e}");
                heartbeat_ok = false;
            }
        },
        Some(Value::Null) | None => {
            eprintln!(
                "{source}: no heartbeat tail anchor (coverage gap — the tail is unverifiable)"
            );
        }
        Some(_) => {
            eprintln!("{source}: heartbeat field is not a string");
            heartbeat_ok = false;
        }
    }

    let tail_ok = tail_anchor_ok(returned_top_seq, seq_seen);
    if !tail_ok {
        eprintln!(
            "{source}: TAIL TRUNCATION — server returned up to seq {:?} but the device signed seq_seen={:?}",
            returned_top_seq, seq_seen
        );
    }
    let ok = envelopes_ok && heartbeat_ok && tail_ok;
    println!(
        "{source}: read-back — envelopes {}, heartbeat {}, tail-anchor {} — {}",
        if envelopes_ok { "ok" } else { "FAIL" },
        if heartbeat_ok { "ok" } else { "FAIL" },
        if tail_ok { "ok" } else { "FAIL" },
        if ok { "OK" } else { "FAIL" },
    );
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_anchor_detects_truncation() {
        assert!(
            tail_anchor_ok(Some(5), Some(5)),
            "returned through the claim"
        );
        assert!(tail_anchor_ok(Some(7), Some(5)), "returned past the claim");
        assert!(
            !tail_anchor_ok(Some(4), Some(5)),
            "withheld the most recent envelope"
        );
        assert!(
            !tail_anchor_ok(None, Some(1)),
            "claim exists but zero envelopes returned"
        );
        assert!(
            tail_anchor_ok(Some(3), None),
            "no heartbeat → unanchored, not a failure"
        );
    }

    #[test]
    fn malformed_readback_fails_closed() {
        let dir = std::env::temp_dir().join(format!("kriya-rb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.json");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(!verify_readback_file(p.to_str().unwrap()));
        std::fs::write(&p, r#"{"heartbeat":null}"#).unwrap(); // no envelopes array
        assert!(!verify_readback_file(p.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
