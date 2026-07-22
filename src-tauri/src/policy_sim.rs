//! **I3 — Policy CI.** "This policy change would have blocked N of last week's M actions — here
//! are the receipts." A counterfactual replay of a CANDIDATE policy over the device's own already-
//! verified receipt history, so an operator can see the blast radius of a policy edit before it
//! ships — free-tier single-device (`PolicyView`'s "Test before apply") and, unmodified, the
//! fleet PolicyBundle pre-rollout gate (`ControlPlanePolicyTab`, doc 22 P3) — both call the exact
//! same [`simulate_policy`] command.
//!
//! **Scope, stated honestly (do not overclaim in UI copy):** this replays ONLY the action-tier
//! gate (`kriya_verify::simulate_tier` — allow / requires-approval / deny, including the B11
//! read-only pre-empt). It does NOT replay budget exhaustion, egress-tier decisions, or the
//! detection-pack body/host heuristics (B5–B10, B12) — those need timestamps, hosts, or outbound
//! payload bytes a bare `action_id` doesn't carry. "Would have been denied" here means "the action
//! id would have been denied at the tier gate," which is the majority of what a policy edit
//! changes, but not the whole enforcement pipeline.
//!
//! The comparison baseline is the CURRENT on-disk policy (`govern::load_agent_policy`), not an
//! attempt to reverse-engineer what tier a historical receipt actually got (receipt `success:false`
//! conflates a policy deny with an unrelated tool-execution failure — an unreliable signal to build
//! a "would have changed" claim on). So the question this answers is precisely: "if the CANDIDATE
//! policy had been running instead of the CURRENT one for the last N days, which of these actions
//! would have gotten a different tier?" — deterministic, and honest about what "actual" means here.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::{json, Value};

use kriya_verify::{simulate_tier, Actor, SimDecision, SimPolicy};

use crate::audit::default_audit_dir;
use crate::coverage::{default_keys_dir, load_or_create_key};
use crate::govern::load_agent_policy;
use crate::paid::{ATTESTATION_ON_DEVICE, COVERAGE_SNAPSHOT, KRIYA_IO_PREFIX};
use crate::receipts::verify_value;

/// This module's own receipt-emission namespace — excluded from its OWN replay corpus (a
/// simulation must never count its own past runs as governed agent activity), mirroring how
/// `paid.rs` excludes `KRIYA_IO_PREFIX`/`COVERAGE_SNAPSHOT`/`ATTESTATION_ON_DEVICE`.
const KRIYA_POLICY_PREFIX: &str = "kriya.policy.";

/// Hard cap on the replay window — mirrors `fleet_evidence`'s 90-day default/cap posture; a
/// candidate-policy test is a "last week or two" question, not an unbounded corpus scan.
const MAX_WINDOW_DAYS: u32 = 90;
const DEFAULT_WINDOW_DAYS: u32 = 7;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn os_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn tail_hash(log: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(log).ok()?;
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|last| kriya_verify::sha256_hex(last.as_bytes()))
}

fn is_governance_internal(action_id: &str) -> bool {
    action_id == ATTESTATION_ON_DEVICE
        || action_id == COVERAGE_SNAPSHOT
        || action_id.starts_with(KRIYA_IO_PREFIX)
        || action_id.starts_with(KRIYA_POLICY_PREFIX)
}

fn decision_str(d: SimDecision) -> &'static str {
    d.as_str()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimExample {
    pub source: String,
    pub action_id: String,
    pub ts_ms: u64,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationReport {
    pub window_from_ms: u64,
    pub window_to_ms: u64,
    pub total_replayed: usize,
    pub changed: usize,
    pub changed_to_deny: usize,
    pub changed_to_approval: usize,
    pub changed_to_allow: usize,
    pub unchanged: usize,
    /// A capped sample of changed actions (most-recent-first), never the full set — this is a
    /// human-facing preview, not an export.
    pub examples: Vec<SimExample>,
    /// `true` when `examples` was truncated — render "…and N more" rather than implying
    /// completeness.
    pub examples_truncated: bool,
    pub candidate_policy_hash: String,
}

const MAX_EXAMPLES: usize = 20;

/// The replay core, independent of how the candidate policy text was obtained (single-device raw
/// `agent-policy.yaml` or a fleet `PolicyBundle.policy` value re-serialized to text by the caller).
fn run_simulation(candidate_yaml: &str, window_days: u32) -> Result<SimulationReport, String> {
    let candidate: SimPolicy = serde_yaml::from_str(candidate_yaml)
        .map_err(|e| format!("candidate policy does not parse: {e}"))?;
    let candidate_policy_hash = kriya_verify::sha256_hex(candidate_yaml.as_bytes());

    let window_days = window_days.clamp(1, MAX_WINDOW_DAYS);
    let window_ms = u64::from(window_days) * 24 * 60 * 60 * 1000;
    let window_to_ms = now_ms();
    let window_from_ms = window_to_ms.saturating_sub(window_ms);

    // The comparison baseline: what's actually in effect on this device today. Absent entirely
    // (a fresh install that never authored a policy), there is no "current" tier to diff against —
    // every replayed action trivially "changes" from an undefined baseline, which is not a
    // meaningful blast-radius number. Treat that state as the runtime's own permissive built-in
    // default (`kriya-hook`'s `DEFAULT_POLICY_YAML`, mirrored by `govern::PERMISSIVE_DEFAULT_POLICY_YAML`)
    // — the same baseline `ensure_policy_file` would have written.
    let current_yaml = load_agent_policy()
        .unwrap_or_else(|| crate::govern::PERMISSIVE_DEFAULT_POLICY_YAML.to_string());
    let current: SimPolicy = serde_yaml::from_str(&current_yaml)
        .map_err(|e| format!("current on-disk policy does not parse: {e}"))?;

    let dir = default_audit_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("jsonl"))
                .collect()
        })
        .unwrap_or_default();
    paths.sort();

    let mut total_replayed = 0usize;
    let mut changed_to_deny = 0usize;
    let mut changed_to_approval = 0usize;
    let mut changed_to_allow = 0usize;
    let mut unchanged = 0usize;
    let mut examples: Vec<SimExample> = Vec::new();
    let mut examples_truncated = false;

    for path in paths {
        let source = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for line in text.split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue, // a malformed/tampered line has no reliable action_id to replay
            };
            if verify_value(&v).is_err() {
                continue; // unverified activity is not evidence to replay a policy decision against
            }
            let action_id = v.get("action_id").and_then(Value::as_str).unwrap_or("");
            if action_id.is_empty() || is_governance_internal(action_id) {
                continue;
            }
            let ts_ms = v.get("ts_ms").and_then(Value::as_u64).unwrap_or(0);
            if ts_ms < window_from_ms || ts_ms > window_to_ms {
                continue;
            }

            total_replayed += 1;
            let before = simulate_tier(&current, action_id);
            let after = simulate_tier(&candidate, action_id);
            if before == after {
                unchanged += 1;
                continue;
            }
            match after {
                SimDecision::Deny => changed_to_deny += 1,
                SimDecision::RequiresApproval => changed_to_approval += 1,
                SimDecision::Allow => changed_to_allow += 1,
            }
            if examples.len() < MAX_EXAMPLES {
                examples.push(SimExample {
                    source: source.clone(),
                    action_id: action_id.to_string(),
                    ts_ms,
                    before: decision_str(before).to_string(),
                    after: decision_str(after).to_string(),
                });
            } else {
                examples_truncated = true;
            }
        }
    }

    let changed = changed_to_deny + changed_to_approval + changed_to_allow;
    // Most-recent-first is more useful to an operator scanning a handful of examples than file
    // order; examples were built in file/line order above.
    examples.sort_by_key(|e| std::cmp::Reverse(e.ts_ms));

    let report = SimulationReport {
        window_from_ms,
        window_to_ms,
        total_replayed,
        changed,
        changed_to_deny,
        changed_to_approval,
        changed_to_allow,
        unchanged,
        examples,
        examples_truncated,
        candidate_policy_hash,
    };

    // Auditable-by-design (doc 26 I3): the simulation itself is a signed, chained fact, so "did
    // anyone test this candidate before publishing it" has a receipted answer, same posture as
    // `kriya.policy.applied`/`kriya.policy.stale`. Best-effort: a failure to emit the receipt must
    // never block returning the report to the operator who's waiting on it.
    let _ = emit_sim_receipt(&report);

    Ok(report)
}

fn emit_sim_receipt(report: &SimulationReport) -> Result<(), String> {
    let key = load_or_create_key(&default_keys_dir().join("policy-sim.key"))?;
    let log = default_audit_dir().join("policy-sim.jsonl");
    let prev_hash = tail_hash(&log);
    let ts_ms = now_ms();
    let mut step_raw = [0u8; 16];
    getrandom::fill(&mut step_raw).map_err(|e| format!("OS CSPRNG failed: {e}"))?;
    let step_id = format!("policy-sim-{}", hex::encode(step_raw));

    let fields = json!({
        "candidate_policy_hash": report.candidate_policy_hash,
        "window_from_ms": report.window_from_ms,
        "window_to_ms": report.window_to_ms,
        "total_replayed": report.total_replayed,
        "changed": report.changed,
        "changed_to_deny": report.changed_to_deny,
        "changed_to_approval": report.changed_to_approval,
        "changed_to_allow": report.changed_to_allow,
    });
    let line = kriya_verify::sign_receipt(
        &key,
        &step_id,
        "kriya.policy.sim.result",
        fields,
        true,
        ts_ms,
        Some(Actor {
            agent: "kriya-console".into(),
            user: os_user(),
        }),
        prev_hash,
    );
    let serialized = serde_json::to_string(&line).map_err(|e| e.to_string())?;
    let mut existing = std::fs::read_to_string(&log).unwrap_or_default();
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&serialized);
    existing.push('\n');
    std::fs::write(&log, existing).map_err(|e| format!("writing {}: {e}", log.display()))?;
    Ok(())
}

/// Replay a candidate policy (raw YAML or JSON text — JSON is valid YAML, so a fleet
/// `PolicyBundle.policy` JSON blob works unmodified) against this device's own verified receipt
/// history. `window_days` defaults to 7 ("last week's actions," doc 26's own framing), clamped to
/// `[1, 90]`. Free-tier, unconditional — both `PolicyView` (single-device) and
/// `ControlPlanePolicyTab` (fleet pre-publish) call this same command.
#[tauri::command]
pub fn simulate_policy(
    candidate_yaml: String,
    window_days: Option<u32>,
) -> Result<SimulationReport, String> {
    run_simulation(&candidate_yaml, window_days.unwrap_or(DEFAULT_WINDOW_DAYS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::chain_break;
    use crate::HOME_ENV_LOCK as ENV_LOCK;

    /// The ONE crate-wide lock every `$HOME`-mutating test in this crate takes, so parallel test
    /// threads never race a different module's `$HOME`-dependent test.
    fn with_sandbox_home<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = std::env::temp_dir().join(format!(
            "kriya-policy-sim-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);
        let result = f(&home);
        match prev {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);
        result
    }

    fn seed_receipt(dir: &std::path::Path, file: &str, action_id: &str, ts_ms: u64) {
        std::fs::create_dir_all(dir).unwrap();
        let key_seed = [7u8; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&key_seed);
        let line = kriya_verify::sign_receipt(
            &key,
            &format!("step-{ts_ms}"),
            action_id,
            json!({}),
            true,
            ts_ms,
            None,
            None,
        );
        let path = dir.join(file);
        let mut existing = std::fs::read_to_string(&path).unwrap_or_default();
        existing.push_str(&serde_json::to_string(&line).unwrap());
        existing.push('\n');
        std::fs::write(&path, existing).unwrap();
    }

    #[test]
    fn replays_current_vs_candidate_and_buckets_by_new_tier() {
        with_sandbox_home(|_home| {
            let dir = default_audit_dir();
            let now = now_ms();
            seed_receipt(
                &dir,
                "claude-code.jsonl",
                "claude-code__mcp__github__create_issue",
                now,
            );
            seed_receipt(&dir, "claude-code.jsonl", "claude-code__bash", now);
            seed_receipt(
                &dir,
                "claude-code.jsonl",
                "claude-code__mcp__slack__post",
                now,
            );

            // Current policy: allow everything (fresh install default).
            // No agent-policy.yaml saved -> falls back to the permissive built-in default.

            // Candidate: deny slack, everything else allowed.
            let candidate = r#"{"rules":[{"action":"claude-code__mcp__slack__*","allow":false},{"action":"*","allow":true}]}"#;
            let report = run_simulation(candidate, 7).unwrap();

            assert_eq!(report.total_replayed, 3);
            assert_eq!(report.changed, 1);
            assert_eq!(report.changed_to_deny, 1);
            assert_eq!(report.unchanged, 2);
            assert_eq!(report.examples.len(), 1);
            assert_eq!(
                report.examples[0].action_id,
                "claude-code__mcp__slack__post"
            );
            assert_eq!(report.examples[0].before, "allow");
            assert_eq!(report.examples[0].after, "deny");
        });
    }

    #[test]
    fn excludes_governance_internal_actions_from_the_corpus() {
        with_sandbox_home(|_home| {
            let dir = default_audit_dir();
            let now = now_ms();
            seed_receipt(&dir, "coverage.jsonl", "kriya.coverage.snapshot", now);
            seed_receipt(&dir, "console.jsonl", "kriya.attestation.on_device", now);
            seed_receipt(&dir, "gateway.jsonl", "kriya.io.egress.example", now);

            let candidate = r#"{"rules":[{"action":"*","allow":false}]}"#;
            let report = run_simulation(candidate, 7).unwrap();
            assert_eq!(
                report.total_replayed, 0,
                "governance-internal actions must never enter the replay corpus"
            );
        });
    }

    #[test]
    fn window_excludes_receipts_outside_the_requested_days() {
        with_sandbox_home(|_home| {
            let dir = default_audit_dir();
            let old = now_ms().saturating_sub(30 * 24 * 60 * 60 * 1000); // 30 days ago
            seed_receipt(&dir, "claude-code.jsonl", "claude-code__bash", old);

            let candidate = r#"{"rules":[{"action":"*","allow":false}]}"#;
            let report = run_simulation(candidate, 7).unwrap();
            assert_eq!(
                report.total_replayed, 0,
                "a 7-day window must not replay a 30-day-old receipt"
            );

            let report_wide = run_simulation(candidate, 90).unwrap();
            assert_eq!(report_wide.total_replayed, 1, "a 90-day window covers it");
        });
    }

    #[test]
    fn unverifiable_lines_are_skipped_not_counted() {
        with_sandbox_home(|_home| {
            let dir = default_audit_dir();
            std::fs::create_dir_all(&dir).unwrap();
            // A tampered receipt: valid JSON, but the signature won't verify (unsigned garbage).
            std::fs::write(
                dir.join("claude-code.jsonl"),
                format!(
                    "{}\n",
                    json!({"action_id": "claude-code__bash", "ts_ms": now_ms(), "success": true})
                ),
            )
            .unwrap();
            let candidate = r#"{"rules":[{"action":"*","allow":false}]}"#;
            let report = run_simulation(candidate, 7).unwrap();
            assert_eq!(
                report.total_replayed, 0,
                "an unverified/tampered line must not be replayed as evidence"
            );
        });
    }

    #[test]
    fn malformed_candidate_policy_is_a_real_error() {
        with_sandbox_home(|_home| {
            let err = run_simulation("not: [valid", 7).unwrap_err();
            assert!(err.contains("does not parse"));
        });
    }

    #[test]
    fn emits_a_signed_chained_sim_receipt() {
        with_sandbox_home(|_home| {
            let dir = default_audit_dir();
            seed_receipt(&dir, "claude-code.jsonl", "claude-code__bash", now_ms());
            let candidate = r#"{"rules":[{"action":"*","allow":false}]}"#;
            run_simulation(candidate, 7).unwrap();

            let log = dir.join("policy-sim.jsonl");
            let text = std::fs::read_to_string(&log).unwrap();
            assert_eq!(text.lines().count(), 1);
            let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
            assert_eq!(v["action_id"], "kriya.policy.sim.result");
            assert!(
                verify_value(&v).is_ok(),
                "the sim receipt itself must verify"
            );
            assert_eq!(chain_break(&text), None, "single-entry chain has no break");

            // A second run chains onto the first.
            run_simulation(candidate, 7).unwrap();
            let text2 = std::fs::read_to_string(&log).unwrap();
            assert_eq!(text2.lines().count(), 2);
            assert_eq!(chain_break(&text2), None);
        });
    }

    #[test]
    fn window_days_out_of_range_is_clamped_not_rejected() {
        with_sandbox_home(|_home| {
            let candidate = r#"{"rules":[{"action":"*","allow":true}]}"#;
            // 0 and absurdly-large both just clamp; neither should error.
            assert!(run_simulation(candidate, 0).is_ok());
            assert!(run_simulation(candidate, 100_000).is_ok());
        });
    }
}
