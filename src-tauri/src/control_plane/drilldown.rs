//! Operator drill-down receipting (doc 24 §7.5/§6-P9, EG-4) — "the surveillance is itself audited."
//!
//! Pattern-echo's own privacy mitigations (fleet_evidence's k-threshold suppression) mean a below-
//! threshold destination-pattern count is hidden from the cockpit by default. An operator CAN still
//! reveal it explicitly — but that act of looking is itself a signed, chained event, so "who looked
//! at device X's low-count detail, and when" has an answer. Mirrors `control_plane::policy`'s
//! `emit_policy_receipt` pattern (a dedicated `*.jsonl` chain under the audit dir, evidence-key
//! signed, tailed by the Evidence Compiler exactly like any other source) — this is doc 24's
//! "coverage.jsonl precedent" (an own-chain control-plane-internal event), applied via this repo's
//! newer `policy.rs` idiom (the same evidence key, not a second dedicated keypair).

use std::path::PathBuf;

use crate::control_plane::envelope::evidence_signing_key;
use crate::control_plane::redact::operator_pseudonym;
use crate::license::require_fleet_console;

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

fn drilldown_events_path() -> PathBuf {
    crate::audit::default_audit_dir().join("kriya-console-drilldown.jsonl")
}

fn last_line_hash(path: &std::path::Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .rfind(|l| !l.trim().is_empty())
            .map(|l| kriya_verify::sha256_hex(l.as_bytes()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn append_line(path: &std::path::Path, line: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("opening {}: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("writing {}: {e}", path.display()))
}

/// The Tauri command — gated on `fleet-console` FIRST, before any signing or I/O, matching every
/// other operator-facing command in `control_plane::fleet` (this reveals fleet-wide aggregate data
/// about OTHER devices, exactly the same role as `fleet_org_evidence`/`fleet_publish_policy`).
#[tauri::command]
pub fn console_drilldown(device_pub: String, scope: String) -> Result<(), String> {
    require_fleet_console()?;
    emit_drilldown_receipt(&device_pub, &scope)
}

/// Sign + append one `kriya.console.drilldown` receipt to the drilldown chain, keyed by this
/// device's evidence key (this event IS the Console's own governance action, mirroring
/// `policy::emit_policy_receipt`). `operator_pseudonym` is computed HERE from the local OS user via
/// the SAME HMAC-pepper scheme device-side agent users get (`control_plane::redact::
/// operator_pseudonym`) — never caller-supplied, so an operator cannot claim to be someone else in
/// their own audit trail. `device_pub` names which device's data was drilled into; `scope` is a
/// short caller-supplied label for WHAT was revealed (e.g. `"egress-unlisted-count"`), reusable
/// across any future below-k-threshold reveal, not hardcoded to one field. Separated from the
/// license-gated Tauri command above so the signing/chaining logic itself is directly unit-testable
/// (mirrors `fleet_evidence()`'s own pure-function-vs-gated-command split).
fn emit_drilldown_receipt(device_pub: &str, scope: &str) -> Result<(), String> {
    let key = evidence_signing_key()?;
    let pepper = crate::control_plane::envelope::pepper()?;
    let operator = operator_pseudonym(&pepper, &os_user());
    let path = drilldown_events_path();
    let prev_hash = last_line_hash(&path)?;
    let ts_ms = now_ms();
    let line = kriya_verify::sign_receipt(
        &key,
        &format!("drilldown-{ts_ms}"),
        "kriya.console.drilldown",
        serde_json::json!({ "device_pub": device_pub, "operator_pseudonym": operator, "scope": scope }),
        true,
        ts_ms,
        Some(kriya_verify::Actor {
            agent: "kriya-console".into(),
            user: "system".into(),
        }),
        prev_hash,
    );
    append_line(&path, &serde_json::to_string(&line).map_err(|e| e.to_string())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as JsonValue;

    use crate::HOME_ENV_LOCK as ENV_LOCK;

    fn with_sandboxed_home<T>(f: impl FnOnce() -> T) -> T {
        let tmp = std::env::temp_dir().join(format!(
            "kriya-drilldown-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("HOME", &tmp);
        let result = f();
        std::env::remove_var("HOME");
        let _ = std::fs::remove_dir_all(&tmp);
        result
    }

    #[test]
    fn emits_a_signed_chained_receipt_naming_the_device_and_scope_never_a_plaintext_operator() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            std::env::set_var("USER", "Jane Q. Operator");
            emit_drilldown_receipt(&"aa".repeat(32), "egress-unlisted-count").unwrap();
            std::env::remove_var("USER");

            let text = std::fs::read_to_string(drilldown_events_path()).unwrap();
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            assert_eq!(lines.len(), 1);
            let v: JsonValue = serde_json::from_str(lines[0]).unwrap();
            assert_eq!(v["action_id"], "kriya.console.drilldown");
            assert_eq!(v["params"]["device_pub"], "aa".repeat(32));
            assert_eq!(v["params"]["scope"], "egress-unlisted-count");
            assert!(kriya_verify::verify_value(&v).is_ok());

            let raw = serde_json::to_string(&v).unwrap();
            assert!(!raw.contains("Jane"), "the plaintext OS user must never appear, only its pseudonym");
            assert!(v["params"]["operator_pseudonym"].as_str().unwrap().starts_with("op_"));
        });
    }

    #[test]
    fn multiple_drilldowns_chain() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            emit_drilldown_receipt(&"aa".repeat(32), "s1").unwrap();
            emit_drilldown_receipt(&"bb".repeat(32), "s2").unwrap();
            let text = std::fs::read_to_string(drilldown_events_path()).unwrap();
            assert_eq!(
                kriya_verify::chain_break(&text),
                None,
                "the drilldown source chains, tailed like any other audit source"
            );
        });
    }

    #[test]
    fn operator_pseudonym_is_deterministic_per_device_pepper() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            emit_drilldown_receipt(&"aa".repeat(32), "s1").unwrap();
            emit_drilldown_receipt(&"bb".repeat(32), "s2").unwrap();
            let text = std::fs::read_to_string(drilldown_events_path()).unwrap();
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            let v1: JsonValue = serde_json::from_str(lines[0]).unwrap();
            let v2: JsonValue = serde_json::from_str(lines[1]).unwrap();
            assert_eq!(
                v1["params"]["operator_pseudonym"], v2["params"]["operator_pseudonym"],
                "the SAME OS user drilling into two different devices gets the SAME pseudonym"
            );
        });
    }

    #[test]
    fn console_drilldown_requires_license_before_any_signing_or_io() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let err = console_drilldown("aa".repeat(32), "s1".into()).unwrap_err();
            assert!(
                err.contains("fleet-console") || err.contains("fleet cockpit"),
                "must fail on the license gate: {err}"
            );
            assert!(
                !drilldown_events_path().exists(),
                "an unlicensed call must sign and write NOTHING"
            );
        });
    }
}
