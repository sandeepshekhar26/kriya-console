//! Device policy downlink (P3, doc 22 §5) — pull the latest in-scope `PolicyBundle` from kriyad
//! (device-pull, on the existing heartbeat cadence — the server never dials a device), verify it
//! against the device's OWN pinned `org_policy_pub` (never a key the bundle itself asserts), enforce
//! anti-rollback (`version > last_applied`), and apply: `policy`/`budgets` → the existing runtime
//! policy YAML, `govern[]` → the doc-21 detect→wire engine, `envelope_verbosity` → the Evidence
//! Compiler's redaction dial. Emits `kriya.policy.applied` / `kriya.policy.stale` receipts (signed with
//! the device evidence key) so the apply itself becomes part of this device's own signed evidence
//! trail. Air-gap mirrors the identical verify+apply path from a bundle FILE instead of the network
//! (`policy_apply_file`) — sneaker-net == network, the same symmetry `push.rs`'s outbox already has.
//!
//! **kriyad authors nothing; the device is the final authority** (doc 22 §3). Even though kriyad's
//! scope filter already narrowed what it served, this module independently re-verifies the signature
//! and re-checks the version — a compromised or merely-buggy kriyad can at worst withhold/delay a
//! bundle, never forge one or force a downgrade.
//!
//! **Scope note (matches the P1 precedent):** `pull_and_apply` is complete, tested, and callable —
//! exactly like P1 left `push_envelopes`/`device_info::emit_if_changed` — but is NOT wired into
//! `compiler::spawn`'s live loop here. Real device mTLS transport-identity provisioning (turning
//! `enrollment.json` into cert/key paths) is Phase-3 scope (`device_info.rs`'s own documented boundary
//! says the same); wiring live network calls for ANY of push/device-info/policy-pull belongs with that
//! work, not decided piecemeal per-phase.

use std::path::PathBuf;

use kriya_verify::{supersedes, GovernDirective, PolicyBundle, SignedPolicyBundle};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::control_plane::enrollment;
use crate::control_plane::envelope::evidence_signing_key;
use crate::govern::{govern_all, ungovern, GovernOpts};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Durable "what's applied" state ──────────────────────────────────────────────────────────────────

/// `~/.kriya/console/policy-state.json` — mirrors `compiler::CompilerState`/`device_info`'s state-file
/// idiom exactly (a small JSON sidecar, best-effort read with a safe default).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyState {
    pub last_applied_version: Option<u64>,
    pub last_applied_bundle_hash: Option<String>,
    pub last_applied_ms: Option<u64>,
    pub last_applied_expires_ms: Option<u64>,
    /// The applied `envelope_verbosity` dial — `None` (pre-P3 / nothing applied yet) means
    /// `"standard"`, the existing behavior, byte-for-byte unchanged. See
    /// [`current_envelope_verbosity`].
    pub envelope_verbosity: Option<String>,
    /// Whether `kriya.policy.stale` has already been emitted for the CURRENT staleness episode — so
    /// [`check_staleness`] emits it once per transition into staleness, not on every heartbeat while
    /// still stale.
    #[serde(default)]
    pub stale_reported: bool,
    /// Whether the kill-switch fallback policy (doc 24 §11 B16/EG-F) is CURRENTLY the policy on disk
    /// — either because the last-applied bundle explicitly set `kill_switch: true`, or because the
    /// applied bundle went stale ([`check_staleness`] engages the same fallback automatically, "the
    /// stale-policy kill-switch"). Cleared the moment a fresh, non-kill-switch bundle applies
    /// ([`verify_and_apply`] always overwrites the policy file, so this can never go stale itself).
    #[serde(default)]
    pub kill_switch_active: bool,
    /// The applied `io_verbosity` dial (doc 24 §4.5/§7.5, EG-4) — `None` (pre-EG-4 / nothing applied
    /// yet) means `"off"`. See [`current_io_verbosity`].
    #[serde(default)]
    pub io_verbosity: Option<String>,
    /// The applied bundle's `policy.egress.rules[].host` patterns, verbatim — the ONLY strings
    /// [`kriya_verify::minimize_io`] is ever allowed to echo for a matched destination. Extracted once
    /// at apply time (not re-parsed from the runtime policy YAML on every envelope) so the pattern set
    /// a device echoes always matches EXACTLY what the operator most recently authored. Empty when
    /// the bundle carries no `egress.rules` — every destination then falls to the unlisted bucket.
    #[serde(default)]
    pub egress_patterns: Vec<String>,
    /// The applied bundle's `purpose_statement` (doc 24 §7.5/§6-P9), echoed into every fleet export
    /// once `io_verbosity` is `"pattern-echo"`.
    #[serde(default)]
    pub purpose_statement: Option<String>,
}

fn state_path() -> PathBuf {
    crate::audit::console_dir().join("policy-state.json")
}

pub fn load_state() -> PolicyState {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(state: &PolicyState) -> Result<(), String> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing policy state: {e}"))
}

/// The Evidence Compiler's redaction dial (`envelope.rs`'s builder reads this via
/// `WindowInput::envelope_verbosity`). `"standard"` until a bundle setting it has actually been applied.
pub fn current_envelope_verbosity() -> String {
    load_state().envelope_verbosity.unwrap_or_else(|| "standard".into())
}

/// The Evidence Compiler's fleet-destination-visibility dial (doc 24 §4.5/§7.5, EG-4) —
/// `WindowInput::io_verbosity` reads this. `"off"` until a bundle setting `"pattern-echo"` has
/// actually been applied.
pub fn current_io_verbosity() -> String {
    load_state().io_verbosity.unwrap_or_else(|| "off".into())
}

/// The applied bundle's operator-authored egress destination patterns — `WindowInput::egress_patterns`
/// reads this. The ONLY strings a device is ever allowed to echo for a matched destination.
pub fn current_egress_patterns() -> Vec<String> {
    load_state().egress_patterns
}

/// The applied bundle's purpose statement, echoed into every fleet export (doc 24 §7.5/§6-P9).
pub fn current_purpose_statement() -> Option<String> {
    load_state().purpose_statement
}

/// Extract `policy.egress.rules[].host` verbatim from a bundle's opaque `policy` payload — this crate
/// doesn't otherwise interpret the runtime policy format (see `kriya_verify::policy`'s module doc),
/// but the io-pattern minimizer needs exactly this ONE slice of it: the operator's own authored
/// destination patterns, nothing else. Tolerant of any shape mismatch (absent `egress`/`rules`, a
/// rule missing `host`, a non-string `host`) — malformed input yields fewer patterns, never a panic
/// or a spurious echo.
fn egress_patterns_from_bundle(bundle: &PolicyBundle) -> Vec<String> {
    bundle
        .policy
        .get("egress")
        .and_then(|e| e.get("rules"))
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|r| r.get("host").and_then(Value::as_str))
                // An empty host string is malformed input, never a real pattern — without this, a
                // receipt legitimately lacking `dest_host` (defaults to `""`) would misleadingly
                // match this "pattern" instead of falling to the honest `UNLISTED_PATTERN` bucket.
                .filter(|h| !h.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// `sha256` of the bundle's canonical signed bytes — the `bundle_hash` carried in the
/// `kriya.policy.applied` receipt, `PolicyEcho.bundle_hash` (P1 device-info echo), and the P3.1
/// envelope `policy_state` field (step 6).
pub fn bundle_hash(bundle: &PolicyBundle) -> String {
    kriya_verify::sha256_hex(&kriya_verify::policy_bundle_canonical_bytes(bundle))
}

// ── Signed receipts for control-plane-internal events ───────────────────────────────────────────────

/// Dedicated audit source for control-plane-internal events this Console itself attests (as opposed to
/// an external front/hook) — tailed by the Evidence Compiler exactly like any other `*.jsonl` source
/// under `~/.kriya/audit/`, so `kriya.policy.applied`/`kriya.policy.stale` become ordinary,
/// chain-verified `MinimizedAction`s in the next envelope.
fn policy_events_path() -> PathBuf {
    crate::audit::default_audit_dir().join("kriya-console-policy.jsonl")
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

/// Sign + append a `kriya.policy.applied`/`kriya.policy.stale` receipt via the shared
/// `kriya_verify::sign_receipt` (the same canonical format any front's receipt uses), chained to this
/// source's own prior tail (each control-plane-internal source is its own independent hash-chain, the
/// same shape as every other `*.jsonl` under the audit dir). Signed with the device evidence key — this
/// event IS this device's own governance action, not an external front's.
fn emit_policy_receipt(action_id: &str, fields: Value) -> Result<(), String> {
    let key = evidence_signing_key()?;
    let path = policy_events_path();
    let prev_hash = last_line_hash(&path)?;
    let ts_ms = now_ms();
    let line = kriya_verify::sign_receipt(
        &key,
        &format!("policy-{ts_ms}"),
        action_id,
        fields,
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

// ── Kill switch (doc 24 §11 B16/EG-F) ───────────────────────────────────────────────────────────────

/// The fixed, maximally-restrictive fallback policy a device applies when the kill switch engages —
/// deny-by-default on every action, no budgets, no egress/detection/secrets sections. An emergency
/// halt, not a policy dial: this is NOT derived from the bundle's own `policy`/`budgets` in any way
/// (a compromised or malformed bundle can never talk its way out of the fallback by shaping those
/// fields), and it is the SAME fallback whether the switch was set explicitly by the operator or
/// engaged automatically by [`check_staleness`] ("the stale-policy kill-switch").
const KILL_SWITCH_POLICY_YAML: &str = "rules:\n  - action: \"*\"\n    allow: false\n";

/// Overwrite the on-device policy file with the kill-switch fallback and mark [`PolicyState`]
/// accordingly. Shared by the explicit-bundle-field path ([`verify_and_apply`]) and the
/// staleness-triggered path ([`check_staleness`]) so both engage IDENTICAL enforcement.
fn engage_kill_switch() -> Result<String, String> {
    let policy_path = crate::govern::agent_policy_path();
    crate::govern::save_agent_policy(KILL_SWITCH_POLICY_YAML.to_string())?;
    Ok(policy_path.to_string_lossy().into_owned())
}

// ── Apply: policy/budgets -> runtime YAML ───────────────────────────────────────────────────────────

/// Merge `bundle.policy` (rules) + `bundle.budgets` into ONE runtime policy YAML. Doc 22 §5 carries
/// `policy`/`budgets` as SEPARATE top-level bundle fields; the existing runtime format nests budget
/// caps under the policy YAML's own `budget:` key (`govern::save_agent_policy`, `src/lib/policy.ts`'s
/// `YamlPolicy{rules, budget}`) — this is the reconciliation point, not a contradiction of either shape.
fn policy_yaml_from_bundle(bundle: &PolicyBundle) -> Result<String, String> {
    let mut combined = bundle.policy.clone();
    if !combined.is_object() {
        combined = serde_json::json!({});
    }
    combined
        .as_object_mut()
        .expect("just ensured this is an object")
        .insert("budget".to_string(), bundle.budgets.clone());
    serde_yaml::to_string(&combined).map_err(|e| format!("policy bundle -> YAML: {e}"))
}

/// Apply `govern[]` via the doc-21 detect→wire engine: `"wire"` calls `govern_all` scoped to this
/// target's hook seam; anything else (`"unwire"`, `"remove"`, or an unrecognized future action)
/// reverts it via `ungovern` — never left silently dangling. A directive's own errors are collected,
/// never fatal to the rest of the bundle (the policy/budget tiers still apply even if e.g. the hook
/// binary isn't bundled on this machine).
fn apply_govern_directives(directives: &[GovernDirective]) -> Vec<String> {
    let mut errors = Vec::new();
    for d in directives {
        let target_id = format!("{}:hook", d.target);
        if d.action == "wire" {
            let report = govern_all(Some(GovernOpts {
                only: Some(vec![target_id.clone()]),
            }));
            errors.extend(report.errors.into_iter().map(|e| format!("govern {target_id}: {}", e.message)));
        } else {
            let report = ungovern(target_id.clone());
            errors.extend(
                report
                    .errors
                    .into_iter()
                    .map(|e| format!("ungovern {target_id}: {}", e.message)),
            );
        }
    }
    errors
}

/// What one successful [`verify_and_apply`] did — enough to show an honest before/after policy-file
/// diff and to drive `kriya.policy.applied`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyOutcome {
    pub version: u64,
    pub bundle_hash: String,
    pub policy_path: String,
    /// The policy YAML that was in effect BEFORE this apply (`None` if none existed yet).
    pub previous_policy_yaml: Option<String>,
    pub new_policy_yaml: String,
    /// Non-fatal per-directive `govern[]` failures (e.g. a hook binary not bundled here).
    pub govern_errors: Vec<String>,
    /// Whether this apply engaged the kill-switch fallback (doc 24 §11 B16/EG-F) — `new_policy_yaml`
    /// is [`KILL_SWITCH_POLICY_YAML`], not a projection of `bundle.policy`/`bundle.budgets`.
    pub kill_switch: bool,
}

/// Verify + apply a bundle already known to be in scope for THIS device — shared by the network pull
/// ([`pull_and_apply`]) and the air-gap file path ([`policy_apply_file`]). `org_policy_pub_hex` is the
/// device's OWN pinned trust anchor (`enrollment.json::org_policy_pub`) — never a key the bundle itself
/// asserts (see `kriya_verify::policy`'s module docs). `Ok(None)` (not an error) when the bundle didn't
/// supersede what's already applied — anti-rollback, nothing to do.
pub fn verify_and_apply(raw: &str, org_policy_pub_hex: &str) -> Result<Option<ApplyOutcome>, String> {
    let v: Value = serde_json::from_str(raw).map_err(|e| format!("bundle is not valid JSON: {e}"))?;
    kriya_verify::verify_policy_bundle(&v, org_policy_pub_hex)?;
    let signed: SignedPolicyBundle =
        serde_json::from_value(v).map_err(|e| format!("decode signed bundle: {e}"))?;
    let bundle = signed.bundle;

    let state = load_state();
    if !supersedes(bundle.version, state.last_applied_version) {
        return Ok(None);
    }

    let policy_path = crate::govern::agent_policy_path();
    let previous_policy_yaml = std::fs::read_to_string(&policy_path).ok();
    // The kill switch (doc 24 §11 B16/EG-F) overrides the bundle's own policy/budgets outright — an
    // emergency halt, not a policy dial. `govern[]` directives still apply either way: un-wiring an
    // agent is itself a safe, kill-switch-compatible action, and a wire directive is harmless (the
    // fallback policy denies everything regardless of what's wired).
    let new_policy_yaml = if bundle.kill_switch {
        KILL_SWITCH_POLICY_YAML.to_string()
    } else {
        policy_yaml_from_bundle(&bundle)?
    };
    crate::govern::save_agent_policy(new_policy_yaml.clone())?;
    let govern_errors = apply_govern_directives(&bundle.govern);

    let hash = bundle_hash(&bundle);
    let applied_ms = now_ms();
    save_state(&PolicyState {
        last_applied_version: Some(bundle.version),
        last_applied_bundle_hash: Some(hash.clone()),
        last_applied_ms: Some(applied_ms),
        last_applied_expires_ms: bundle.expires_ms,
        envelope_verbosity: Some(bundle.envelope_verbosity.clone()),
        stale_reported: false, // freshly applied ⇒ fresh by definition
        kill_switch_active: bundle.kill_switch,
        io_verbosity: Some(bundle.io_verbosity.clone()),
        egress_patterns: egress_patterns_from_bundle(&bundle),
        purpose_statement: bundle.purpose_statement.clone(),
    })?;

    emit_policy_receipt(
        "kriya.policy.applied",
        serde_json::json!({ "version": bundle.version, "bundle_hash": hash, "kill_switch": bundle.kill_switch }),
    )?;

    Ok(Some(ApplyOutcome {
        version: bundle.version,
        bundle_hash: hash,
        policy_path: policy_path.to_string_lossy().into_owned(),
        previous_policy_yaml,
        new_policy_yaml,
        govern_errors,
        kill_switch: bundle.kill_switch,
    }))
}

/// Check the currently-applied bundle's `expires_ms` against wall-clock time and emit
/// `kriya.policy.stale` ONCE per transition into staleness (never re-emitted every cycle while still
/// stale — `PolicyState::stale_reported`). Takes `now_ms` explicitly (dependency-injected, like the
/// Compiler's own window/heartbeat timers) so this is testable without a real clock. Called on the same
/// cadence as the downlink pull, so staleness is detected even when kriyad itself is unreachable — the
/// device's own clock is authoritative here (kriyad decides nothing, doc 22 §3).
///
/// **The stale-policy kill switch (doc 24 §11 B16/EG-F):** the FIRST transition into staleness also
/// engages [`KILL_SWITCH_POLICY_YAML`] — a device that has lost contact with the org long enough for
/// its own bundle to expire stops trusting that (now-unverifiable-as-current) bundle's permissive
/// rules and fails closed, exactly like an operator-set `kill_switch: true` would. This is automatic
/// and local: kriyad is never consulted (it may be the very thing that's unreachable) and authors
/// nothing (doc 22 §3) — the device's own clock decided. Recovery is a fresh, superseding
/// [`verify_and_apply`], which always overwrites the policy file again.
pub fn check_staleness(now_ms_val: u64) -> Result<(), String> {
    let mut state = load_state();
    let is_stale = state.last_applied_expires_ms.map(|exp| now_ms_val > exp).unwrap_or(false);
    if is_stale && !state.stale_reported {
        engage_kill_switch()?;
        emit_policy_receipt(
            "kriya.policy.stale",
            serde_json::json!({
                "version": state.last_applied_version,
                "bundle_hash": state.last_applied_bundle_hash,
                "kill_switch_engaged": true,
            }),
        )?;
        state.stale_reported = true;
        state.kill_switch_active = true;
        save_state(&state)?;
    } else if !is_stale && state.stale_reported {
        state.stale_reported = false;
        state.kill_switch_active = false;
        save_state(&state)?;
    }
    Ok(())
}

// ── Network pull (after each heartbeat) + air-gap file apply ────────────────────────────────────────

/// `GET /v1/policy` over the SAME mTLS client shape as `push.rs`/`device_info.rs` (pinned CA,
/// client-cert identity, no public-CA fallback). Treats HTTP 404 — and every other non-2xx or
/// transport failure — as `None`: an old kriyad lacking the route, a new kriyad with nothing published
/// in scope, and a transient network blip are ALL "nothing to apply this cycle" from the device's
/// perspective (BC-4; mirrors `device_info.rs::EmitOutcome`'s non-fatal-by-design shape).
#[cfg(feature = "control-plane")]
fn fetch_policy(
    target: &crate::control_plane::push::PushTarget,
    device_pub: &str,
    business_unit: Option<&str>,
) -> Option<String> {
    let identity_pem = std::fs::read(&target.client_identity_pem).ok()?;
    let ca_pem = std::fs::read(&target.server_ca_pem).ok()?;
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).ok()?)
        .identity(reqwest::Identity::from_pem(&identity_pem).ok()?)
        .build()
        .ok()?;
    let mut req = client
        .get(format!("{}/v1/policy", target.server_url))
        .query(&[("device_pub", device_pub)]);
    if let Some(bu) = business_unit {
        req = req.query(&[("business_unit", bu)]);
    }
    let resp = req.send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().ok()
}

/// The full downlink cycle — called after each heartbeat (doc 22 §5: "pull on the existing heartbeat
/// cycle", never a separate poll loop). No-ops with NO network call at all when this device has no
/// pinned `org_policy_pub` — an enrollment with the downlink simply not configured behaves EXACTLY like
/// a pre-P3 device (BC-4). A fetched-and-rejected bundle (bad signature, malformed) IS surfaced as an
/// `Err` (a real problem worth logging), unlike a fetch/transport failure, which [`fetch_policy`]
/// already absorbed to `None`.
#[cfg(feature = "control-plane")]
pub fn pull_and_apply(target: &crate::control_plane::push::PushTarget) -> Result<(), String> {
    let enrollment = enrollment::load_enrollment().ok_or("not enrolled")?;
    let Some(org_pub) = enrollment.org_policy_pub_hex() else {
        return Ok(()); // downlink off — no org key pinned (BC-4)
    };
    let device_pub = crate::control_plane::envelope::evidence_public_hex()?;

    if let Some(raw) = fetch_policy(target, &device_pub, enrollment.business_unit.as_deref()) {
        verify_and_apply(&raw, org_pub)?;
    }
    check_staleness(now_ms())
}

/// Air-gap variant (Tauri command): verify + apply a bundle carried across the gap as a FILE — the
/// identical verify+apply path [`pull_and_apply`] uses, just sourced from disk instead of the network
/// (mirrors `push::write_airgap`'s sneaker-net-equals-network symmetry). Gated on enrollment + a pinned
/// org key — NOT on `fleet-console` (that license flag gates the OPERATOR's authoring/publishing UI, a
/// different role; APPLYING a bundle is a device-side act any enrolled device can do).
#[tauri::command]
#[cfg(feature = "control-plane")]
pub fn policy_apply_file(path: String) -> Result<Option<ApplyOutcome>, String> {
    let enrollment = enrollment::load_enrollment().ok_or("not enrolled")?;
    let org_pub = enrollment
        .org_policy_pub_hex()
        .ok_or("no org policy key pinned in enrollment.json — the downlink is not configured")?;
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("reading {path}: {e}"))?;
    verify_and_apply(&raw, org_pub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// The ONE crate-wide lock (`crate::HOME_ENV_LOCK`) every `$HOME`-mutating test in this crate takes
    /// — a per-module lock alone doesn't stop this module's tests from racing another module's.
    use crate::HOME_ENV_LOCK as ENV_LOCK;

    fn with_sandboxed_home<T>(f: impl FnOnce() -> T) -> T {
        let tmp = std::env::temp_dir().join(format!(
            "kriya-policy-{}-{:?}",
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

    fn org_key() -> SigningKey {
        SigningKey::from_bytes(&[61u8; 32])
    }

    fn signed_bundle_json(key: &SigningKey, version: u64, expires_ms: Option<u64>) -> String {
        let signed = kriya_verify::sign_policy_bundle(
            key,
            kriya_verify::PolicyBundle {
                org_id: "acme".into(),
                version,
                issued_ms: 1000 + version,
                expires_ms,
                scope: kriya_verify::PolicyScope::all(),
                policy: serde_json::json!({ "rules": [{ "action": "*", "allow": true }] }),
                budgets: serde_json::json!({ "max_actions_per_minute": 42 }),
                govern: vec![],
                envelope_verbosity: "extended".into(),
                kill_switch: false,
                io_verbosity: "off".into(),
                purpose_statement: None,
            },
        );
        serde_json::to_string(&signed).unwrap()
    }

    /// Like [`signed_bundle_json`], but with an explicit `kill_switch` value — kept as a separate
    /// helper so the many existing (non-kill-switch) call sites above stay untouched.
    fn signed_bundle_json_ks(key: &SigningKey, version: u64, expires_ms: Option<u64>, kill_switch: bool) -> String {
        let signed = kriya_verify::sign_policy_bundle(
            key,
            kriya_verify::PolicyBundle {
                org_id: "acme".into(),
                version,
                issued_ms: 1000 + version,
                expires_ms,
                scope: kriya_verify::PolicyScope::all(),
                policy: serde_json::json!({ "rules": [{ "action": "*", "allow": true }] }),
                budgets: serde_json::json!({ "max_actions_per_minute": 42 }),
                govern: vec![],
                envelope_verbosity: "extended".into(),
                kill_switch,
                io_verbosity: "off".into(),
                purpose_statement: None,
            },
        );
        serde_json::to_string(&signed).unwrap()
    }

    /// A bundle carrying a real `policy.egress.rules[]` section plus `io_verbosity: "pattern-echo"`
    /// and a `purpose_statement` — for the EG-4 apply tests below.
    fn signed_bundle_json_pattern_echo(key: &SigningKey, version: u64) -> String {
        let signed = kriya_verify::sign_policy_bundle(
            key,
            kriya_verify::PolicyBundle {
                org_id: "acme".into(),
                version,
                issued_ms: 1000 + version,
                expires_ms: None,
                scope: kriya_verify::PolicyScope::all(),
                policy: serde_json::json!({
                    "rules": [{ "action": "*", "allow": true }],
                    "egress": {
                        "unlisted": "deny",
                        "rules": [
                            { "host": "*.vendor.com", "tier": "allow" },
                            { "host": "api.partner.com", "tier": "approval" },
                        ],
                    },
                }),
                budgets: serde_json::json!({}),
                govern: vec![],
                envelope_verbosity: "standard".into(),
                kill_switch: false,
                io_verbosity: "pattern-echo".into(),
                purpose_statement: Some("compliance/security evidence; never performance evaluation".into()),
            },
        );
        serde_json::to_string(&signed).unwrap()
    }

    #[test]
    fn verify_and_apply_persists_io_verbosity_egress_patterns_and_purpose_statement() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            verify_and_apply(&signed_bundle_json_pattern_echo(&key, 1), &pub_hex).unwrap();

            assert_eq!(current_io_verbosity(), "pattern-echo");
            assert_eq!(
                current_egress_patterns(),
                vec!["*.vendor.com".to_string(), "api.partner.com".to_string()]
            );
            assert_eq!(
                current_purpose_statement().as_deref(),
                Some("compliance/security evidence; never performance evaluation")
            );
        });
    }

    #[test]
    fn defaults_are_off_empty_and_none_before_any_bundle_applies() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            assert_eq!(current_io_verbosity(), "off");
            assert!(current_egress_patterns().is_empty());
            assert!(current_purpose_statement().is_none());
        });
    }

    #[test]
    fn egress_patterns_from_bundle_tolerates_missing_or_malformed_shapes() {
        let no_egress = kriya_verify::PolicyBundle {
            org_id: "acme".into(),
            version: 1,
            issued_ms: 0,
            expires_ms: None,
            scope: kriya_verify::PolicyScope::all(),
            policy: serde_json::json!({ "rules": [] }),
            budgets: serde_json::json!({}),
            govern: vec![],
            envelope_verbosity: "standard".into(),
            kill_switch: false,
            io_verbosity: "off".into(),
            purpose_statement: None,
        };
        assert!(egress_patterns_from_bundle(&no_egress).is_empty(), "no egress section at all");

        let malformed = kriya_verify::PolicyBundle {
            policy: serde_json::json!({ "egress": { "rules": [
                { "host": 42 }, { "no_host": "x" }, "not even an object", { "host": "" },
            ] } }),
            ..no_egress
        };
        assert!(
            egress_patterns_from_bundle(&malformed).is_empty(),
            "a non-string/missing host must be skipped, never panic"
        );
    }

    #[test]
    fn verify_and_apply_writes_policy_yaml_and_advances_state() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            let raw = signed_bundle_json(&key, 1, None);

            let outcome = verify_and_apply(&raw, &pub_hex).unwrap().expect("v1 supersedes nothing");
            assert_eq!(outcome.version, 1);
            assert!(outcome.previous_policy_yaml.is_none(), "no prior policy existed");
            assert!(outcome.new_policy_yaml.contains("max_actions_per_minute"));
            assert!(outcome.govern_errors.is_empty(), "no govern[] directives in this fixture");

            // The runtime-visible policy file was actually written, with the merged budget section.
            let on_disk = std::fs::read_to_string(&outcome.policy_path).unwrap();
            assert_eq!(on_disk, outcome.new_policy_yaml);
            assert!(on_disk.contains("42"));

            // State advanced.
            let state = load_state();
            assert_eq!(state.last_applied_version, Some(1));
            assert_eq!(state.envelope_verbosity.as_deref(), Some("extended"));
            assert_eq!(current_envelope_verbosity(), "extended");

            // The kriya.policy.applied receipt landed, verifies, and is chained (genesis).
            let events = std::fs::read_to_string(policy_events_path()).unwrap();
            let lines: Vec<&str> = events.lines().filter(|l| !l.trim().is_empty()).collect();
            assert_eq!(lines.len(), 1);
            let v: Value = serde_json::from_str(lines[0]).unwrap();
            assert_eq!(v["action_id"], "kriya.policy.applied");
            assert!(kriya_verify::verify_value(&v).is_ok());
        });
    }

    #[test]
    fn verify_and_apply_shows_an_honest_diff_on_a_second_apply() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            verify_and_apply(&signed_bundle_json(&key, 1, None), &pub_hex).unwrap();

            let outcome = verify_and_apply(&signed_bundle_json(&key, 2, None), &pub_hex)
                .unwrap()
                .expect("v2 supersedes v1");
            assert_eq!(outcome.version, 2);
            assert!(
                outcome.previous_policy_yaml.is_some(),
                "the v1-applied file must be captured as the pre-image"
            );

            // Two receipts now, chained.
            let events = std::fs::read_to_string(policy_events_path()).unwrap();
            let lines: Vec<&str> = events.lines().filter(|l| !l.trim().is_empty()).collect();
            assert_eq!(lines.len(), 2);
            assert_eq!(kriya_verify::chain_break(&events), None, "the policy-events source chains");
        });
    }

    #[test]
    fn anti_rollback_rejects_equal_and_lower_versions() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            verify_and_apply(&signed_bundle_json(&key, 5, None), &pub_hex).unwrap();

            // Equal version: not applied (a replay), no error, no second receipt.
            let replay = verify_and_apply(&signed_bundle_json(&key, 5, None), &pub_hex).unwrap();
            assert!(replay.is_none(), "an equal version must not re-apply");

            // Lower version: not applied (a rollback attempt).
            let rollback = verify_and_apply(&signed_bundle_json(&key, 3, None), &pub_hex).unwrap();
            assert!(rollback.is_none(), "a lower version must not apply — anti-rollback");

            assert_eq!(load_state().last_applied_version, Some(5), "state stays at the highest applied");
            let events = std::fs::read_to_string(policy_events_path()).unwrap();
            assert_eq!(
                events.lines().filter(|l| !l.trim().is_empty()).count(),
                1,
                "no receipt for a rejected replay/rollback"
            );
        });
    }

    #[test]
    fn a_tampered_bundle_is_rejected_and_never_applied() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            let raw = signed_bundle_json(&key, 1, None);
            let mut v: Value = serde_json::from_str(&raw).unwrap();
            v["bundle"]["policy"]["rules"][0]["allow"] = serde_json::json!(false);

            let err = verify_and_apply(&v.to_string(), &pub_hex).unwrap_err();
            assert!(!err.is_empty());
            assert!(load_state().last_applied_version.is_none(), "a tampered bundle must never apply");
            assert!(
                !crate::govern::agent_policy_path().exists(),
                "no policy file must be written for a rejected bundle"
            );
        });
    }

    #[test]
    fn a_bundle_signed_by_the_wrong_key_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let pinned = org_key();
            let pinned_pub = hex::encode(pinned.verifying_key().to_bytes());
            let attacker = SigningKey::from_bytes(&[62u8; 32]);
            let forged = signed_bundle_json(&attacker, 1, None);

            assert!(verify_and_apply(&forged, &pinned_pub).is_err());
            assert!(load_state().last_applied_version.is_none());
        });
    }

    #[test]
    fn check_staleness_emits_once_then_clears_on_recovery() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            verify_and_apply(&signed_bundle_json(&key, 1, Some(1_000)), &pub_hex).unwrap();

            check_staleness(500).unwrap(); // before expiry — not stale
            assert!(!load_state().stale_reported);
            let events_before = std::fs::read_to_string(policy_events_path()).unwrap();
            assert_eq!(events_before.lines().filter(|l| !l.trim().is_empty()).count(), 1, "only policy.applied so far");

            check_staleness(2_000).unwrap(); // past expiry — stale, first time
            assert!(load_state().stale_reported);
            check_staleness(3_000).unwrap(); // still stale — must NOT re-emit
            let events_after = std::fs::read_to_string(policy_events_path()).unwrap();
            let lines: Vec<&str> = events_after.lines().filter(|l| !l.trim().is_empty()).collect();
            assert_eq!(lines.len(), 2, "exactly one kriya.policy.stale, not one per check");
            let stale: Value = serde_json::from_str(lines[1]).unwrap();
            assert_eq!(stale["action_id"], "kriya.policy.stale");
            assert!(kriya_verify::verify_value(&stale).is_ok());
        });
    }

    // ─── Kill switch (doc 24 §11 B16/EG-F) ─────────────────────────────────────────────────────────

    #[test]
    fn an_explicit_kill_switch_bundle_writes_the_deny_all_fallback_not_the_bundles_own_policy() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            let raw = signed_bundle_json_ks(&key, 1, None, true);

            let outcome = verify_and_apply(&raw, &pub_hex).unwrap().expect("v1 supersedes nothing");
            assert!(outcome.kill_switch);
            assert_eq!(outcome.new_policy_yaml, KILL_SWITCH_POLICY_YAML);
            assert!(
                !outcome.new_policy_yaml.contains("max_actions_per_minute"),
                "the kill switch must NOT be a projection of the bundle's own policy/budgets"
            );

            let on_disk = std::fs::read_to_string(&outcome.policy_path).unwrap();
            assert_eq!(on_disk, KILL_SWITCH_POLICY_YAML);

            assert!(load_state().kill_switch_active);

            let events = std::fs::read_to_string(policy_events_path()).unwrap();
            let line: Value = serde_json::from_str(events.lines().next().unwrap()).unwrap();
            assert_eq!(line["action_id"], "kriya.policy.applied");
            assert_eq!(line["params"]["kill_switch"], true);
        });
    }

    #[test]
    fn a_fresh_non_kill_switch_bundle_lifts_the_kill_switch() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            verify_and_apply(&signed_bundle_json_ks(&key, 1, None, true), &pub_hex).unwrap();
            assert!(load_state().kill_switch_active);

            let outcome = verify_and_apply(&signed_bundle_json_ks(&key, 2, None, false), &pub_hex)
                .unwrap()
                .expect("v2 supersedes v1");
            assert!(!outcome.kill_switch);
            assert!(outcome.new_policy_yaml.contains("max_actions_per_minute"));
            assert!(!load_state().kill_switch_active, "a fresh apply lifts the kill switch");
        });
    }

    #[test]
    fn staleness_engages_the_kill_switch_automatically_and_a_fresh_apply_lifts_it() {
        // "The stale-policy kill switch": a device that hasn't heard from the org since its bundle's
        // own expiry fails closed automatically, without any operator having set kill_switch: true.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            let outcome =
                verify_and_apply(&signed_bundle_json(&key, 1, Some(1_000)), &pub_hex).unwrap().unwrap();
            assert!(outcome.new_policy_yaml.contains("max_actions_per_minute"), "starts permissive");
            assert!(!load_state().kill_switch_active);

            check_staleness(500).unwrap(); // before expiry — untouched
            assert!(!load_state().kill_switch_active);
            let on_disk = std::fs::read_to_string(&outcome.policy_path).unwrap();
            assert!(on_disk.contains("max_actions_per_minute"), "still the original policy pre-expiry");

            check_staleness(2_000).unwrap(); // past expiry — kill switch engages
            assert!(load_state().kill_switch_active);
            let on_disk = std::fs::read_to_string(&outcome.policy_path).unwrap();
            assert_eq!(on_disk, KILL_SWITCH_POLICY_YAML, "the stale bundle's own rules are no longer trusted");

            let events = std::fs::read_to_string(policy_events_path()).unwrap();
            let lines: Vec<&str> = events.lines().filter(|l| !l.trim().is_empty()).collect();
            let stale: Value = serde_json::from_str(lines[1]).unwrap();
            assert_eq!(stale["action_id"], "kriya.policy.stale");
            assert_eq!(stale["params"]["kill_switch_engaged"], true);

            // Recovery: a fresh, superseding, non-kill-switch bundle lifts it again.
            let recovered = verify_and_apply(&signed_bundle_json(&key, 2, None), &pub_hex)
                .unwrap()
                .expect("v2 supersedes v1");
            assert!(!recovered.kill_switch);
            assert!(!load_state().kill_switch_active);
            let on_disk = std::fs::read_to_string(&recovered.policy_path).unwrap();
            assert!(on_disk.contains("max_actions_per_minute"), "the fresh bundle's own policy is restored");
        });
    }

    #[cfg(feature = "control-plane")]
    #[test]
    fn pull_and_apply_is_a_silent_no_op_when_the_downlink_is_not_configured() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            std::fs::create_dir_all(crate::audit::console_dir()).unwrap();
            std::fs::write(
                crate::audit::console_dir().join("enrollment.json"),
                r#"{"serverUrl":"https://kriyad.invalid:8443","orgId":"acme",
                    "operatorId":"op-1","serverCaPinSha256":"ab"}"#, // no orgPolicyPub — downlink off
            )
            .unwrap();
            let target = crate::control_plane::push::PushTarget {
                server_url: "https://kriyad.invalid:8443".into(),
                client_identity_pem: "/nonexistent/client.pem".into(),
                server_ca_pem: "/nonexistent/ca.pem".into(),
            };
            // Must return Ok(()) WITHOUT ever attempting a network call (proven by the certs not
            // existing — if this tried to build an mTLS client it would still be Ok via fetch_policy's
            // None-on-any-failure absorption, so the REAL proof is that no state/receipt is touched).
            pull_and_apply(&target).expect("no-op, never an error, when downlink isn't configured");
            assert!(load_state().last_applied_version.is_none());
            assert!(!policy_events_path().exists());
        });
    }

    #[cfg(feature = "control-plane")]
    #[test]
    fn pull_and_apply_is_non_fatal_when_transport_identity_is_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let pub_hex = hex::encode(org_key().verifying_key().to_bytes());
            std::fs::create_dir_all(crate::audit::console_dir()).unwrap();
            std::fs::write(
                crate::audit::console_dir().join("enrollment.json"),
                format!(
                    r#"{{"serverUrl":"https://kriyad.invalid:8443","orgId":"acme",
                        "operatorId":"op-1","serverCaPinSha256":"ab","orgPolicyPub":"{pub_hex}"}}"#
                ),
            )
            .unwrap();
            let target = crate::control_plane::push::PushTarget {
                server_url: "https://kriyad.invalid:8443".into(),
                client_identity_pem: "/nonexistent/client.pem".into(),
                server_ca_pem: "/nonexistent/ca.pem".into(),
            };
            // A downlink that IS configured but can't reach the network (missing certs here,
            // equally a real network blip in production) must still be non-fatal — local governance
            // is never blocked by a transport problem (mirrors `device_info.rs`'s emit path).
            pull_and_apply(&target).expect("a transport failure must not error — local-first");
        });
    }

    #[test]
    fn policy_apply_file_requires_a_pinned_org_key() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            std::fs::create_dir_all(crate::audit::console_dir()).unwrap();
            std::fs::write(
                crate::audit::console_dir().join("enrollment.json"),
                r#"{"serverUrl":"https://kriyad.invalid:8443","orgId":"acme",
                    "operatorId":"op-1","serverCaPinSha256":"ab"}"#,
            )
            .unwrap();
            let err = policy_apply_file("/nonexistent/bundle.json".into()).unwrap_err();
            assert!(err.contains("org policy key"), "{err}");
        });
    }

    #[test]
    fn policy_apply_file_round_trips_a_real_bundle_from_disk() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        with_sandboxed_home(|| {
            let key = org_key();
            let pub_hex = hex::encode(key.verifying_key().to_bytes());
            std::fs::create_dir_all(crate::audit::console_dir()).unwrap();
            std::fs::write(
                crate::audit::console_dir().join("enrollment.json"),
                format!(
                    r#"{{"serverUrl":"https://kriyad.invalid:8443","orgId":"acme",
                        "operatorId":"op-1","serverCaPinSha256":"ab","orgPolicyPub":"{pub_hex}"}}"#
                ),
            )
            .unwrap();
            let bundle_path = crate::audit::console_dir().join("bundle-v1.json");
            std::fs::write(&bundle_path, signed_bundle_json(&key, 1, None)).unwrap();

            let outcome = policy_apply_file(bundle_path.to_string_lossy().into_owned())
                .unwrap()
                .expect("a genuinely valid, superseding bundle applies");
            assert_eq!(outcome.version, 1);
            assert_eq!(load_state().last_applied_version, Some(1));
        });
    }
}
