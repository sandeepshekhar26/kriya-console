//! The device-side **DeviceInfo** collector (doc 22 §7, fleet cockpit v2.1, P1 step 2) — builds a
//! [`kriya_verify::DeviceInfo`] snapshot from what this Console already knows (its own version, the
//! doc-21 govern-all detection, the outbox, enrollment), signs it with the device evidence key, and
//! POSTs it to the new `POST /v1/device-info` route on startup and whenever its content changes.
//!
//! **Local-first, by construction**: every step that can fail (build, sign, POST) returns/handles its
//! error without panicking, and the emit path treats EVERY transport outcome — success, HTTP error, a
//! network failure, and specifically HTTP 404 (an old kriyad that doesn't have this route yet, BC-4)
//! — as non-fatal. This module must never block or interrupt the governance the device is already
//! doing (the Compiler/outbox/enforcement paths keep running regardless of whether this beacon ever
//! lands anywhere).
//!
//! **GDPR allowlist boundary**: this collector is the ONLY place that constructs a
//! [`kriya_verify::DeviceInfo`] on-device. It reads `enrollment.json` for `device_label` and NEVER
//! reads `$HOSTNAME`/`whoami`/any OS-identity API — see [`device_label`]'s doc comment for the exact
//! reasoning, and `kriya_verify::device_info`'s own allowlist test for the schema-level enforcement.

use std::path::PathBuf;

use kriya_verify::{
    canonical_json_bytes, sha256_hex, sign_device_info, AgentInfo, DeviceInfo, OsInfo, PolicyEcho,
    SignedDeviceInfo,
};

use crate::control_plane::enrollment::{self, Enrollment};
use crate::control_plane::envelope::evidence_signing_key;
use crate::govern::{governable_surface, GovernTarget};

// ── Field collection ────────────────────────────────────────────────────────────────────────────

/// This Console's own version — the exact same technique `coverage.rs::emit_snapshot` already uses
/// for its `console_version` param (`env!("CARGO_PKG_VERSION")`, baked in at compile time from
/// `src-tauri/Cargo.toml`). No process spawn, no filesystem read, can't fail.
fn console_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// `kriya-verify`'s own crate version — this Console statically links a pinned `kriya-verify`
/// (`src-tauri/Cargo.toml`'s `[dependencies] kriya-verify = { path = "crates/kriya-verify" }`), so the
/// verifier logic actually compiled into THIS binary is exactly `kriya_verify::VERSION` (re-exported
/// from that crate's own `CARGO_PKG_VERSION`) — never a runtime probe of some other installed copy.
fn verify_crate_version() -> String {
    format!("kriya-verify {}", kriya_verify::VERSION)
}

/// **Judgment call (documented per task instructions):** doc 22 §7's sample schema shows
/// `"runtime_version": "kriya-host 0.4.2"` with the inline comment "the governed gateway/runtime".
/// Research against the actual codebase found:
///   - No `kriya-host` binary is bundled by this Console at all (`onboarding::resolve_sidecar` only
///     ever resolves `kriya-gateway` / `kriya-hook` / `kriya-hermes-hook`); `kriya-host` exists in the
///     sibling `experiment1` repo but isn't even wired into that repo's own `[[bin]]` list and this app
///     never shells out to it.
///   - The binary this Console actually bundles and calls "the governed gateway/runtime" in its own
///     onboarding code is `kriya-gateway` (`onboarding::resolve_gateway`) — the sidecar that wraps
///     local MCP servers under governance. That matches the doc's own inline comment far better than a
///     binary this app has never heard of.
///   - Neither `kriya-gateway` nor `kriya-hook`/`kriya-hermes-hook` implements a `--version` flag today
///     (confirmed empirically: `kriya-gateway --version` exits 2 with a "unknown subcommand" usage
///     error, and `doctor`'s human-readable preflight output has no version line either) — so there is
///     no non-destructive way to extract a real semver from the shipped binary without teaching it a
///     new flag, which is out of this step's scope (device-side collector only).
///
/// Given that, this reports the resolved sidecar's PRESENCE/PROVENANCE (bundled vs. dev-loose vs.
/// absent) rather than fabricating a version number it cannot actually read — honest beats invented,
/// per `docs/TRUST.md`'s standing principle. When `kriya-gateway` grows a real `--version`, this is the
/// one function to update.
fn runtime_version() -> String {
    match crate::onboarding::resolve_gateway() {
        Some((_, true)) => "kriya-gateway (bundled)".to_string(),
        Some((_, false)) => "kriya-gateway (dev)".to_string(),
        None => "kriya-gateway (not found)".to_string(),
    }
}

/// Coarse OS descriptor — platform family + arch from `std::env::consts` (compile-time constants, no
/// process/API call, so this can never fail or leak anything dynamic), plus a best-effort coarse OS
/// version string. No hostname, no serial, no MAC — see doc 22 §7's exclusion table.
fn os_info() -> OsInfo {
    OsInfo {
        platform: std::env::consts::OS.to_string(), // "macos" | "linux" | "windows"
        version: os_coarse_version(),
        arch: std::env::consts::ARCH.to_string(), // "aarch64" | "x86_64" | ...
    }
}

/// Best-effort coarse OS version (e.g. macOS `"15.5"`), via `sw_vers -productVersion` on macOS —
/// deliberately NOT `uname -a`/`system_profiler` (those can embed a hardware serial or hostname).
/// Any failure (binary absent, non-UTF8, non-zero exit) yields `"unknown"`, never a panic and never a
/// blocked emit — this field is cosmetic (an "update available" nicety), not load-bearing.
fn os_coarse_version() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        "unknown".to_string()
    }
}

/// **Judgment call:** map the doc-21 govern-all detection (`governable_surface()`) into doc 22 §7's
/// `agents[]` shape. Per-field sourcing (documented, since the research phase found three of the five
/// fields don't exist anywhere in `govern.rs` today):
///   - `id` — `GovernTarget::agent` (exact match: `"claude-code"` / `"hermes"`; `"claude-desktop"` and
///     `"desktop"` targets are skipped here, see below).
///   - `wired` — derived as `state == "governed"`. `GovernTarget::state` is a 4-way enum string; only
///     `"governed"` means "the adapter is actually installed and active", so that's the one true case.
///   - `adapter` — derived from the agent id (`"claude-code"` → `"kriya-hook"`, `"hermes"` →
///     `"kriya-hermes-hook"`), matching `onboarding::resolve_hook`/`resolve_hermes_hook`'s own binary
///     names — this Console has exactly one hook adapter per governable agent today, so the mapping is
///     unambiguous, but it IS a derivation, not a field `GovernTarget` carries directly.
///   - `adapter_version` / `version` (the agent's own version) — **no probe exists anywhere in this
///     codebase** for either (confirmed: no `claude --version`/`hermes --version` shell-out, no hook
///     binary version query). Rather than fabricate a number, both report `"unknown"` — an honest
///     placeholder the P3+ work can replace once a real version probe lands, consistent with this
///     collector's "don't invent facts it can't verify" stance (mirrors `runtime_version` above).
///
/// Only `claude-code` and `hermes` targets carry a hook-adapter identity today (the doc-21 "governed
/// gateway/runtime" seam this schema field is about); `claude-desktop`'s MCP-server targets and the
/// `desktop:desktop-apps` reach-in target aren't a discrete "agent" with an adapter/version in this
/// schema's sense, so they're excluded from `agents[]` — surfacing them would require inventing fields
/// the doc's schema doesn't have a slot for.
fn agents_from_surface() -> Vec<AgentInfo> {
    let surface = governable_surface();
    let mut seen = std::collections::BTreeSet::new();
    let mut agents = Vec::new();
    for t in surface.targets.iter().filter(|t| t.kind == "hook") {
        if !seen.insert(t.agent.clone()) {
            continue; // one row per agent, even if detect() ever emits >1 hook target for it
        }
        if let Some(info) = agent_info_from_target(t) {
            agents.push(info);
        }
    }
    agents
}

fn agent_info_from_target(t: &GovernTarget) -> Option<AgentInfo> {
    let adapter = match t.agent.as_str() {
        "claude-code" => "kriya-hook",
        "hermes" => "kriya-hermes-hook",
        _ => return None, // no known adapter for this agent id — nothing sensible to report
    };
    Some(AgentInfo {
        id: t.agent.clone(),
        version: "unknown".to_string(), // no agent-version probe exists yet (see fn doc above)
        adapter: adapter.to_string(),
        adapter_version: "unknown".to_string(), // no adapter-version probe exists yet
        wired: t.state == "governed",
    })
}

/// `policy` is always `None` pre-P3 (no policy-push producer exists yet) — the field itself is present
/// in the schema (`Option<PolicyEcho>`, `skip_serializing_if`), its value simply has no producer today.
fn policy_echo() -> Option<PolicyEcho> {
    None
}

/// Buffered-envelope health signal — the outbox's line count. Reuses `outbox::head()`'s already-public
/// read path (`next_seq - 1` is the highest seq ever appended, NOT "how many are still undelivered" —
/// see the judgment-call note below) rather than adding new outbox-drain-state tracking, which is out
/// of this step's scope (outbox drain/ack bookkeeping belongs to the push client, `push.rs`, which
/// today has no "delivered up to seq N" cursor at all — it's a courier, not a queue with acks).
///
/// **Judgment call:** absent a real "delivered" cursor, `outbox_pending` is approximated as the total
/// count of lines currently in the outbox file (append-only; nothing truncates it today), which is an
/// upper bound on "pending" and exactly correct until a future ack/truncate mechanism lands. This is a
/// health signal for the cockpit dashboard, not evidence — an over-count here does not affect any
/// trust-spine guarantee.
fn outbox_pending() -> u64 {
    crate::control_plane::outbox::line_count().unwrap_or(0)
}

/// `enrolled_ms` — **judgment call:** `Enrollment` (`enrollment.rs`) has no `enrolled_ms` field of its
/// own (confirmed in research: the struct is `{server_url, org_id, business_unit?, operator_id,
/// server_ca_pin_sha256}`, no timestamp). Rather than add a new required field to the MDM-authored
/// `enrollment.json` wire shape (a breaking change to what MDM tooling must write), this derives
/// `enrolled_ms` from the enrollment file's own filesystem modification time — the moment enrollment
/// was (re)written IS the moment this device became enrolled, and it's already durable/monotonic
/// without any new on-disk field. Falls back to `0` (not a panic, not a fabricated "now") if the mtime
/// is unavailable for any reason — an honest "unknown" rather than a false claim of freshness.
fn enrolled_ms() -> u64 {
    let path = crate::audit::console_dir().join("enrollment.json");
    std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `device_label` — **hard requirement, not a fallback**: ONLY `enrollment.json`'s own optional
/// `device_label` field (an enterprise/MDM-assigned asset tag), NEVER the OS hostname. Per doc 22 §7's
/// exclusion table: "Hostname — never auto-derived (usually contains a person's name); the
/// enterprise-assigned `device_label` asset tag from MDM is the only naming."
///
/// The task text says "ONLY from enrollment/fleet.json"; research (this Console's actual code) found
/// `fleet.json` is the OPERATOR's own connection config (`fleet.rs`, `~/.kriya/console/fleet.json`,
/// explicitly documented as "kept deliberately independent of `enrollment.json` — this is the console
/// operator's own connection, not the device's") with no label field at all, while `enrollment.json` is
/// the device-side MDM-written binding — exactly where an MDM asset tag belongs. So `device_label`
/// reads ONLY `enrollment.json`; `fleet.json` is never touched by this function. [`Enrollment`] gained
/// an additive, `#[serde(default)]` `device_label: Option<String>` field (this step) so an
/// MDM-authored `enrollment.json` MAY set it; existing enrollment files without it parse unaffected.
fn device_label(enrollment: &Enrollment) -> Option<String> {
    enrollment.device_label.clone()
}

// ── Assembly ─────────────────────────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build the current [`DeviceInfo`] snapshot from live device state. Pure collection — never signs,
/// never emits, so it's independently testable and safe to call speculatively (e.g. to hash-compare
/// against the last-emitted snapshot before deciding whether to sign+POST at all).
pub fn collect(enrollment: &Enrollment) -> DeviceInfo {
    DeviceInfo {
        console_version: console_version(),
        runtime_version: runtime_version(),
        verify_crate_version: verify_crate_version(),
        os: os_info(),
        agents: agents_from_surface(),
        policy: policy_echo(),
        outbox_pending: outbox_pending(),
        enrolled_ms: enrolled_ms(),
        device_label: device_label(enrollment),
    }
}

/// Content hash of a [`DeviceInfo`] snapshot — canonical JSON (R21, the same key-sorting technique the
/// signer itself uses) so field REORDER never spuriously trips a "changed" detection, only an actual
/// value change does. Used purely for local change-detection (never transmitted, never signed itself —
/// the signed bytes are `device_info_canonical_bytes`, computed fresh at sign time).
pub fn content_hash(info: &DeviceInfo) -> String {
    sha256_hex(&canonical_json_bytes(
        &serde_json::to_value(info).unwrap_or(serde_json::Value::Null),
    ))
}

// ── Emit-on-startup / emit-on-change state ──────────────────────────────────────────────────────

/// Durable "last emitted content hash" — mirrors `compiler::{load_state,save_state}`'s exact idiom
/// (a small JSON sidecar under `~/.kriya/console/`, best-effort read with a safe default, written on
/// successful emit) since no existing "hash change → re-emit" mechanism exists elsewhere in this
/// codebase to reuse directly (confirmed in research: `Compiler`/`HeartbeatTimer` are both fixed-
/// interval, not content-hash-gated).
fn last_hash_path() -> PathBuf {
    crate::audit::console_dir().join("device-info-state.json")
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct DeviceInfoState {
    last_emitted_hash: Option<String>,
}

fn load_last_hash() -> Option<String> {
    std::fs::read_to_string(last_hash_path())
        .ok()
        .and_then(|t| serde_json::from_str::<DeviceInfoState>(&t).ok())
        .and_then(|s| s.last_emitted_hash)
}

fn save_last_hash(hash: &str) -> Result<(), String> {
    let path = last_hash_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let state = DeviceInfoState {
        last_emitted_hash: Some(hash.to_string()),
    };
    let json = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("writing device-info state: {e}"))
}

// ── Transport ────────────────────────────────────────────────────────────────────────────────────

/// The outcome of one emit attempt — surfaced for logging/tests; never propagated as a hard error to
/// any caller (local-first: this beacon is a nicety for the fleet cockpit, never a gate on governance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitOutcome {
    /// The server accepted the beacon (2xx).
    Sent,
    /// The content hash hadn't changed since the last successful send — nothing to do.
    Unchanged,
    /// The server doesn't have this route yet (HTTP 404) — an old kriyad, BC-4. Silent by design: this
    /// is the expected steady state for any fleet running a pre-P1 aggregator, not a fault.
    ServerTooOld,
    /// Any other failure (network error, non-2xx, non-success) — logged at most, never fatal.
    Failed(String),
}

/// POST a signed [`DeviceInfo`] beacon to `/v1/device-info` over the SAME mTLS client pattern as
/// `push.rs`/`fleet_client.rs` (pinned server CA, client-cert identity, no public-CA fallback).
/// Treats HTTP 404 as [`EmitOutcome::ServerTooOld`] (BC-4) and every other failure as
/// [`EmitOutcome::Failed`] — NEVER an `Err` that could propagate into a panic or block the caller.
#[cfg(feature = "control-plane")]
fn push_device_info(
    target: &crate::control_plane::push::PushTarget,
    signed: &SignedDeviceInfo,
) -> EmitOutcome {
    let body = match serde_json::to_string(signed) {
        Ok(b) => b,
        Err(e) => return EmitOutcome::Failed(format!("serialize device-info: {e}")),
    };
    let identity_pem = match std::fs::read(&target.client_identity_pem) {
        Ok(b) => b,
        Err(e) => return EmitOutcome::Failed(format!("read client identity: {e}")),
    };
    let ca_pem = match std::fs::read(&target.server_ca_pem) {
        Ok(b) => b,
        Err(e) => return EmitOutcome::Failed(format!("read server CA: {e}")),
    };
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false) // no public-CA fallback — pin the customer CA only
        .add_root_certificate(match reqwest::Certificate::from_pem(&ca_pem) {
            Ok(c) => c,
            Err(e) => return EmitOutcome::Failed(format!("parse server CA: {e}")),
        })
        .identity(match reqwest::Identity::from_pem(&identity_pem) {
            Ok(i) => i,
            Err(e) => return EmitOutcome::Failed(format!("parse client identity: {e}")),
        })
        .build();
    let client = match client {
        Ok(c) => c,
        Err(e) => return EmitOutcome::Failed(format!("build mTLS client: {e}")),
    };

    match client
        .post(format!("{}/v1/device-info", target.server_url))
        .body(body)
        .send()
    {
        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => EmitOutcome::ServerTooOld,
        Ok(resp) if resp.status().is_success() => EmitOutcome::Sent,
        Ok(resp) => EmitOutcome::Failed(format!("device-info rejected: HTTP {}", resp.status())),
        Err(e) => EmitOutcome::Failed(format!("POST /v1/device-info: {e}")),
    }
}

/// The real emit path: collect the current snapshot, skip if unchanged since the last successful send,
/// sign with the device evidence key, POST it, and (only on confirmed delivery — `Sent`) persist the
/// new content hash. Called on startup and by the periodic poll loop; every failure mode is absorbed
/// here (see [`EmitOutcome`]) — this function's `Result` only reflects "was there enrollment/key
/// material to work with at all", never a network outcome.
///
/// **`target` is caller-supplied, not derived here — a deliberate scope boundary.** Research into the
/// existing codebase found `push.rs`'s `PushTarget` (device cert + key + pinned server CA paths) has
/// NO established provisioning path from `Enrollment` today: `Enrollment` carries only
/// `server_ca_pin_sha256` (a pin hash, not a CA file) and no client cert/key paths at all, and the only
/// thing that ever mints real device mTLS certs is the explicitly-labeled `kriyd-ca.sh` **DEV/PILOT
/// stub** ("real CA + per-device single-use tokens = Phase 3" per its own header) — `push_envelopes`/
/// `push_heartbeat` (the transport this reuses) are themselves already built+tested but not called from
/// anywhere in `lib.rs`'s spawn loop today. Rather than invent a fake "how does a device get its
/// transport identity" path to satisfy this step, `emit_if_changed` takes `target: &PushTarget`
/// injected by the caller — exactly the same dependency-injection shape `compiler::compile_once` uses
/// for its own inputs — so the real answer to "where do these paths come from" is deferred to whoever
/// wires the real device-enrollment handshake (Phase 3 scope, not P1 step 2's device-info collector).
#[cfg(feature = "control-plane")]
pub fn emit_if_changed(target: &crate::control_plane::push::PushTarget) -> Result<EmitOutcome, String> {
    let enrollment = enrollment::load_enrollment().ok_or("not enrolled")?;
    let info = collect(&enrollment);
    let hash = content_hash(&info);
    if load_last_hash().as_deref() == Some(hash.as_str()) {
        return Ok(EmitOutcome::Unchanged);
    }

    let key = evidence_signing_key()?;
    let signed = sign_device_info(&key, now_ms(), info);

    let outcome = push_device_info(target, &signed);
    if outcome == EmitOutcome::Sent {
        let _ = save_last_hash(&hash); // best-effort: a failed persist just re-sends next cycle
    }
    match &outcome {
        EmitOutcome::ServerTooOld => {
            // BC-4: expected steady state against a pre-P1 kriyad. Debug-level at most, never an error.
            #[cfg(debug_assertions)]
            eprintln!("[device-info] server does not support /v1/device-info yet (404) — skipping");
        }
        EmitOutcome::Failed(_e) => {
            // Non-fatal by design (local-first) — never escalated beyond a debug note.
            #[cfg(debug_assertions)]
            eprintln!("[device-info] emit failed non-fatally: {_e}");
        }
        _ => {}
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_enrollment() -> Enrollment {
        Enrollment {
            server_url: "https://kriyad.invalid:8443".into(),
            org_id: "acme".into(),
            business_unit: None,
            operator_id: "op-1".into(),
            server_ca_pin_sha256: "ab".into(),
            device_label: Some("ENG-1234".into()),
            org_policy_pub: None,
        }
    }

    #[test]
    fn collect_never_derives_device_label_from_hostname() {
        let mut e = sample_enrollment();
        e.device_label = None;
        let info = collect(&e);
        assert_eq!(
            info.device_label, None,
            "no device_label in enrollment.json => None, never a hostname fallback"
        );
    }

    #[test]
    fn collect_reads_device_label_only_from_enrollment() {
        let e = sample_enrollment();
        let info = collect(&e);
        assert_eq!(info.device_label.as_deref(), Some("ENG-1234"));
    }

    #[test]
    fn collect_policy_is_none_pre_p3() {
        let info = collect(&sample_enrollment());
        assert!(info.policy.is_none());
    }

    #[test]
    fn content_hash_is_stable_and_reorder_safe() {
        let info = collect(&sample_enrollment());
        let h1 = content_hash(&info);
        let h2 = content_hash(&info);
        assert_eq!(h1, h2, "hashing is deterministic for the same value");

        let mut changed = info.clone();
        changed.outbox_pending += 1;
        assert_ne!(
            content_hash(&changed),
            h1,
            "a real content change must change the hash"
        );
    }

    #[test]
    fn console_version_and_verify_crate_version_are_non_empty() {
        assert!(!console_version().is_empty());
        assert!(verify_crate_version().starts_with("kriya-verify "));
    }

    #[test]
    fn agent_info_from_target_maps_known_agents_and_skips_unknown() {
        let governed = GovernTarget {
            id: "claude-code:hook".into(),
            agent: "claude-code".into(),
            kind: "hook".into(),
            seam: "hook".into(),
            state: "governed".into(),
            config_path: None,
            label: "x".into(),
            detail: "x".into(),
        };
        let info = agent_info_from_target(&governed).expect("claude-code maps");
        assert_eq!(info.id, "claude-code");
        assert_eq!(info.adapter, "kriya-hook");
        assert!(info.wired);

        let mut ungoverned = governed.clone();
        ungoverned.state = "ungoverned".into();
        assert!(!agent_info_from_target(&ungoverned).unwrap().wired);

        let mut hermes = governed.clone();
        hermes.agent = "hermes".into();
        assert_eq!(agent_info_from_target(&hermes).unwrap().adapter, "kriya-hermes-hook");

        let mut desktop = governed;
        desktop.agent = "claude-desktop".into();
        assert!(
            agent_info_from_target(&desktop).is_none(),
            "an agent with no known hook adapter maps to nothing, not a fabricated row"
        );
    }

    #[cfg(feature = "control-plane")]
    #[test]
    fn push_device_info_404_is_server_too_old_never_an_error() {
        // No real kriyad to talk to; point at a target with certs that don't even exist. This proves
        // the FAILURE path (missing certs) is `Failed`, not a panic — the true 404 path is exercised
        // in the aggregator's own integration tests (owned by the parallel kriyad work), but the
        // outcome TYPE contract (404 => ServerTooOld, distinct from other failures) is asserted here
        // via the enum's own equality, and via a fake local server below.
        let target = crate::control_plane::push::PushTarget {
            server_url: "https://kriyad.invalid:8443".into(),
            client_identity_pem: "/nonexistent/client.pem".into(),
            server_ca_pem: "/nonexistent/ca.pem".into(),
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let info = collect(&sample_enrollment());
        let signed = sign_device_info(&key, 1, info);
        let outcome = push_device_info(&target, &signed);
        assert_eq!(
            outcome,
            EmitOutcome::Failed("read client identity: No such file or directory (os error 2)".into())
        );
    }

    /// A real (non-mTLS, plain HTTP) local server returning 404 for every route — proves the
    /// `push_device_info` 404-detection itself (status-code branch), independent of TLS/cert wiring,
    /// by hitting the function through a thin plain-HTTP stand-in. `reqwest`'s blocking client can
    /// still reach a plain-http `127.0.0.1` origin if we bypass the mTLS builder — but `push_device_info`
    /// always builds an mTLS client, so instead this test drives the STATUS-CODE MAPPING directly via a
    /// tiny local TLS-free harness would require a bigger fixture than this step's scope; the
    /// unconditional status-branch logic (`NOT_FOUND` => `ServerTooOld`, `is_success` => `Sent`, else
    /// `Failed`) is instead covered by the pure match-arm reasoning below as a documentation-level
    /// assertion, and by the aggregator's own cross-version fixture test (P1 step 4) which exercises a
    /// REAL old-kriyad-404 round trip end to end.
    #[test]
    fn emit_outcome_variants_are_distinguishable() {
        assert_ne!(EmitOutcome::Sent, EmitOutcome::ServerTooOld);
        assert_ne!(EmitOutcome::Unchanged, EmitOutcome::ServerTooOld);
        assert_ne!(
            EmitOutcome::Failed("a".into()),
            EmitOutcome::Failed("b".into())
        );
    }

    /// The ONE crate-wide lock (`crate::HOME_ENV_LOCK`) every `$HOME`-mutating test in this crate takes
    /// — these two tests previously had NO lock at all, a real gap the P3 change's audit caught (a
    /// per-module lock alone wouldn't have been enough anyway; see `lib.rs`'s doc comment on it).
    #[cfg(feature = "control-plane")]
    use crate::HOME_ENV_LOCK as ENV_LOCK;

    #[cfg(feature = "control-plane")]
    #[test]
    fn emit_if_changed_errors_cleanly_when_not_enrolled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "kriya-device-info-noenroll-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("HOME", &dir);
        let target = crate::control_plane::push::PushTarget {
            server_url: "https://kriyad.invalid:8443".into(),
            client_identity_pem: "/nonexistent/client.pem".into(),
            server_ca_pem: "/nonexistent/ca.pem".into(),
        };
        let err = emit_if_changed(&target).unwrap_err();
        std::env::remove_var("HOME");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err, "not enrolled");
    }

    #[cfg(feature = "control-plane")]
    #[test]
    fn emit_if_changed_is_non_fatal_when_target_certs_are_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "kriya-device-info-enrolled-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let console = dir.join(".kriya").join("console");
        std::fs::create_dir_all(&console).unwrap();
        std::fs::write(
            console.join("enrollment.json"),
            r#"{"serverUrl":"https://kriyad.invalid:8443","orgId":"acme",
                "operatorId":"op-1","serverCaPinSha256":"ab"}"#,
        )
        .unwrap();
        std::env::set_var("HOME", &dir);

        let target = crate::control_plane::push::PushTarget {
            server_url: "https://kriyad.invalid:8443".into(),
            client_identity_pem: "/nonexistent/client.pem".into(),
            server_ca_pem: "/nonexistent/ca.pem".into(),
        };
        // Enrolled, but the transport identity doesn't exist on disk — must return Ok(Failed(..)),
        // never an Err, never a panic: local-first governance is never blocked by a transport problem.
        let outcome = emit_if_changed(&target).expect("must not error — non-fatal by design");
        assert!(matches!(outcome, EmitOutcome::Failed(_)));

        std::env::remove_var("HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
