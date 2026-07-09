//! Fleet-wide, envelope-native evidence export (P5, doc 22 §9) — the "org-wide assessor-ready
//! evidence" the shipped per-device engine (`compliance.ts` / `paid.rs`) structurally CANNOT produce,
//! because it iterates raw receipts and kriyad only ever stores signed envelope ROLLUPS, never raw
//! receipts (doc 22 §11-B1: "org-wide evidence ≠ engine reuse — new envelope-native module"). This
//! module is wholly new: it never calls, imports, or modifies anything in `paid.rs`/`compliance.ts` —
//! their output stays byte-identical after this phase (proven by `tests/p5_manual_proof.rs`'s
//! regression check). It mirrors that engine's SHAPE (Markdown + JSON, the same footer, the same
//! honesty norms) without sharing its code, because the two operate over structurally different
//! inputs (raw per-device receipts vs. signed envelope aggregates pulled from kriyad) that cannot
//! honestly be unified into one function.
//!
//! doc 22 §9's four contents, honestly labeled:
//!  1. **Fleet coverage-completeness** (the headline — no per-device tool can produce it): per-device
//!     seq-continuity + chain integrity (locally re-verified over the raw envelope bytes) + kriyad's
//!     own liveness hint, silent devices named as admitted red cells. Strengthens 3.3.1 (retention) and
//!     3.3.4 (failure alerting) — doc 21 Part D's own GA-3 item already names exactly these two.
//!  2. **AU-family (3.3.x) fleet-wide** from envelope aggregates — 3.3.2 (individual accountability) is
//!     PERMANENTLY capped `partial`: operators are HMAC pseudonyms at the aggregator (the privacy
//!     design working, not a shortfall to fix).
//!  3. **CM-family (3.4.1 baseline / 3.4.2 enforced settings)** — NEW, unlocked by the P3/P4 downlink:
//!     the signed chain "bundle vN authored → verified-applied on X/Y devices → drift list", enriched
//!     with each device's own recent §7 inventory (which console/runtime version ran where).
//!  4. Doc-21 honesty norms, carried forward verbatim: 3.3.9 stays a permanent `✗ gap`; every export
//!     footer reads "evidence, not a certification."
//!
//! **Trust rule (matches P4's own, doc 22 §9's implicit extension of it):** every verdict here is
//! computed from LOCALLY RE-VERIFIED envelope data (`VerifiedEnvelope.verified`,
//! `kriya_verify::envelope_chain_break` over the raw bytes) — never from kriyad's own aggregate hints.
//! The one documented exception is [`DeviceInventory`] (§7 fields) — see its own doc comment for why.
//!
//! **Streaming (doc 22 §9's "Scale" paragraph):** [`stream_fleet_envelopes`] pulls device-by-device
//! through the existing P0 windowed client (`fleet_client::MAX_WINDOW`-capped `from_seq..to_seq`
//! chunks), keeping only envelopes whose own `window.to_ms` falls inside the report's time window and
//! discarding everything else as soon as each chunk is scanned — a single device's full lifetime
//! history (which could vastly exceed one report's window) is never pulled or held in memory at once.
//! [`fleet_evidence`] itself is a pure function over whatever bounded, already-windowed set the caller
//! assembled — kept separate from the network layer so it is fixture-testable with zero network I/O.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use super::fleet::VerifiedEnvelope;
use super::fleet_client::DeviceCoverage;

/// doc 21 Part D / doc 22 §9 item 4, verbatim — the SAME footer the per-device engine uses. Never
/// paraphrase this; it is the credibility line the whole export rests on.
pub const FOOTER: &str =
    "_Status: ✓ satisfied · ◐ partial · ✗ gap. This report is evidence, not a certification._";

/// Default report window — 90 days (doc 22 §9's "Scale" paragraph). Overridable per call.
pub const DEFAULT_WINDOW_MS: u64 = 90 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlStatus {
    Satisfied,
    Partial,
    Gap,
}

impl ControlStatus {
    fn icon(self) -> &'static str {
        match self {
            ControlStatus::Satisfied => "✓",
            ControlStatus::Partial => "◐",
            ControlStatus::Gap => "✗",
        }
    }
    fn word(self) -> &'static str {
        match self {
            ControlStatus::Satisfied => "satisfied",
            ControlStatus::Partial => "partial",
            ControlStatus::Gap => "gap",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgControl {
    pub framework: String,
    pub control: String,
    pub requirement: String,
    pub evidence: String,
    pub status: ControlStatus,
}

/// One device's §7 inventory enrichment for the CM-family drift narrative — "which console/runtime
/// version ran where, when" (doc 22 §9 item 3). **Not** a re-verification of a raw `SignedDeviceInfo`:
/// kriyad checks that signature once, at ingest (P1), and serves ONLY the flattened passthrough on
/// `DeviceCoverage` — there is no `GET` readback of the raw signed bytes for a second, independent
/// local check here (unlike `envelopes`, which this module DOES re-verify). Accepted on exactly the
/// same trust basis P2's cockpit inventory display already accepted these same fields on; deliberately
/// its own small type rather than `kriya_verify::DeviceInfo` so nothing here implies a re-verification
/// that cannot actually happen with today's kriyad wire surface.
#[derive(Debug, Clone)]
pub struct DeviceInventory {
    pub device_pub: String,
    pub console_version: Option<String>,
    pub runtime_version: Option<String>,
}

/// Project the §7 inventory fields straight off a fleet's coverage rows — see [`DeviceInventory`]'s
/// doc comment for why this is a projection, not a fresh re-verified fetch.
pub fn device_inventories_from_coverage(coverage: &[DeviceCoverage]) -> Vec<DeviceInventory> {
    coverage
        .iter()
        .map(|d| DeviceInventory {
            device_pub: d.device_pub.clone(),
            console_version: d.console_version.clone(),
            runtime_version: d.runtime_version.clone(),
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCompleteness {
    pub device_pub: String,
    pub device_label: Option<String>,
    /// kriyad's own liveness hint (`current` / `behind` / `silent`) — accepted as-is (see module doc);
    /// the stream-continuity/chain fields below are the LOCALLY re-verified proof layer.
    pub liveness: String,
    pub envelopes_in_window: u32,
    /// Human-readable seq-continuity gap citations, e.g. `"seq 12 -> 15 (2 missing)"`. Empty = no gaps.
    pub seq_gaps: Vec<String>,
    pub chain_intact: bool,
    /// 1-based index of the first chain break within this device's in-window envelopes, if any.
    pub chain_break_at: Option<usize>,
    /// From the LATEST in-window envelope's `policy_state` (locally re-verified) — `None` if no
    /// in-window envelope for this device carries one (never applied within the window, or pre-P3).
    pub applied_policy_version: Option<u64>,
    pub applied_bundle_hash: Option<String>,
    pub console_version: Option<String>,
    pub runtime_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgEvidence {
    pub generated_ms: u64,
    pub organization: String,
    pub window_from_ms: u64,
    pub window_to_ms: u64,
    pub devices_total: usize,
    pub devices_current: usize,
    pub devices_behind: usize,
    pub devices_silent: usize,
    pub device_completeness: Vec<DeviceCompleteness>,
    /// The highest version among the currently-published, in-scope-visible bundle(s) passed in —
    /// `None` when nothing has ever been published.
    pub latest_bundle_version: Option<u64>,
    /// Named exceptions: devices whose LOCALLY-verified applied version is behind `latest_bundle_version`.
    pub drift: Vec<String>,
    pub controls: Vec<OrgControl>,
    #[serde(skip)]
    pub markdown: String,
    #[serde(skip)]
    pub json: String,
}

/// Parse one raw signed-envelope JSON string into its `Value`, returning `None` for anything that
/// isn't valid JSON or isn't `verified` — an unverified/malformed envelope contributes NOTHING to the
/// evidence (matches the per-device engine's "only verified rows count", doc 21 Part D).
fn verified_value(e: &VerifiedEnvelope) -> Option<Value> {
    if !e.verified {
        return None;
    }
    serde_json::from_str::<Value>(&e.raw).ok()
}

fn short_pub(device_pub: &str) -> String {
    device_pub.chars().take(12).collect::<String>() + "…"
}

fn device_citation(device_pub: &str, label: Option<&str>) -> String {
    match label {
        Some(l) if !l.is_empty() => format!("{l} ({})", short_pub(device_pub)),
        _ => short_pub(device_pub),
    }
}

/// The envelope-native org-wide evidence engine (doc 22 §9). Pure — takes already-fetched, already
/// locally-verified data (see the module doc for the streaming layer that assembles it) and computes
/// the full [`OrgEvidence`] bundle, fixture-testable with zero network I/O.
pub fn fleet_evidence(
    envelopes: &[VerifiedEnvelope],
    coverage: &[DeviceCoverage],
    bundles: &[kriya_verify::PolicyBundle],
    device_infos: &[DeviceInventory],
    window: (u64, u64),
    organization: &str,
    generated_ms: u64,
) -> OrgEvidence {
    let (window_from_ms, window_to_ms) = window;

    // Envelope-level re-verification tally — this is DISTINCT from `total_receipts_failed` below (a
    // device-self-reported count of individual RECEIPTS inside an already-verified envelope). This one
    // counts envelopes whose OWN signature (or basic shape) failed THIS module's local re-verification
    // — the actual "tampering/corruption" signal 3.3.8's evidence text reports. Computed over the FULL
    // input slice, independent of the `verified_value()` gate below, so a tampered/forged envelope is
    // counted here even though (correctly) excluded from every other aggregate.
    let envelopes_received = envelopes.len();
    let envelopes_failed_reverification = envelopes.iter().filter(|e| !e.verified).count();

    // Group verified, parsed envelope values by device_pub, sorted by seq — the ONLY grouping key we
    // trust is the envelope's own `device_pub` (self-consistent with `public_key` per
    // `verify_envelope`), never a caller-supplied label.
    let mut by_device: std::collections::BTreeMap<String, Vec<(u64, Value)>> = Default::default();
    // Device-SELF-REPORTED receipt-level counts, rolled up from each (already re-verified) envelope's
    // own `counts` field — "how many receipts this device says it processed/verified/failed", NOT a
    // measure of THIS module's own envelope re-verification (see `envelopes_failed_reverification`).
    let mut total_receipts = 0u64;
    let mut total_receipts_verified = 0u64;
    let mut total_receipts_failed = 0u64;
    let mut distinct_signers: BTreeSet<String> = Default::default();
    let mut distinct_operators: BTreeSet<String> = Default::default();

    for e in envelopes {
        let Some(v) = verified_value(e) else { continue };
        let Some(env) = v.get("envelope") else { continue };
        let Some(device_pub) = env.get("device_pub").and_then(Value::as_str) else { continue };
        let seq = env.get("seq").and_then(Value::as_u64).unwrap_or(0);

        if let Some(counts) = env.get("counts") {
            total_receipts += counts.get("receipts").and_then(Value::as_u64).unwrap_or(0);
            total_receipts_verified += counts.get("verified").and_then(Value::as_u64).unwrap_or(0);
            total_receipts_failed += counts.get("failed").and_then(Value::as_u64).unwrap_or(0);
        }
        for signer in env.get("signers").and_then(Value::as_array).into_iter().flatten() {
            if let Some(fp) = signer.get("fingerprint").and_then(Value::as_str) {
                distinct_signers.insert(fp.to_string());
            }
        }
        for op in env.get("operators").and_then(Value::as_array).into_iter().flatten() {
            if let Some(r) = op.get("ref").and_then(Value::as_str) {
                distinct_operators.insert(r.to_string());
            }
        }

        by_device.entry(device_pub.to_string()).or_default().push((seq, v));
    }
    for envs in by_device.values_mut() {
        envs.sort_by_key(|(seq, _)| *seq);
    }

    // Fleet-wide latest published bundle (across whatever bundles the caller could see).
    let latest_bundle_version = bundles.iter().map(|b| b.version).max();

    let inventory_by_pub: std::collections::BTreeMap<&str, &DeviceInventory> =
        device_infos.iter().map(|d| (d.device_pub.as_str(), d)).collect();
    let coverage_by_pub: std::collections::BTreeMap<&str, &DeviceCoverage> =
        coverage.iter().map(|d| (d.device_pub.as_str(), d)).collect();

    let mut device_completeness = Vec::with_capacity(coverage.len());
    let mut drift: Vec<String> = Vec::new();
    let mut devices_with_gaps = 0usize;
    let mut devices_chain_broken = 0usize;
    let mut devices_never_applied = 0usize;
    let mut devices_current_on_latest = 0usize;

    for d in coverage {
        let empty = Vec::new();
        let envs = by_device.get(&d.device_pub).unwrap_or(&empty);

        let mut seq_gaps = Vec::new();
        for w in envs.windows(2) {
            let (a, _) = w[0];
            let (b, _) = w[1];
            if b > a + 1 {
                seq_gaps.push(format!("seq {a} -> {b} ({} missing)", b - a - 1));
            }
        }
        if !seq_gaps.is_empty() {
            devices_with_gaps += 1;
        }

        let values: Vec<Value> = envs.iter().map(|(_, v)| v.clone()).collect();
        let break_at = kriya_verify::envelope_chain_break(&values);
        let chain_intact = break_at.is_none();
        if !chain_intact {
            devices_chain_broken += 1;
        }

        let (applied_policy_version, applied_bundle_hash) = envs
            .last()
            .and_then(|(_, v)| v.get("envelope")?.get("policy_state"))
            .map(|ps| {
                (
                    ps.get("version").and_then(Value::as_u64),
                    ps.get("bundle_hash").and_then(Value::as_str).map(str::to_string),
                )
            })
            .unwrap_or((None, None));
        match (applied_policy_version, latest_bundle_version) {
            (Some(applied), Some(latest)) if applied < latest => {
                drift.push(format!(
                    "{}: applied v{applied} < latest v{latest}",
                    device_citation(&d.device_pub, d.device_label.as_deref())
                ));
            }
            (Some(_), _) => devices_current_on_latest += 1,
            (None, Some(_)) => {
                // A published baseline exists but this device has never applied ANY version within
                // the window — a more severe drift case than merely "behind", named distinctly.
                devices_never_applied += 1;
                drift.push(format!(
                    "{}: never applied (baseline is v{})",
                    device_citation(&d.device_pub, d.device_label.as_deref()),
                    latest_bundle_version.expect("Some checked above")
                ));
            }
            (None, None) => devices_never_applied += 1,
        }

        let inv = inventory_by_pub.get(d.device_pub.as_str());
        device_completeness.push(DeviceCompleteness {
            device_pub: d.device_pub.clone(),
            device_label: d.device_label.clone(),
            liveness: d.status.clone(),
            envelopes_in_window: envs.len() as u32,
            seq_gaps,
            chain_intact,
            chain_break_at: break_at,
            applied_policy_version,
            applied_bundle_hash,
            console_version: inv.and_then(|i| i.console_version.clone()),
            runtime_version: inv.and_then(|i| i.runtime_version.clone()),
        });
    }
    let _ = coverage_by_pub; // reserved for future cross-checks; silences an unused-binding lint for now

    let devices_total = coverage.len();
    let devices_current = coverage.iter().filter(|d| d.status == "current").count();
    let devices_behind = coverage.iter().filter(|d| d.status == "behind").count();
    let devices_silent = coverage.iter().filter(|d| d.status == "silent").count();

    let silent_citations: Vec<String> = coverage
        .iter()
        .filter(|d| d.status == "silent")
        .map(|d| device_citation(&d.device_pub, d.device_label.as_deref()))
        .collect();

    let controls = vec![
        // 1. Fleet coverage-completeness → strengthens 3.3.1 (doc 21 GA-3: "AU-2/AU-12 ... 3.3.1/3.3.4").
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.1 (AU.L2-3.3.1 · AU-2/3/12) — Audit record creation & retention".into(),
            requirement: "Create and retain system audit logs/records to enable monitoring, analysis, investigation, and reporting of unlawful or unauthorized activity.".into(),
            evidence: format!(
                "{total_receipts} device-reported receipt(s) retained across {devices_total} device(s) as hash-chained, signed envelope rollups ({total_receipts_verified} verified / {total_receipts_failed} failed at the device, per-envelope self-reported counts); {envelopes_failed_reverification} of {envelopes_received} envelope(s) fleet-wide failed THIS module's own local re-verification (tampering/corruption); {devices_chain_broken} device(s) with a broken chain, {devices_with_gaps} with a seq-continuity gap, {devices_silent} silent (unreachable). Fleet-wide coverage-completeness is itself attested per device from re-verified envelope bytes, not asserted."
            ),
            status: if devices_total == 0 {
                ControlStatus::Gap
            } else if devices_chain_broken == 0 && devices_with_gaps == 0 && devices_silent == 0 {
                ControlStatus::Satisfied
            } else {
                ControlStatus::Partial
            },
        },
        // 2. AU-family fleet-wide — 3.3.2 PERMANENTLY partial (doc 22 §9 item 2).
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.2 (AU.L2-3.3.2 · AU-3) — Individual accountability".into(),
            requirement: "Ensure the actions of individual system users can be uniquely traced to those users so they can be held accountable.".into(),
            evidence: format!(
                "{} distinct pseudonymous operator ref(s) across {devices_total} device(s) fleet-wide (HMAC-pseudonymized at the aggregator — individual identities never leave the originating device). Accountability is traceable to a stable per-window pseudonym, not a directly identifiable individual; this is the privacy design working, not a shortfall to fix.",
                distinct_operators.len()
            ),
            status: ControlStatus::Partial,
        },
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.3 (AU.L2-3.3.3 · AU-2) — Review & update logged events".into(),
            requirement: "Review and update logged events.".into(),
            evidence: format!(
                "{devices_total} device(s) contributing envelope rollups fleet-wide; the periodic review and update of which events to log remains an organizational process outside kriya."
            ),
            status: if devices_total == 0 { ControlStatus::Gap } else { ControlStatus::Partial },
        },
        // 4. Failure alerting → strengthens the coverage-completeness headline (doc 21 GA-3: 3.3.4).
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.4 (AU.L2-3.3.4 · AU-5) — Audit logging process failure alerting".into(),
            requirement: "Alert in the event of an audit logging process failure.".into(),
            evidence: if silent_citations.is_empty() {
                format!("No devices are currently silent out of {devices_total} fleet-wide; a stopped or silenced device would be visible by absence in the signed coverage chain, not a quiet nothing. No external paging/alerting integration exists.")
            } else {
                format!(
                    "{} device(s) currently silent out of {devices_total}, named: {}. A stopped or silenced device is visible by absence in the signed coverage chain — a gap in the heartbeat/envelope stream, not a quiet nothing. No external paging/alerting integration exists.",
                    silent_citations.len(),
                    silent_citations.join(", ")
                )
            },
            status: ControlStatus::Partial,
        },
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.5 (AU.L2-3.3.5 · AU-6(3)) — Correlate audit review & analysis".into(),
            requirement: "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of suspicious activity.".into(),
            evidence: format!(
                "Cross-device correlation via kriyad's aggregated envelope store across {devices_total} device(s); this is fleet-wide, single-organization correlation, not cross-organization SIEM aggregation."
            ),
            status: if devices_total == 0 { ControlStatus::Gap } else { ControlStatus::Partial },
        },
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.6 (AU.L2-3.3.6 · AU-7) — Audit record reduction & report generation".into(),
            requirement: "Provide audit record reduction and report generation to support on-demand analysis and reporting.".into(),
            evidence: "This Markdown + JSON org-wide evidence bundle is itself the fleet-wide reduction/report artifact, generated on-demand from every device's signed envelope stream and independently re-verifiable offline.".into(),
            status: ControlStatus::Satisfied,
        },
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.7 (AU.L2-3.3.7 · AU-8) — Clock synchronization for time stamps".into(),
            requirement: "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source for audit-record time stamps.".into(),
            evidence: "Every envelope carries a compiler-stamped window (from_ms/to_ms); clock synchronization against an authoritative source is OS-provided (NTP) on each device, outside kriya's control — this control is capped at partial regardless of fleet size.".into(),
            status: ControlStatus::Partial,
        },
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.8 (AU.L2-3.3.8 · AU-9) — Protect audit information & tools".into(),
            requirement: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.".into(),
            evidence: format!(
                "{envelopes_failed_reverification} envelope(s) failed local re-verification fleet-wide out of {envelopes_received} received (tampering/corruption detected) — the detection control is functioning as intended; investigate any flagged device(s). Access control over kriyad's own store/OS account is outside kriya's control, capping this at partial regardless of trail size."
            ),
            status: ControlStatus::Partial,
        },
        // 4. Permanent gap, carried forward verbatim (doc 21 Part D / doc 22 §9 item 4).
        OrgControl {
            framework: "NIST 800-171".into(),
            control: "3.3.9 (AU.L2-3.3.9 · AU-9(4)) — Limit audit-logging management to privileged users".into(),
            requirement: "Limit management of audit logging functionality to a subset of privileged users.".into(),
            evidence: "kriyad's aggregator runs under the operator's own OS account, and in-app roles are self-asserted (see docs/TRUST.md) — kriya enforces no privileged-user restriction on who can manage audit logging fleet-wide; this must be enforced by an OS-level or organizational access control (the same permanent gap the per-device engine reports, doc 21 Part D).".into(),
            status: ControlStatus::Gap,
        },
        // 3. CM-family — NEW, unlocked by the P3/P4 downlink.
        OrgControl {
            framework: "NIST 800-171 / CMMC L2".into(),
            control: "3.4.1 (CM.L2-3.4.1 · CM-2/3/8) — Baseline configuration".into(),
            requirement: "Establish and maintain baseline configurations and inventories of systems throughout the respective system development life cycles.".into(),
            evidence: match latest_bundle_version {
                Some(v) => format!(
                    "Policy bundle v{v}, authored and org-key-signed, is the fleet's current baseline; verified-applied on {devices_current_on_latest}/{devices_total} device(s) ({devices_never_applied} never applied any bundle within the window) — applied version taken from EACH DEVICE'S OWN locally re-verified envelope, never kriyad's serving hint."
                ),
                None => "No policy bundle has ever been published to this kriyad — there is no baseline to attest to yet.".into(),
            },
            status: match latest_bundle_version {
                None => ControlStatus::Gap,
                Some(_) if devices_total > 0 && devices_current_on_latest == devices_total => ControlStatus::Satisfied,
                Some(_) if devices_current_on_latest > 0 => ControlStatus::Partial,
                Some(_) => ControlStatus::Gap,
            },
        },
        OrgControl {
            framework: "NIST 800-171 / CMMC L2".into(),
            control: "3.4.2 (CM.L2-3.4.2 · CM-6) — Enforce security configuration settings".into(),
            requirement: "Establish and enforce security configuration settings for information technology products employed in organizational systems.".into(),
            evidence: if latest_bundle_version.is_none() {
                "No policy bundle has ever been published — there are no enforced settings to attest to yet.".into()
            } else if drift.is_empty() {
                format!("All {devices_total} device(s) are locally re-verified as current on the latest baseline — no drift exceptions.")
            } else {
                format!(
                    "{} device(s) behind the current baseline: {}. Enriched with §7 inventory where available (console/runtime versions on `device_completeness`).",
                    drift.len(),
                    drift.join("; ")
                )
            },
            status: match latest_bundle_version {
                None => ControlStatus::Gap,
                Some(_) if drift.is_empty() && devices_total > 0 => ControlStatus::Satisfied,
                Some(_) => ControlStatus::Partial,
            },
        },
    ];

    let mut out = OrgEvidence {
        generated_ms,
        organization: organization.to_string(),
        window_from_ms,
        window_to_ms,
        devices_total,
        devices_current,
        devices_behind,
        devices_silent,
        device_completeness,
        latest_bundle_version,
        drift,
        controls,
        markdown: String::new(),
        json: String::new(),
    };
    out.json = serde_json::to_string_pretty(&out).unwrap_or_default();
    out.markdown = render_markdown(&out);
    out
}

/// Minimal, dependency-free ms→ISO-8601 (UTC) formatter — this crate has no `chrono` dependency and
/// doesn't need one just for a report timestamp. Same civil-calendar math as `paid.rs`/`compliance.ts`
/// (proleptic Gregorian, epoch 1970-01-01).
fn iso(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);

    // Civil-from-days (Howard Hinnant's algorithm) — proleptic Gregorian, epoch-agnostic.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };

    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

fn render_markdown(e: &OrgEvidence) -> String {
    let mut l: Vec<String> = Vec::new();
    l.push(format!("# Fleet compliance evidence — {}", e.organization));
    l.push(String::new());
    l.push(format!(
        "_Generated {} by kriya Console (kriyad aggregator: {} device(s)). Evidence derived from cryptographically signed envelope rollups, verified locally — never raw receipts (kriyad never stores them)._",
        iso(e.generated_ms),
        e.devices_total
    ));
    l.push(String::new());
    l.push(format!("**Window:** {} → {}", iso(e.window_from_ms), iso(e.window_to_ms)));
    l.push(String::new());

    l.push("## Fleet coverage-completeness".to_string());
    l.push(String::new());
    l.push(format!(
        "- Devices: **{}** — current **{}** · behind **{}** · silent **{}**",
        e.devices_total, e.devices_current, e.devices_behind, e.devices_silent
    ));
    l.push(String::new());
    l.push("| Device | Liveness | Envelopes | Seq gaps | Chain | Applied |".to_string());
    l.push("| --- | --- | ---: | --- | --- | --- |".to_string());
    for d in &e.device_completeness {
        let label = device_citation(&d.device_pub, d.device_label.as_deref());
        let gaps = if d.seq_gaps.is_empty() { "none".to_string() } else { d.seq_gaps.join("; ") };
        let chain = if d.chain_intact {
            "intact".to_string()
        } else {
            format!("BROKEN (at {})", d.chain_break_at.unwrap_or(0))
        };
        let applied = match &d.applied_policy_version {
            Some(v) => format!("v{v}"),
            None => "never applied".to_string(),
        };
        l.push(format!(
            "| {label} | {} | {} | {gaps} | {chain} | {applied} |",
            d.liveness, d.envelopes_in_window
        ));
    }
    l.push(String::new());

    l.push("## Configuration management (CM-family)".to_string());
    l.push(String::new());
    match e.latest_bundle_version {
        Some(v) => l.push(format!("- Current baseline: **bundle v{v}**")),
        None => l.push("- No policy bundle has ever been published.".to_string()),
    }
    if e.drift.is_empty() {
        l.push("- Drift exceptions: **none**".to_string());
    } else {
        l.push(format!("- Drift exceptions ({}): {}", e.drift.len(), e.drift.join("; ")));
    }
    l.push(String::new());

    l.push("## Control mapping".to_string());
    l.push(String::new());
    l.push("| Framework | Control | Status | Evidence |".to_string());
    l.push("| --- | --- | --- | --- |".to_string());
    for c in &e.controls {
        l.push(format!(
            "| {} | {} | {} {} | {} |",
            c.framework,
            c.control,
            c.status.icon(),
            c.status.word(),
            c.evidence
        ));
    }
    l.push(String::new());
    l.push(FOOTER.to_string());

    l.join("\n") + "\n"
}

/// Fetch + fold the whole fleet's envelopes within `[now_ms - window_ms, now_ms]`, device by device,
/// streaming in `fleet_client::MAX_WINDOW`-sized seq chunks so a single device's full lifetime history
/// is never pulled or held in memory at once — see the module doc's "Streaming" paragraph.
#[cfg(feature = "control-plane")]
pub fn stream_fleet_envelopes(
    cfg: &super::fleet_client::FleetConfig,
    coverage: &[DeviceCoverage],
    now_ms: u64,
    window_ms: u64,
) -> Vec<VerifiedEnvelope> {
    let cutoff_ms = now_ms.saturating_sub(window_ms);
    let mut kept = Vec::new();

    for d in coverage {
        if d.last_seq < 0 {
            continue;
        }
        let mut to_seq = d.last_seq as u64;
        loop {
            let from_seq = to_seq.saturating_sub(super::fleet_client::MAX_WINDOW.saturating_sub(1));
            let resp = match super::fleet_client::fetch_device_envelopes(cfg, &d.device_pub, from_seq, to_seq) {
                Ok(r) => r,
                Err(_) => break, // non-fatal — this device simply contributes less to this report
            };
            let mut chunk_has_in_window = false;
            for raw in resp.parsed.envelopes {
                // A malformed line can't be windowed (there is no `window.to_ms` to read) — kept
                // unconditionally rather than silently dropped: a corrupted/unparseable envelope IS
                // itself a tamper/corruption signal (3.3.8's evidence), and hiding it here would create
                // exactly the blind spot the "never materialize the full corpus" streaming design must
                // not introduce into the evidence's own honesty.
                let Ok(v) = serde_json::from_str::<Value>(&raw) else {
                    chunk_has_in_window = true;
                    kept.push(VerifiedEnvelope {
                        raw,
                        verified: false,
                        error: Some("not valid JSON".to_string()),
                    });
                    continue;
                };
                let to_ms = v
                    .get("envelope")
                    .and_then(|e| e.get("window"))
                    .and_then(|w| w.get("to_ms"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if to_ms < cutoff_ms {
                    continue; // outside the report window — dropped immediately, never retained
                }
                chunk_has_in_window = true;
                let (verified, error) = match kriya_verify::verify_envelope(&v) {
                    Ok(()) => (true, None),
                    Err(e) => (false, Some(e)),
                };
                kept.push(VerifiedEnvelope { raw, verified, error });
            }
            if from_seq == 0 || !chunk_has_in_window {
                break;
            }
            to_seq = from_seq - 1;
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Build + sign a minimal, schema-valid envelope for device `key`, with `seq`/`prev_hash` and an
    /// optional `policy_state`. Mirrors `kriya_verify::envelope::tests::sign_envelope`'s shape closely
    /// enough to pass `verify_envelope` for real (not a stub).
    fn envelope(
        key: &SigningKey,
        seq: u64,
        prev_hash: Option<String>,
        from_ms: u64,
        to_ms: u64,
        policy_state: Option<(u64, &str)>,
    ) -> VerifiedEnvelope {
        let device_pub = hex::encode(key.verifying_key().to_bytes());
        let mut env = json!({
            "schema": "kriya.envelope.v1",
            "device_pub": device_pub,
            "org_id": "acme",
            "operators": [{"ref": format!("op-{}", &device_pub[..4]), "actions": 1}],
            "seq": seq,
            "window": {"from_ms": from_ms, "to_ms": to_ms},
            "signers": [{"fingerprint": "fp1", "receipts": 1, "verified": 1}],
            "actions": [],
            "counts": {"receipts": 1, "verified": 1, "failed": 0, "destructive": 0, "attestations": 0},
            "integrity": {"merkle_root": "0".repeat(64), "chain_intact": true, "broken_sources": []},
            "non_egress": {"attested": false, "attestation_count": 0},
            "compiler": {"version": "0.1.0", "produced_ms": to_ms},
        });
        if let Some(p) = &prev_hash {
            env["prev_envelope_hash"] = json!(p);
        }
        if let Some((version, hash)) = policy_state {
            env["policy_state"] = json!({"version": version, "bundle_hash": hash, "applied_ms": to_ms});
        }
        let bytes = kriya_verify::canonical_json_bytes(&env);
        let sig = hex::encode(key.sign(&bytes).to_bytes());
        let raw = serde_json::to_string(&json!({
            "envelope": env,
            "public_key": device_pub,
            "signature": sig,
        }))
        .unwrap();
        VerifiedEnvelope { raw, verified: true, error: None }
    }

    fn coverage_row(device_pub: &str, label: &str, status: &str, last_seq: i64) -> DeviceCoverage {
        DeviceCoverage {
            device_pub: device_pub.to_string(),
            org_id: Some("acme".into()),
            business_unit: None,
            last_seq,
            max_seq_seen: last_seq,
            last_seen_ms: 1_000,
            status: status.to_string(),
            console_version: Some("0.2.0".into()),
            runtime_version: Some("0.4.0".into()),
            verify_crate_version: None,
            os_platform: None,
            os_version: None,
            os_arch: None,
            policy_applied_version: None,
            policy_bundle_hash: None,
            outbox_pending: None,
            enrolled_ms: None,
            device_label: Some(label.to_string()),
            agents: None,
            info_collected_ms: None,
            applied_policy_version: None,
            applied_bundle_hash: None,
            latest_bundle_version: None,
        }
    }

    fn bundle(version: u64) -> kriya_verify::PolicyBundle {
        kriya_verify::PolicyBundle {
            org_id: "acme".into(),
            version,
            issued_ms: 1,
            expires_ms: None,
            scope: kriya_verify::PolicyScope::all(),
            policy: json!({}),
            budgets: json!({}),
            govern: vec![],
            envelope_verbosity: "standard".into(),
        }
    }

    /// 3-synthetic-device fixture (task acceptance): device A fully in sync, device B drifted (behind
    /// the latest bundle), device C silent with a seq gap. Asserts the exact statuses/labels a real
    /// assessor-facing report must show.
    fn three_device_fixture() -> (Vec<VerifiedEnvelope>, Vec<DeviceCoverage>, Vec<kriya_verify::PolicyBundle>) {
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let a_pub = hex::encode(a.verifying_key().to_bytes());
        let b_pub = hex::encode(b.verifying_key().to_bytes());
        let c_pub = hex::encode(c.verifying_key().to_bytes());

        let e1 = envelope(&a, 1, None, 0, 1000, Some((2, "hash-v2")));
        // `envelope_chain_break` hashes the WHOLE signed line (`{envelope, public_key, signature}`),
        // not just the inner `envelope` object — match that exactly, or the very first link fails.
        let e1_value: Value = serde_json::from_str(&e1.raw).unwrap();
        let e1_hash = kriya_verify::sha256_hex(&kriya_verify::canonical_json_bytes(&e1_value));
        let e2 = envelope(&a, 2, Some(e1_hash), 1000, 2000, Some((2, "hash-v2")));

        let b1 = envelope(&b, 1, None, 0, 1000, Some((1, "hash-v1")));
        // b2 deliberately SKIPPED (seq 2 missing) -> a seq gap, then b3 continues at seq 3.
        let b3 = envelope(&b, 3, None, 2000, 3000, Some((1, "hash-v1")));

        let c1 = envelope(&c, 1, None, 0, 1000, None);

        let envelopes = vec![e1, e2, b1, b3, c1];
        let coverage = vec![
            coverage_row(&a_pub, "laptop-a", "current", 2),
            coverage_row(&b_pub, "laptop-b", "current", 3),
            coverage_row(&c_pub, "server-c", "silent", 1),
        ];
        let bundles = vec![bundle(1), bundle(2)];
        (envelopes, coverage, bundles)
    }

    #[test]
    fn three_device_fixture_produces_the_expected_statuses() {
        let (envelopes, coverage, bundles) = three_device_fixture();
        let device_infos = device_inventories_from_coverage(&coverage);
        let out = fleet_evidence(&envelopes, &coverage, &bundles, &device_infos, (0, 3000), "Acme Corp", 5000);

        assert_eq!(out.devices_total, 3);
        assert_eq!(out.devices_current, 2);
        assert_eq!(out.devices_silent, 1);
        assert_eq!(out.latest_bundle_version, Some(2));

        let a = &out.device_completeness[0];
        assert_eq!(a.liveness, "current");
        assert!(a.seq_gaps.is_empty(), "device A has a dense seq stream");
        assert!(a.chain_intact);
        assert_eq!(a.applied_policy_version, Some(2), "device A is on the latest bundle");

        let b = &out.device_completeness[1];
        assert_eq!(b.seq_gaps, vec!["seq 1 -> 3 (1 missing)".to_string()]);
        assert_eq!(b.applied_policy_version, Some(1), "device B is drifted — still on v1");

        let c = &out.device_completeness[2];
        assert_eq!(c.liveness, "silent");
        assert_eq!(c.applied_policy_version, None, "device C never applied any bundle");

        // Device B (behind) and device C (never applied) are both named drift exceptions; device A
        // (in sync) is not.
        assert_eq!(out.drift.len(), 2, "device B (behind) and device C (never applied) are both drift");
        assert!(out.drift.iter().any(|d| d.contains("laptop-b") && d.contains("v1") && d.contains("v2")));
        assert!(out.drift.iter().any(|d| d.contains("server-c") && d.contains("never applied")));

        // 3.3.9 stays a permanent gap (doc 21 honesty norm, carried forward verbatim).
        let c39 = out.controls.iter().find(|c| c.control.starts_with("3.3.9")).unwrap();
        assert_eq!(c39.status, ControlStatus::Gap);

        // 3.3.2 (individual accountability) is PERMANENTLY partial, never satisfied (doc 22 §9 item 2).
        let c32 = out.controls.iter().find(|c| c.control.starts_with("3.3.2")).unwrap();
        assert_eq!(c32.status, ControlStatus::Partial);

        // 3.4.2 (enforce security configuration settings) must be partial, not satisfied, given a real
        // drift exception exists.
        let c342 = out.controls.iter().find(|c| c.control.starts_with("3.4.2")).unwrap();
        assert_eq!(c342.status, ControlStatus::Partial);
        assert!(c342.evidence.contains("laptop-b"));

        assert!(out.markdown.ends_with(&format!("{FOOTER}\n")), "the footer must be reproduced verbatim");
        assert!(out.markdown.contains("evidence, not a certification"));
        assert!(out.json.contains("\"devicesTotal\": 3"));
    }

    #[test]
    fn no_devices_and_no_bundles_render_honest_gaps_not_a_crash() {
        let out = fleet_evidence(&[], &[], &[], &[], (0, 1000), "Empty Org", 1000);
        assert_eq!(out.devices_total, 0);
        assert_eq!(out.latest_bundle_version, None);
        let c1 = out.controls.iter().find(|c| c.control.starts_with("3.3.1")).unwrap();
        assert_eq!(c1.status, ControlStatus::Gap);
        let c341 = out.controls.iter().find(|c| c.control.starts_with("3.4.1")).unwrap();
        assert_eq!(c341.status, ControlStatus::Gap);
    }

    #[test]
    fn unverified_envelopes_never_contribute_to_evidence() {
        let a = key(9);
        let mut forged = envelope(&a, 1, None, 0, 1000, None);
        forged.verified = false; // simulates a tampered/forged envelope kriyad or a MITM returned
        let a_pub = hex::encode(a.verifying_key().to_bytes());
        let coverage = vec![coverage_row(&a_pub, "tampered-device", "current", 1)];
        let out = fleet_evidence(&[forged], &coverage, &[], &[], (0, 1000), "Org", 1000);
        assert_eq!(out.device_completeness[0].envelopes_in_window, 0, "an unverified envelope must not count");

        // The tamper IS surfaced, though — as its own honestly-labeled 3.3.8 count, never conflated
        // with the (necessarily zero, since nothing contributed) receipt-level counts on 3.3.1.
        let c338 = out.controls.iter().find(|c| c.control.starts_with("3.3.8")).unwrap();
        assert!(c338.evidence.contains("1 envelope(s) failed local re-verification fleet-wide out of 1"));
    }

    /// The 3.3.8 "envelopes failed re-verification" count must be a genuine tally of envelopes whose
    /// OWN signature failed local re-verification — NOT the device-self-reported receipt-level
    /// `counts.failed` rolled up from an ALREADY-verified envelope's body (a real bug an adversarial
    /// review caught: those are two different things, and conflating them makes a compliance-evidence
    /// claim the code cannot actually back).
    #[test]
    fn envelope_reverification_failures_are_distinct_from_receipt_level_failures() {
        let a = key(11);
        // A genuinely verified envelope whose OWN device-reported `counts.failed` is nonzero (some of
        // ITS receipts failed at the device) — this must NOT be counted as an envelope re-verification
        // failure; it is receipt-level noise inside an envelope that itself verifies just fine.
        let mut good = envelope(&a, 1, None, 0, 1000, None);
        let raw_value: Value = serde_json::from_str(&good.raw).unwrap();
        let mut env = raw_value["envelope"].clone();
        env["counts"]["failed"] = json!(3);
        env["counts"]["receipts"] = json!(4);
        let bytes = kriya_verify::canonical_json_bytes(&env);
        let sig = hex::encode(a.sign(&bytes).to_bytes());
        good.raw = serde_json::to_string(&json!({
            "envelope": env,
            "public_key": hex::encode(a.verifying_key().to_bytes()),
            "signature": sig,
        }))
        .unwrap();

        let b = key(12);
        let mut tampered = envelope(&b, 1, None, 0, 1000, None);
        tampered.verified = false; // an envelope that failed THIS module's own re-verification

        let a_pub = hex::encode(a.verifying_key().to_bytes());
        let b_pub = hex::encode(b.verifying_key().to_bytes());
        let coverage = vec![
            coverage_row(&a_pub, "device-a", "current", 1),
            coverage_row(&b_pub, "device-b", "current", 1),
        ];
        let out = fleet_evidence(&[good, tampered], &coverage, &[], &[], (0, 1000), "Org", 1000);

        let c331 = out.controls.iter().find(|c| c.control.starts_with("3.3.1")).unwrap();
        assert!(
            c331.evidence.contains("3 failed at the device"),
            "receipt-level failures still surface, correctly labeled: {}",
            c331.evidence
        );
        let c338 = out.controls.iter().find(|c| c.control.starts_with("3.3.8")).unwrap();
        assert!(
            c338.evidence.contains("1 envelope(s) failed local re-verification fleet-wide out of 2"),
            "exactly ONE envelope (the tampered one) failed re-verification, not the receipt-level 3: {}",
            c338.evidence
        );
    }

    #[test]
    fn footer_is_reproduced_character_for_character() {
        assert_eq!(
            FOOTER,
            "_Status: ✓ satisfied · ◐ partial · ✗ gap. This report is evidence, not a certification._"
        );
    }

    /// Emits the committed Rust↔TS parity fixture (`src/sample/sample-org-evidence.json`) for the TS
    /// `OrgEvidence` type — the SAME 3-device fixture `three_device_fixture_produces_the_expected_statuses`
    /// asserts against, so the TS parity test and this Rust test are provably describing the same data.
    /// Deterministic (fixed key seeds, fixed `generated_ms`/window). Regenerate with:
    ///   cargo test -p kriya-console --features control-plane print_sample_org_evidence -- --ignored --nocapture
    #[test]
    #[ignore = "fixture generator; run with --ignored --nocapture to (re)generate the parity fixture"]
    fn print_sample_org_evidence() {
        let (envelopes, coverage, bundles) = three_device_fixture();
        let device_infos = device_inventories_from_coverage(&coverage);
        let out = fleet_evidence(&envelopes, &coverage, &bundles, &device_infos, (0, 3000), "Sample contractor — illustrative data", 5000);
        println!("{}", out.json);
    }
}
