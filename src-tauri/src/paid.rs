//! The **paid** compute, in compiled Rust, license-gated (D-018). These are the features an
//! organization pays for and the reason the value can't be lifted out of a shipped `.app`: the
//! cross-machine **fleet correlation** and the **compliance-evidence bundle** are generated here, not
//! in shippable JS, and every entry point first calls [`license::require_pro`]. They read the same
//! on-device audit trail the free monitor shows, re-verify it in Rust, and turn it into evidence.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::audit::default_audit_dir;
use crate::license;
use crate::receipts::{chain_break, verify_value};
use kriya_verify::is_destructive;

const ATTESTATION_ON_DEVICE: &str = "kriya.attestation.on_device";
/// The signed coverage-completeness snapshot action id (`~/.kriya/audit/coverage.jsonl`). These are
/// meta-evidence (what was/wasn't governed), not agent actions — separated out and cited as AU-2/
/// AU-12 completeness evidence rather than counted in the action totals (GA-3).
const COVERAGE_SNAPSHOT: &str = "kriya.coverage.snapshot";
/// The reserved `kriya.io.*` namespace prefix (EG-2 / doc 24 §4.2) — governance metadata, like
/// `ATTESTATION_ON_DEVICE`, excluded from the action-type counts and the sole gate on whether the
/// egress control rows appear. MUST match `src/lib/compliance.ts`'s `KRIYA_IO_PREFIX` exactly.
const KRIYA_IO_PREFIX: &str = "kriya.io.";

/// The doc 24 §3.1 scope block, verbatim — embedded in every egress-bearing compliance export.
/// MUST match `src/lib/compliance.ts`'s `EGRESS_SCOPE_BLOCK` exactly (parity is asserted by a test).
pub const EGRESS_SCOPE_BLOCK: &str = "Scope: this artifact covers only agent traffic proxied through the kriya gateway (MCP-over-HTTP connectors, gateway-proxied tool calls) and the hook-observed tool lane. Agent processes can generate network traffic outside these lanes — spawned subprocesses, and the outbound connections of stdio MCP servers — which kriya does not observe, control, or record. Enforcement rides a cooperative hook that can be disabled at the host (see TRUST.md). This artifact is supporting evidence toward the identified assessment objectives for the agent-connector lane only; it does not by itself render any control MET, and coverage of non-governed agent egress must be documented in the organization's SSP under its own boundary and flow controls.";

/// Egress/ingress ledger facts computed from VERIFIED `kriya.io.*` receipts only (EG-2/EG-3) — the
/// sole gate on whether the doc 24 §3 egress control rows appear at all. Mirrors the TS
/// `EgressEvidence` shape exactly.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EgressEvidence {
    pub verified_receipts: usize,
    pub allow: usize,
    pub deny: usize,
    pub approve: usize,
}

/// Build the egress evidence summary from the full `rows` slice — `None` when no VERIFIED
/// `kriya.io.*` receipt exists in the trail.
fn egress_evidence(rows: &[Collected]) -> Option<EgressEvidence> {
    let io: Vec<&Collected> = rows
        .iter()
        .filter(|r| r.verified && r.action_id.starts_with(KRIYA_IO_PREFIX))
        .collect();
    if io.is_empty() {
        return None;
    }
    Some(EgressEvidence {
        verified_receipts: io.len(),
        allow: io.iter().filter(|r| r.action_id.ends_with(".allow")).count(),
        deny: io.iter().filter(|r| r.action_id.ends_with(".deny")).count(),
        approve: io.iter().filter(|r| r.action_id.ends_with(".approve")).count(),
    })
}

/// The governed-surface posture statement (doc 24 §7.2 row 4) — mirrors TS's `EgressPostureState`
/// exactly (parity is asserted by a test). Deliberately WEAKER than the document's pinned target
/// text, which assumes a signed toggle/policy-version receipt bounding the window (not yet built).
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EgressPostureState {
    NotMonitored,
    ZeroObserved,
    EgressPresent,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EgressPosture {
    pub state: EgressPostureState,
    pub governed_lane_receipts: usize,
    pub egress_receipts: usize,
}

/// Governed-lane receipts EXCLUDING the attestation marker and the whole `kriya.io.*` ledger — the
/// same population `distinct_actions` counts, summed instead of deduped. Egress-direction receipts
/// only (never ingress) for `egress_receipts` — mirrors TS's `EgressPosture` computation exactly.
fn egress_posture(rows: &[Collected]) -> EgressPosture {
    let governed_lane_receipts = rows
        .iter()
        .filter(|r| r.verified && !r.is_attestation && !r.action_id.starts_with(KRIYA_IO_PREFIX))
        .count();
    let egress_receipts = rows
        .iter()
        .filter(|r| r.verified && r.action_id.starts_with("kriya.io.egress."))
        .count();
    let state = if governed_lane_receipts == 0 && egress_receipts == 0 {
        EgressPostureState::NotMonitored
    } else if egress_receipts == 0 {
        EgressPostureState::ZeroObserved
    } else {
        EgressPostureState::EgressPresent
    };
    EgressPosture { state, governed_lane_receipts, egress_receipts }
}

/// Render the governed-surface posture statement — MUST match TS's `renderEgressPosture` wording
/// exactly (parity is asserted by a test). Never "nothing left at all"; never "zero egress" without
/// governed-lane activity to back it (§6-H1/H10).
fn render_egress_posture(p: &EgressPosture) -> String {
    match p.state {
        EgressPostureState::NotMonitored => "Governed-lane egress: NOT MONITORED in this window — zero governed-lane receipts of any kind were observed, so no statement about egress can be made either way. This is absent-by-configuration, not a zero-egress finding.".to_string(),
        EgressPostureState::ZeroObserved => format!(
            "Governed-lane egress: zero kriya.io.egress.* receipts observed in this window, alongside {} other governed-lane receipt(s) — the governed surface was active and produced no egress. This does NOT prove the egress ledger was continuously enabled for the full window (no signed toggle/policy-version receipt bounds it yet — see docs/TRUST.md). The raw-egress lane (host-level observation) is a separate, GREY-by-default surface — see the Coverage Map. Any physical air gap or network isolation is the organization's own attested posture, not verified by kriya.",
            p.governed_lane_receipts
        ),
        EgressPostureState::EgressPresent => format!(
            "Governed-lane egress: NOT zero — {} kriya.io.egress.* receipt(s) observed and verified in this window.",
            p.egress_receipts
        ),
    }
}

/// One receipt collected + re-verified from the on-device trail, flattened to what the paid
/// reports need.
struct Collected {
    source: String,
    action_id: String,
    success: bool,
    ts_ms: u64,
    actor_agent: Option<String>,
    actor_user: Option<String>,
    public_key: String,
    verified: bool,
    is_attestation: bool,
}

/// Read + verify every receipt across the standard audit dir. Per-file chain integrity is returned
/// alongside (a break = a deleted/reordered/truncated log, a first-class tamper signal).
fn collect() -> (Vec<Collected>, BTreeMap<String, Option<usize>>) {
    let dir = default_audit_dir();
    let mut out = Vec::new();
    let mut chains: BTreeMap<String, Option<usize>> = BTreeMap::new();
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("jsonl"))
                .collect()
        })
        .unwrap_or_default();
    paths.sort();
    for path in paths {
        let source = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        chains.insert(source.clone(), chain_break(&text));
        for line in text.split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let action_id = v
                .get("action_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            out.push(Collected {
                source: source.clone(),
                is_attestation: action_id == ATTESTATION_ON_DEVICE,
                action_id,
                success: v.get("success").and_then(|x| x.as_bool()).unwrap_or(false),
                ts_ms: v.get("ts_ms").and_then(|x| x.as_u64()).unwrap_or(0),
                actor_agent: v
                    .get("actor")
                    .and_then(|a| a.get("agent"))
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                actor_user: v
                    .get("actor")
                    .and_then(|a| a.get("user"))
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                public_key: v
                    .get("public_key")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                verified: verify_value(&v).is_ok(),
            });
        }
    }
    (out, chains)
}

// ── Fleet correlation ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerGroup {
    /// Short, human-readable signer fingerprint (first 16 hex of the public key) — one signer ≈ one
    /// host/identity, the unit of cross-machine correlation.
    pub fingerprint: String,
    pub receipts: usize,
    pub verified: usize,
    pub failed: usize,
    pub apps: Vec<String>,
    pub agents: Vec<String>,
    pub operators: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRollup {
    pub app: String,
    pub receipts: usize,
    pub verified: usize,
    pub destructive: usize,
    pub chain_break_line: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetReport {
    pub total_receipts: usize,
    pub verified: usize,
    pub failed: usize,
    /// Receipts whose signature verified but whose action `success` was false — a governed action
    /// that ran and failed (distinct from a forged/tampered receipt).
    pub failed_actions: usize,
    pub distinct_signers: usize,
    pub distinct_apps: usize,
    pub distinct_agents: usize,
    pub on_device_attestations: usize,
    /// Earliest / latest receipt timestamp (ms since epoch) across the whole trail; 0 when empty.
    pub first_ms: u64,
    pub last_ms: u64,
    /// Files whose hash-chain is broken (deleted/reordered) — the headline integrity signal.
    pub tamper_signals: Vec<String>,
    pub signers: Vec<SignerGroup>,
    pub apps: Vec<AppRollup>,
}

/// Cross-machine / cross-app correlation of the signed trail — a paid feature: group every receipt by
/// signer (≈ host) and by app, surface distinct agents/operators, and flag any file whose hash-chain
/// is broken. The kind of fleet rollup a single-machine viewer can't give you.
#[tauri::command]
pub fn fleet_correlation() -> Result<FleetReport, String> {
    license::require_pro()?;
    let (rows, chains) = collect();

    let mut by_signer: BTreeMap<String, Vec<&Collected>> = BTreeMap::new();
    let mut by_app: BTreeMap<String, Vec<&Collected>> = BTreeMap::new();
    let mut agents: BTreeSet<String> = BTreeSet::new();
    for r in &rows {
        by_signer.entry(r.public_key.clone()).or_default().push(r);
        by_app.entry(r.source.clone()).or_default().push(r);
        if let Some(a) = &r.actor_agent {
            agents.insert(a.clone());
        }
    }

    let signers = by_signer
        .iter()
        .map(|(key, rs)| {
            let mut apps: BTreeSet<String> = BTreeSet::new();
            let mut ags: BTreeSet<String> = BTreeSet::new();
            let mut ops: BTreeSet<String> = BTreeSet::new();
            let mut verified = 0;
            for r in rs {
                apps.insert(r.source.clone());
                if let Some(a) = &r.actor_agent {
                    ags.insert(a.clone());
                }
                if let Some(u) = &r.actor_user {
                    ops.insert(u.clone());
                }
                if r.verified {
                    verified += 1;
                }
            }
            SignerGroup {
                fingerprint: key.chars().take(16).collect::<String>(),
                receipts: rs.len(),
                verified,
                failed: rs.len() - verified,
                apps: apps.into_iter().collect(),
                agents: ags.into_iter().collect(),
                operators: ops.into_iter().collect(),
            }
        })
        .collect();

    let apps = by_app
        .iter()
        .map(|(app, rs)| AppRollup {
            app: app.clone(),
            receipts: rs.len(),
            verified: rs.iter().filter(|r| r.verified).count(),
            destructive: rs.iter().filter(|r| is_destructive(&r.action_id)).count(),
            chain_break_line: chains.get(app).copied().flatten(),
        })
        .collect();

    let verified = rows.iter().filter(|r| r.verified).count();
    let failed_actions = rows.iter().filter(|r| r.verified && !r.success).count();
    let stamps: Vec<u64> = rows.iter().map(|r| r.ts_ms).filter(|&t| t > 0).collect();
    let tamper_signals = chains
        .iter()
        .filter_map(|(f, b)| b.map(|line| format!("{f}: chain breaks at line {line}")))
        .collect();

    Ok(FleetReport {
        total_receipts: rows.len(),
        verified,
        failed: rows.len() - verified,
        failed_actions,
        distinct_signers: by_signer.len(),
        distinct_apps: by_app.len(),
        distinct_agents: agents.len(),
        on_device_attestations: rows.iter().filter(|r| r.is_attestation).count(),
        first_ms: stamps.iter().copied().min().unwrap_or(0),
        last_ms: stamps.iter().copied().max().unwrap_or(0),
        tamper_signals,
        signers,
        apps,
    })
}

// ── Compliance evidence bundle ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Control {
    pub id: String,
    pub name: String,
    /// `satisfied` | `partial` | `gap` — derived from the evidence actually present in the trail.
    pub status: String,
    pub evidence: String,
}

/// Summary of the signed coverage-completeness chain (`coverage.jsonl`), cited as AU-2/AU-12
/// completeness evidence for NIST 3.3.1 / 3.3.4 (GA-3). Mirrors the TS `CoverageEvidence`.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoverageEvidence {
    pub snapshots: usize,
    pub chain_ok: bool,
}

/// Build the coverage summary from the separated coverage-snapshot rows + that chain's break status.
/// `None` when there are no coverage snapshots (evidence text is then unchanged).
fn coverage_evidence(coverage_rows: &[Collected], chain_break: Option<usize>) -> Option<CoverageEvidence> {
    if coverage_rows.is_empty() {
        return None;
    }
    let chain_ok = chain_break.is_none() && coverage_rows.iter().all(|r| r.verified);
    Some(CoverageEvidence {
        snapshots: coverage_rows.len(),
        chain_ok,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceBundle {
    pub framework: String,
    pub generated_ms: u64,
    pub total_receipts: usize,
    pub verified: usize,
    pub failed: usize,
    pub distinct_apps: usize,
    pub distinct_agents: usize,
    pub distinct_operators: usize,
    pub on_device_attestations: usize,
    pub destructive_actions: usize,
    pub integrity_ok: bool,
    pub controls: Vec<Control>,
    /// Egress/ingress ledger facts (EG-2/EG-3), `None` when the trail carries no verified
    /// `kriya.io.*` receipts — the same signal gating whether the doc 24 §3 rows appear in `controls`.
    pub egress: Option<EgressEvidence>,
    /// The governed-surface posture statement (doc 24 §7.2 row 4) — always present, unlike `egress`.
    pub egress_posture: EgressPosture,
    /// A ready-to-file Markdown report and the structured JSON, both generated in Rust.
    pub markdown: String,
    pub json: String,
}

/// Turn the verified on-device trail into a framework evidence bundle (SOC 2 / ISO 42001 / EU AI
/// Act) — a paid feature. The control statuses are *derived from the evidence actually present*
/// (attestations, attribution, integrity), not asserted, so the report reflects the real trail.
#[tauri::command]
pub fn export_compliance(framework: String) -> Result<ComplianceBundle, String> {
    license::require_pro()?;
    let (all_rows, mut chains) = collect();
    // Separate the signed coverage-completeness chain from the agent-action trail (GA-3): its
    // snapshots are meta-evidence, cited below, not agent actions to be counted in the totals.
    let coverage_chain_break = chains.remove("coverage.jsonl").flatten();
    let (coverage_rows, rows): (Vec<Collected>, Vec<Collected>) = all_rows
        .into_iter()
        .partition(|r| r.action_id == COVERAGE_SNAPSHOT);
    let coverage = coverage_evidence(&coverage_rows, coverage_chain_break);

    let verified = rows.iter().filter(|r| r.verified).count();
    let failed = rows.len() - verified;
    let apps: BTreeSet<&String> = rows.iter().map(|r| &r.source).collect();
    let agents: BTreeSet<&String> = rows.iter().filter_map(|r| r.actor_agent.as_ref()).collect();
    let operators: BTreeSet<&String> = rows.iter().filter_map(|r| r.actor_user.as_ref()).collect();
    let attestations = rows.iter().filter(|r| r.is_attestation).count();
    let destructive = rows.iter().filter(|r| is_destructive(&r.action_id)).count();
    let integrity_ok = failed == 0 && chains.values().all(|b| b.is_none());
    // Attribution coverage (mirrors the TS bundle's `attribution.coveragePct`): a verified receipt
    // whose signed bytes carried BOTH actor fields counts as attributed.
    let attributed = rows
        .iter()
        .filter(|r| r.verified && r.actor_agent.is_some() && r.actor_user.is_some())
        .count();
    // Distinct verified action types (excluding the attestation marker AND the kriya.io.* ledger —
    // both governance metadata, not app actions, same treatment as `compliance.ts`'s actionInventory
    // exclusion) — used by the NIST 3.3.3 "review logged events" row.
    let distinct_actions = rows
        .iter()
        .filter(|r| r.verified && !r.is_attestation && !r.action_id.starts_with(KRIYA_IO_PREFIX))
        .map(|r| r.action_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let egress = egress_evidence(&rows);
    let egress_posture = egress_posture(&rows);

    let status = |cond: bool, partial: bool| -> &'static str {
        if cond {
            "satisfied"
        } else if partial {
            "partial"
        } else {
            "gap"
        }
    };

    // Evidence-derived controls. The framework label selects the framing; the underlying evidence is
    // the same signed trail.
    let mut controls = vec![
        Control {
            id: "AUDIT-1".into(),
            name: "Tamper-evident activity log".into(),
            status: status(integrity_ok && !rows.is_empty(), !rows.is_empty()).into(),
            evidence: format!(
                "{} signed receipts; {verified} verify offline, {failed} fail; hash-chain {}",
                rows.len(),
                if chains.values().all(|b| b.is_none()) {
                    "intact"
                } else {
                    "BROKEN"
                }
            ),
        },
        Control {
            id: "ATTR-1".into(),
            name: "Action attribution (who did what)".into(),
            status: status(!agents.is_empty(), !operators.is_empty()).into(),
            evidence: format!(
                "{} distinct agent identities, {} operators stamped inside signed receipts",
                agents.len(),
                operators.len()
            ),
        },
        Control {
            id: "ONDEV-1".into(),
            name: "On-device processing attestation".into(),
            status: status(attestations > 0, false).into(),
            evidence: format!("{attestations} on-device attestation receipt(s) in the trail"),
        },
        Control {
            id: "HITL-1".into(),
            name: "High-risk actions gated for a human".into(),
            status: status(destructive > 0 || !rows.is_empty(), true).into(),
            evidence: format!(
                "{destructive} destructive/financial action(s) recorded under policy governance"
            ),
        },
    ];
    let generic_count = controls.len();
    controls.extend(framework_controls(
        &framework,
        rows.len(),
        verified,
        failed,
        apps.len(),
        distinct_actions,
        attributed,
        operators.len(),
        destructive,
        integrity_ok,
        agents.len(),
        coverage.as_ref(),
        egress.as_ref(),
    ));

    let generated_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let (generic_controls, extra_controls) = controls.split_at(generic_count);
    let markdown = render_markdown(
        &framework,
        rows.len(),
        verified,
        failed,
        &apps,
        &agents,
        &operators,
        attestations,
        destructive,
        integrity_ok,
        generic_controls,
        extra_controls,
        &chains,
        egress.as_ref(),
        &egress_posture,
    );

    let bundle_json = serde_json::json!({
        "framework": framework,
        "generatedMs": generated_ms,
        "summary": {
            "totalReceipts": rows.len(),
            "verified": verified,
            "failed": failed,
            "distinctApps": apps.len(),
            "distinctAgents": agents.len(),
            "distinctOperators": operators.len(),
            "onDeviceAttestations": attestations,
            "destructiveActions": destructive,
            "integrityOk": integrity_ok,
        },
        "controls": controls,
        "egress": egress,
        "egressPosture": egress_posture,
    });
    let json = serde_json::to_string_pretty(&bundle_json).map_err(|e| e.to_string())?;

    Ok(ComplianceBundle {
        framework,
        generated_ms,
        total_receipts: rows.len(),
        verified,
        failed,
        distinct_apps: apps.len(),
        distinct_agents: agents.len(),
        distinct_operators: operators.len(),
        on_device_attestations: attestations,
        destructive_actions: destructive,
        integrity_ok,
        controls,
        egress,
        egress_posture,
        markdown,
        json,
    })
}

/// Per-framework control rows, mirroring the TS mapping in `src/lib/compliance.ts` so the desktop
/// export carries the same rows the web preview shows (R1-1 closed the drift where the shipped
/// bundle had only the four generic controls above). Derives only from facts already computed in
/// [`export_compliance`] — there is no `Policy` object on this side, so the two rows that would be
/// policy-derived (SOC2 CC8.1, and NIST oversight-flavored rows) are honestly capped at `partial`
/// with wording that says so, rather than fabricating a policy fact this function doesn't have.
/// Unknown `framework` keys return an empty vec (today's behavior: generic controls only).
#[allow(clippy::too_many_arguments)]
fn framework_controls(
    framework: &str,
    total: usize,
    verified: usize,
    failed: usize,
    distinct_apps: usize,
    distinct_actions: usize,
    attributed: usize,
    operators: usize,
    destructive: usize,
    integrity_ok: bool,
    agents: usize,
    coverage: Option<&CoverageEvidence>,
    egress: Option<&EgressEvidence>,
) -> Vec<Control> {
    let has_rows = total > 0;
    let coverage_pct = if verified == 0 { 0 } else { (attributed * 100) / verified };

    // GA-3: cite the signed coverage-completeness chain as AU-2/AU-12 completeness evidence. Wording
    // mirrors the TS `mapControls` so the desktop + web bundles carry the same NIST rows.
    let coverage_creation_cite = coverage
        .filter(|c| c.snapshots > 0)
        .map(|c| {
            format!(
                " Completeness is itself attested: {} signed coverage snapshot(s) ({}) record which lanes were governed over the window — what was and wasn't logged is provable, not asserted.",
                c.snapshots,
                if c.chain_ok { "chain intact" } else { "chain BROKEN" }
            )
        })
        .unwrap_or_default();
    let coverage_failure_cite = if coverage.map(|c| c.snapshots > 0).unwrap_or(false) {
        " The signed coverage chain makes a stopped or silenced logging process visible by absence — a gap in the heartbeat chain, not a quiet nothing."
    } else {
        ""
    };

    let integrity_status = || -> &'static str {
        if !has_rows {
            "gap"
        } else if integrity_ok {
            "satisfied"
        } else {
            "partial"
        }
    };
    let attribution_status = || -> &'static str {
        if coverage_pct == 100 {
            "satisfied"
        } else if coverage_pct > 0 {
            "partial"
        } else {
            "gap"
        }
    };
    // Several rows describe an organizational/OS-level process (review cadence, alerting, clock
    // sync, change-authorization policy) kriya can surface signal for but never itself complete —
    // capped at partial, never satisfied, exactly like the TS `partialWhenReceipts` helper.
    let partial_when_rows = || -> &'static str { if has_rows { "partial" } else { "gap" } };

    // Egress/ingress ledger rows (EG-2/EG-3, doc 24 §3) — appear ONLY when `egress` carries at least
    // one verified `kriya.io.*` receipt; never hard-coded, never present as "gap" when absent (that
    // trail simply carries none of these rows). Every status is capped at "partial" — never
    // "satisfied" — because the governed-lane ceiling is structural (a spawned subprocess or a stdio
    // server's own outbound traffic bypasses this lane). Deliberately absent: 3.13.1, 3.13.6, SC-7,
    // SC-8, CC6.6 — killed at the governed-lane layer (doc 24 §3); the word "DLP" never appears.
    // Folded into the nearest existing selectable framework bucket (no new UI framework card is
    // introduced by this change) — the row's OWN `framework`/`control` labels carry the true
    // standard, mirroring `src/lib/compliance.ts`'s wording exactly (parity is asserted by a test).
    let deny_cite = |e: &EgressEvidence| -> String {
        if e.deny > 0 {
            format!("{} denial(s) against the allowlist observed in this window (unapproved-endpoint / anomalous-destination detection on governed lanes).", e.deny)
        } else {
            "No denials observed in this window — the allowlist has not yet been exercised against an unlisted destination.".into()
        }
    };
    let nist_800_171_egress_rows = |e: &EgressEvidence| -> Vec<Control> {
        vec![
            Control {
                id: "3.1.3".into(),
                name: "CUI flow enforcement (AC)".into(),
                status: "partial".into(),
                evidence: format!(
                    "Egress allow/deny/approve by destination for governed connector lanes ({} signed kriya.io.* receipt(s) verified: {} allow, {} deny, {} approve), signed per-decision. Governed lanes only — a spawned subprocess or a stdio MCP server's own outbound traffic is not observed. {EGRESS_SCOPE_BLOCK}",
                    e.verified_receipts, e.allow, e.deny, e.approve
                ),
            },
            Control {
                id: "3.4.2".into(),
                name: "Enforce configuration settings (CM)".into(),
                status: "partial".into(),
                evidence: format!(
                    "The egress allowlist is an enforced, receipted setting — {} governed-lane decision(s) signed against it this window. Product-scoped: this is one enforced setting on one control-plane app, never a system-wide configuration-management claim.",
                    e.verified_receipts
                ),
            },
            Control {
                id: "3.14.6/3.14.7".into(),
                name: "Monitor / identify unauthorized use (SI-4)".into(),
                status: "partial".into(),
                evidence: format!("Unapproved-endpoint and anomalous-egress detection on governed lanes. {}", deny_cite(e)),
            },
            Control {
                id: "NIST 800-53 AC-4".into(),
                name: "Information flow enforcement".into(),
                status: "partial".into(),
                evidence: format!(
                    "A signed, per-decision enforcement point on governed connector lanes ({} kriya.io.* receipt(s) verified). Nothing at this layer stands in the way of a flow that avoids it entirely — a spawned subprocess bypasses it (see the E2 host-observation roadmap and TRUST.md).",
                    e.verified_receipts
                ),
            },
            Control {
                id: "NIST 800-53 SI-4".into(),
                name: "System monitoring".into(),
                status: "partial".into(),
                evidence: format!(
                    "The governed-lane egress ledger FEEDS an organization's SI-4 monitoring program as one signed source among others — it is a contributing signal, never claimed to BE the organization's system monitoring. {} receipt(s) verified in this window.",
                    e.verified_receipts
                ),
            },
        ]
    };
    let soc2_egress_rows = |e: &EgressEvidence| -> Vec<Control> {
        vec![
            Control {
                id: "CC6.1".into(),
                name: "Logical access boundaries".into(),
                status: "partial".into(),
                evidence: format!(
                    "The gateway is a managed access point for governed connector lanes — {} signed access decision(s) this window ({} allow, {} deny, {} approve).",
                    e.verified_receipts, e.allow, e.deny, e.approve
                ),
            },
            Control {
                id: "CC6.7".into(),
                name: "Restrict transmission and movement".into(),
                status: "partial".into(),
                evidence: format!(
                    "A transmission-restriction control for governed agent lanes: destination-based allow/deny/approve, signed per decision ({} receipt(s) verified this window). {}",
                    e.verified_receipts, deny_cite(e)
                ),
            },
            Control {
                id: "CC7.2 (governed-lane egress)".into(),
                name: "Anomaly monitoring".into(),
                status: "partial".into(),
                evidence: format!("Detection tooling and logging of unusual egress activity on governed lanes. {}", deny_cite(e)),
            },
        ]
    };
    let eu_dora_egress_rows = |e: &EgressEvidence| -> Vec<Control> {
        vec![
            Control {
                id: "Art.12 (governed-lane egress)".into(),
                name: "Record-keeping".into(),
                status: "partial".into(),
                evidence: format!(
                    "Readiness-framed: {} governed-lane egress/ingress event(s) signed and verified this window; Annex III high-risk obligations are deferred to Dec 2, 2027 pending the Digital Omnibus. If this agent system is not classified high-risk, this row is INAPPLICABLE, not partial — that classification is the deploying organization's own determination, not derived from this trail.",
                    e.verified_receipts
                ),
            },
            Control {
                id: "DORA Art.28(3)".into(),
                name: "Register reconciliation".into(),
                status: "partial".into(),
                evidence: format!(
                    "A signed, actual-usage enumeration of governed-lane destinations feeds register reconciliation against the organization's Art. 28(3) ICT third-party register — {} receipt(s) verified this window. This is one input to that register, never a substitute for the organization's own maintained register.",
                    e.verified_receipts
                ),
            },
            Control {
                id: "DORA Art.10(2)/17".into(),
                name: "Detection & incident management".into(),
                status: "partial".into(),
                evidence: format!(
                    "A lane-scoped detection/incident-timeline layer for governed agent egress — one of the \"multiple layers of control\" DORA expects, not the organization's full ICT risk framework. {}",
                    deny_cite(e)
                ),
            },
        ]
    };

    match framework {
        "NIST-800-171" => {
            let mut rows = vec![
            Control {
                id: "AU.L2-3.3.1".into(),
                name: "Audit record creation & retention (AU-2/3/12)".into(),
                status: integrity_status().into(),
                evidence: if has_rows {
                    format!(
                        "{total} signed receipt(s) retained across {distinct_apps} app(s) and {agents} governed agent(s) as a hash-chained local JSONL log{}; each record carries action id, parameters, timestamp, outcome, and signer.{coverage_creation_cite}",
                        if failed > 0 { format!("; {failed} failed verification") } else { String::new() }
                    )
                } else {
                    "No audit records present in this trail.".into()
                },
            },
            Control {
                id: "AU.L2-3.3.2".into(),
                name: "Individual accountability (AU-3)".into(),
                status: attribution_status().into(),
                evidence: format!(
                    "{coverage_pct}% of verified receipts carry a signed agent + individual-operator identity ({operators} distinct operator(s))."
                ),
            },
            Control {
                id: "AU.L2-3.3.3".into(),
                name: "Review & update logged events (AU-2)".into(),
                status: partial_when_rows().into(),
                evidence: if has_rows {
                    format!(
                        "{distinct_actions} distinct action type(s) captured; the periodic review and update of which events to log is an organizational process outside kriya."
                    )
                } else {
                    "No logged events to review yet.".into()
                },
            },
            Control {
                id: "AU.L2-3.3.4".into(),
                name: "Audit logging process failure alerting (AU-5)".into(),
                status: partial_when_rows().into(),
                evidence: if has_rows {
                    format!("Per-receipt verification failures and hash-chain breaks surface live in the Console, and the Coverage Map flags silent lanes; no external paging/alerting integration exists.{coverage_failure_cite}")
                } else {
                    "No audit logging process to alert on yet.".into()
                },
            },
            Control {
                id: "AU.L2-3.3.5".into(),
                name: "Correlate audit review & analysis (AU-6(3))".into(),
                status: partial_when_rows().into(),
                evidence: if has_rows {
                    format!(
                        "Cross-app correlation on this machine (across {distinct_apps} app(s)) plus tamper flags support investigation; this is single-machine correlation, not cross-machine SIEM aggregation."
                    )
                } else {
                    "No audit records to correlate yet.".into()
                },
            },
            Control {
                id: "AU.L2-3.3.6".into(),
                name: "Audit record reduction & report generation (AU-7)".into(),
                status: (if has_rows { "satisfied" } else { "gap" }).into(),
                evidence: if has_rows {
                    "This evidence bundle (Markdown + JSON) is itself the reduction/report artifact, generated on-demand from the signed trail and independently re-verifiable offline via kriya-audit.".into()
                } else {
                    "No audit records to reduce or report on yet.".into()
                },
            },
            Control {
                id: "AU.L2-3.3.7".into(),
                name: "Clock synchronization for time stamps (AU-8)".into(),
                status: partial_when_rows().into(),
                evidence: if has_rows {
                    "Every receipt carries a host timestamp; clock synchronization against an authoritative source is OS-provided (NTP), outside kriya's control — this control is capped at partial regardless of trail size.".into()
                } else {
                    "No timestamped receipts present.".into()
                },
            },
            Control {
                id: "AU.L2-3.3.8".into(),
                name: "Protect audit information & tools (AU-9)".into(),
                status: integrity_status().into(),
                evidence: if !has_rows {
                    "No audit information to protect yet.".into()
                } else if integrity_ok {
                    "Every receipt is Ed25519-signed and hash-chained; modification or deletion is detectable, not prevented, and independently re-verifiable offline.".into()
                } else {
                    format!(
                        "{failed} receipt(s) failed verification or the hash chain broke — tampering detected; the detection control is functioning as intended, investigate the flagged record(s)."
                    )
                },
            },
            Control {
                id: "AU.L2-3.3.9".into(),
                name: "Limit audit-logging management to privileged users (AU-9(4))".into(),
                status: "gap".into(),
                evidence: "kriya's audit tooling runs under the operator's own OS account, and in-app roles are self-asserted (see docs/TRUST.md) — kriya enforces no privileged-user restriction on who can manage audit logging; this must be enforced by an OS-level or organizational access control.".into(),
            },
            ];
            if let Some(e) = egress {
                rows.extend(nist_800_171_egress_rows(e));
            }
            rows
        }
        "SOC2" => {
            let mut rows = vec![
            Control {
                id: "CC7.3".into(),
                name: "Security event evaluation".into(),
                status: partial_when_rows().into(),
                evidence: if has_rows {
                    "Per-receipt verification failures and hash-chain-break flags surface the security-event signal; the evaluation and response process itself is organizational, outside kriya.".into()
                } else {
                    "No security-event signal available yet.".into()
                },
            },
            Control {
                id: "CC8.1".into(),
                name: "Change management".into(),
                status: partial_when_rows().into(),
                evidence: format!(
                    "{destructive} destructive/financial action(s) recorded under policy governance; confirming the authorization posture (deny-by-default, approval gates) requires the policy view — not re-derived here."
                ),
            },
            ];
            if let Some(e) = egress {
                rows.extend(soc2_egress_rows(e));
            }
            rows
        }
        "ISO42001" => vec![Control {
            id: "A.6.2.6".into(),
            name: "Operation and monitoring".into(),
            status: integrity_status().into(),
            evidence: if has_rows {
                format!(
                    "The signed receipt stream is the operation/monitoring log ({verified} verified of {total}), surfaced live in the Console Monitor."
                )
            } else {
                "No operation log present yet.".into()
            },
        }],
        "EU-AI-Act" => {
            let mut rows = vec![Control {
            id: "Art.26(6)".into(),
            name: "Deployer log retention".into(),
            status: partial_when_rows().into(),
            evidence: if has_rows {
                format!(
                    "{total} receipt(s) retained locally as JSONL under the deployer's own control; kriya does not enforce or verify a specific retention schedule (e.g. the six-month minimum) — that is the deployer's responsibility."
                )
            } else {
                "No logs retained yet.".into()
            },
            }];
            if let Some(e) = egress {
                rows.extend(eu_dora_egress_rows(e));
            }
            rows
        }
        _ => vec![],
    }
}

#[allow(clippy::too_many_arguments)]
fn render_markdown(
    framework: &str,
    total: usize,
    verified: usize,
    failed: usize,
    apps: &BTreeSet<&String>,
    agents: &BTreeSet<&String>,
    operators: &BTreeSet<&String>,
    attestations: usize,
    destructive: usize,
    integrity_ok: bool,
    generic_controls: &[Control],
    extra_controls: &[Control],
    chains: &BTreeMap<String, Option<usize>>,
    egress: Option<&EgressEvidence>,
    egress_posture: &EgressPosture,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "# Kriya Console — {framework} evidence bundle\n\n"
    ));
    s.push_str(
        "Generated on-device from the signed audit trail. Every figure below is derived from\n",
    );
    s.push_str("Ed25519 receipts re-verified in compiled Rust; nothing left this machine.\n\n");
    s.push_str("## Summary\n\n");
    s.push_str(&format!(
        "- Signed receipts: **{total}** ({verified} verified, {failed} failed)\n"
    ));
    s.push_str(&format!("- Apps governed: **{}**\n", apps.len()));
    s.push_str(&format!(
        "- Agent identities: **{}**; operators: **{}**\n",
        agents.len(),
        operators.len()
    ));
    s.push_str(&format!("- On-device attestations: **{attestations}**\n"));
    s.push_str(&format!(
        "- Destructive/financial actions recorded: **{destructive}**\n"
    ));
    s.push_str(&format!(
        "- Trail integrity: **{}**\n\n",
        if integrity_ok {
            "intact"
        } else {
            "BROKEN — see integrity section"
        }
    ));
    s.push_str("## Egress/ingress ledger (governed lanes)\n\n");
    s.push_str(&render_egress_posture(egress_posture));
    s.push('\n');
    if let Some(e) = egress {
        s.push_str(&format!(
            "\n- Signed `kriya.io.*` receipts verified in this window: **{}** ({} allow, {} deny, {} approve)\n\n",
            e.verified_receipts, e.allow, e.deny, e.approve
        ));
        s.push_str(&format!("> {EGRESS_SCOPE_BLOCK}\n"));
    }
    s.push('\n');
    s.push_str("## Core evidence\n\n");
    s.push_str("| Control | Status | Evidence |\n|---|---|---|\n");
    for c in generic_controls {
        s.push_str(&format!(
            "| {} — {} | {} | {} |\n",
            c.id, c.name, c.status, c.evidence
        ));
    }
    if !extra_controls.is_empty() {
        s.push_str(&format!("\n## {framework} control mapping\n\n"));
        s.push_str("| Control | Status | Evidence |\n|---|---|---|\n");
        for c in extra_controls {
            s.push_str(&format!(
                "| {} — {} | {} | {} |\n",
                c.id, c.name, c.status, c.evidence
            ));
        }
    }
    s.push_str("\n## Integrity (hash-chain per log)\n\n");
    for (file, brk) in chains {
        match brk {
            None => s.push_str(&format!("- `{file}` — chain intact\n")),
            Some(line) => s.push_str(&format!("- `{file}` — **CHAIN BREAK at line {line}**\n")),
        }
    }
    s.push_str("\n## Apps\n\n");
    for app in apps {
        s.push_str(&format!("- {app}\n"));
    }
    s
}

#[cfg(test)]
mod framework_controls_tests {
    use super::*;

    // A small synthetic "fully verified, fully attributed" fact set: 10 receipts across 2 apps, 5
    // distinct action types, all attributed, 3 destructive actions, an intact hash chain.
    fn healthy() -> Vec<Control> {
        framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, None)
    }

    #[test]
    fn nist_800_171_returns_all_nine_au_family_rows() {
        assert_eq!(healthy().len(), 9);
    }

    #[test]
    fn practice_3_3_9_is_always_a_gap() {
        // Privileged-user restriction on audit-logging management is never provided by kriya
        // itself — the status must read "gap" regardless of how clean the rest of the trail is.
        for integrity_ok in [true, false] {
            let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, integrity_ok, 2, None, None);
            let c = rows.iter().find(|c| c.id == "AU.L2-3.3.9").unwrap();
            assert_eq!(c.status, "gap");
        }
    }

    #[test]
    fn practice_3_3_8_is_satisfied_only_when_integrity_ok_and_rows_exist() {
        let clean = healthy();
        assert_eq!(
            clean.iter().find(|c| c.id == "AU.L2-3.3.8").unwrap().status,
            "satisfied"
        );

        let tampered = framework_controls("NIST-800-171", 10, 8, 2, 2, 5, 8, 3, 3, false, 2, None, None);
        let c = tampered.iter().find(|c| c.id == "AU.L2-3.3.8").unwrap();
        assert_eq!(c.status, "partial");
        assert!(
            c.evidence.to_lowercase().contains("detect"),
            "3.3.8 evidence should name detection when tampering is present: {}",
            c.evidence
        );

        let empty = framework_controls("NIST-800-171", 0, 0, 0, 0, 0, 0, 0, 0, false, 0, None, None);
        assert_eq!(
            empty.iter().find(|c| c.id == "AU.L2-3.3.8").unwrap().status,
            "gap"
        );
    }

    #[test]
    fn empty_trail_is_every_row_gap() {
        let rows = framework_controls("NIST-800-171", 0, 0, 0, 0, 0, 0, 0, 0, false, 0, None, None);
        assert_eq!(rows.len(), 9);
        for c in &rows {
            assert_eq!(c.status, "gap", "{} should be gap on an empty trail", c.id);
        }
    }

    #[test]
    fn soc2_iso42001_eu_ai_act_each_add_one_row() {
        assert_eq!(framework_controls("SOC2", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, None).len(), 2);
        assert_eq!(framework_controls("ISO42001", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, None).len(), 1);
        assert_eq!(framework_controls("EU-AI-Act", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, None).len(), 1);
    }

    #[test]
    fn unknown_framework_key_returns_no_extra_controls_without_panicking() {
        assert!(framework_controls("FEDRAMP", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, None).is_empty());
    }

    #[test]
    fn coverage_completeness_and_agent_span_are_cited_in_3_3_1_and_3_3_4() {
        let cov = CoverageEvidence { snapshots: 14, chain_ok: true };
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, Some(&cov), None);
        let c331 = rows.iter().find(|c| c.id == "AU.L2-3.3.1").unwrap();
        assert!(c331.evidence.contains("2 governed agent(s)"), "3.3.1 spans agents: {}", c331.evidence);
        assert!(c331.evidence.contains("14 signed coverage snapshot(s)"), "3.3.1 cites coverage: {}", c331.evidence);
        assert!(c331.evidence.contains("chain intact"));
        let c334 = rows.iter().find(|c| c.id == "AU.L2-3.3.4").unwrap();
        assert!(c334.evidence.contains("visible by absence"), "3.3.4 cites the heartbeat chain: {}", c334.evidence);

        // A broken coverage chain is named honestly, not hidden.
        let broken = CoverageEvidence { snapshots: 3, chain_ok: false };
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, Some(&broken), None);
        assert!(rows.iter().find(|c| c.id == "AU.L2-3.3.1").unwrap().evidence.contains("chain BROKEN"));

        // Without a coverage summary the evidence is unchanged (backward compatible) and 3.3.9 is
        // still a permanent gap.
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, None);
        assert!(!rows.iter().find(|c| c.id == "AU.L2-3.3.1").unwrap().evidence.contains("coverage snapshot"));
        assert_eq!(rows.iter().find(|c| c.id == "AU.L2-3.3.9").unwrap().status, "gap");
    }

    // ── egress/ingress ledger rows (EG-3, doc 24 §3) ──────────────────────────────────────────────

    const FORBIDDEN: [&str; 6] = ["3.13.1", "3.13.6", "SC-7", "SC-8", "CC6.6", "DLP"];

    fn sample_egress() -> EgressEvidence {
        EgressEvidence { verified_receipts: 4, allow: 2, deny: 1, approve: 1 }
    }

    #[test]
    fn no_egress_rows_when_egress_is_none() {
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, None);
        assert!(!rows.iter().any(|c| c.id == "3.1.3"));
        assert_eq!(rows.len(), 9, "exactly the 9 AU-family rows, no egress rows");
    }

    #[test]
    fn nist_800_171_gains_five_egress_rows_all_partial_when_egress_present() {
        let egress = sample_egress();
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, Some(&egress));
        assert_eq!(rows.len(), 14, "9 AU-family + 5 egress rows");
        for id in ["3.1.3", "3.4.2", "3.14.6/3.14.7", "NIST 800-53 AC-4", "NIST 800-53 SI-4"] {
            let c = rows.iter().find(|c| c.id == id).unwrap_or_else(|| panic!("missing control row {id}"));
            assert_eq!(c.status, "partial", "{id} must be capped at partial");
        }
        let c313 = rows.iter().find(|c| c.id == "3.1.3").unwrap();
        assert!(c313.evidence.contains("4 signed kriya.io.* receipt(s)"));
        assert!(c313.evidence.contains(EGRESS_SCOPE_BLOCK));
    }

    #[test]
    fn soc2_gains_three_egress_rows() {
        let egress = sample_egress();
        let rows = framework_controls("SOC2", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, Some(&egress));
        assert_eq!(rows.len(), 5, "2 existing + 3 egress rows");
        for id in ["CC6.1", "CC6.7", "CC7.2 (governed-lane egress)"] {
            let c = rows.iter().find(|c| c.id == id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(c.status, "partial");
            assert!(!c.evidence.to_uppercase().contains("DLP"));
        }
    }

    #[test]
    fn eu_ai_act_gains_three_egress_and_dora_rows() {
        let egress = sample_egress();
        let rows = framework_controls("EU-AI-Act", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, Some(&egress));
        assert_eq!(rows.len(), 4, "1 existing + 3 egress/DORA rows");
        let art12 = rows.iter().find(|c| c.id == "Art.12 (governed-lane egress)").unwrap();
        assert!(art12.evidence.contains("INAPPLICABLE"), "the non-high-risk caveat must be present");
        assert!(rows.iter().any(|c| c.id == "DORA Art.28(3)"));
        assert!(rows.iter().any(|c| c.id == "DORA Art.10(2)/17"));
    }

    #[test]
    fn iso42001_is_unaffected_by_egress() {
        // ISO42001 has no egress bucket wired — presence of egress data must not add rows there.
        let egress = sample_egress();
        let rows = framework_controls("ISO42001", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, Some(&egress));
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn deny_count_is_cited_honestly_when_zero() {
        let egress = EgressEvidence { verified_receipts: 2, allow: 2, deny: 0, approve: 0 };
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, Some(&egress));
        let si4 = rows.iter().find(|c| c.id == "3.14.6/3.14.7").unwrap();
        assert!(si4.evidence.contains("No denials observed"));
    }

    #[test]
    fn no_egress_row_ever_carries_a_killed_control_id_or_dlp() {
        let egress = sample_egress();
        for framework in ["NIST-800-171", "SOC2", "ISO42001", "EU-AI-Act", "FEDRAMP"] {
            let rows = framework_controls(framework, 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None, Some(&egress));
            for c in &rows {
                for banned in FORBIDDEN {
                    assert!(
                        !c.id.contains(banned) && !c.evidence.contains(banned),
                        "framework={framework} control={} evidence must never contain '{banned}': {}",
                        c.id, c.evidence
                    );
                }
            }
        }
    }

    #[test]
    fn egress_evidence_is_computed_from_verified_kriya_io_receipts_and_excluded_from_action_counts() {
        let rows = vec![
            Collected { source: "x".into(), action_id: "create_note".into(), success: true, ts_ms: 1, actor_agent: None, actor_user: None, public_key: "pk".into(), verified: true, is_attestation: false },
            Collected { source: "x".into(), action_id: "kriya.io.egress.mcp.allow".into(), success: true, ts_ms: 2, actor_agent: None, actor_user: None, public_key: "pk".into(), verified: true, is_attestation: false },
            Collected { source: "x".into(), action_id: "kriya.io.egress.mcp.allow".into(), success: true, ts_ms: 3, actor_agent: None, actor_user: None, public_key: "pk".into(), verified: true, is_attestation: false },
            Collected { source: "x".into(), action_id: "kriya.io.egress.mcp.deny".into(), success: false, ts_ms: 4, actor_agent: None, actor_user: None, public_key: "pk".into(), verified: true, is_attestation: false },
            // NOT verified — must not be counted.
            Collected { source: "x".into(), action_id: "kriya.io.egress.http.approve".into(), success: true, ts_ms: 5, actor_agent: None, actor_user: None, public_key: "pk".into(), verified: false, is_attestation: false },
        ];
        let e = egress_evidence(&rows).expect("egress evidence present");
        assert_eq!(e.verified_receipts, 3, "only VERIFIED kriya.io.* receipts count");
        assert_eq!(e.allow, 2);
        assert_eq!(e.deny, 1);
        assert_eq!(e.approve, 0, "the unverified approve receipt must not count");

        let distinct_actions = rows
            .iter()
            .filter(|r| r.verified && !r.is_attestation && !r.action_id.starts_with(KRIYA_IO_PREFIX))
            .map(|r| r.action_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        assert_eq!(distinct_actions, 1, "kriya.io.* must be excluded from the action-type count");
    }

    // ── governed-surface posture (doc 24 §7.2 row 4) ──────────────────────────────────────────────

    fn collected(action_id: &str, verified: bool, is_attestation: bool) -> Collected {
        Collected {
            source: "x".into(), action_id: action_id.into(), success: true, ts_ms: 1,
            actor_agent: None, actor_user: None, public_key: "pk".into(), verified, is_attestation,
        }
    }

    #[test]
    fn posture_not_monitored_on_an_empty_trail() {
        let p = egress_posture(&[]);
        assert_eq!(p.state, EgressPostureState::NotMonitored);
        let md = render_egress_posture(&p);
        assert!(md.contains("NOT MONITORED"));
        assert!(!md.contains("zero egress"));
        assert!(!md.to_lowercase().contains("nothing left at all"));
    }

    #[test]
    fn posture_zero_observed_when_governed_lane_active_but_no_egress() {
        let rows = vec![collected("create_note", true, false), collected("delete_note", true, false)];
        let p = egress_posture(&rows);
        assert_eq!(p.state, EgressPostureState::ZeroObserved);
        assert_eq!(p.governed_lane_receipts, 2);
        assert_eq!(p.egress_receipts, 0);
        assert!(render_egress_posture(&p).contains("does NOT prove the egress ledger was continuously enabled"));
    }

    #[test]
    fn posture_egress_present_counts_egress_only_never_ingress() {
        let rows = vec![
            collected("create_note", true, false),
            collected("kriya.io.egress.mcp.allow", true, false),
            collected("kriya.io.ingress.mcp.allow", true, false),
        ];
        let p = egress_posture(&rows);
        assert_eq!(p.state, EgressPostureState::EgressPresent);
        assert_eq!(p.egress_receipts, 1, "ingress must not count as egress");
        assert!(render_egress_posture(&p).contains("NOT zero — 1 kriya.io.egress.* receipt(s)"));
    }

    #[test]
    fn posture_ignores_unverified_and_attestation_receipts() {
        let rows = vec![
            collected("kriya.attestation.on_device", true, true), // attestation: excluded
            collected("kriya.io.egress.mcp.allow", false, false),  // unverified: excluded
        ];
        let p = egress_posture(&rows);
        assert_eq!(p.state, EgressPostureState::NotMonitored);
    }

    /// Backs the "MUST match ... exactly" claims on `EgressPostureState`/`render_egress_posture`:
    /// spot-checks that TS's `renderEgressPosture` produces the same three verbatim phrases this
    /// Rust implementation does, by reading `compliance.ts`'s source at compile time.
    #[test]
    fn egress_posture_wording_matches_the_ts_implementation() {
        let ts_src = include_str!("../../src/lib/compliance.ts");
        for phrase in [
            "NOT MONITORED in this window",
            "does NOT prove the egress ledger was continuously enabled for the full window",
            "NOT zero —",
        ] {
            assert!(ts_src.contains(phrase), "TS renderEgressPosture missing phrase: {phrase}");
        }
    }

    #[test]
    fn egress_evidence_is_none_on_a_trail_with_no_kriya_io_receipts() {
        let rows = vec![Collected {
            source: "x".into(), action_id: "create_note".into(), success: true, ts_ms: 1,
            actor_agent: None, actor_user: None, public_key: "pk".into(), verified: true, is_attestation: false,
        }];
        assert!(egress_evidence(&rows).is_none());
    }

    /// Backs the doc comment's claim ("MUST match ... exactly, parity is asserted by a test"): reads
    /// `src/lib/compliance.ts`'s source at COMPILE time and reconstructs its `EGRESS_SCOPE_BLOCK`
    /// string-concatenation literal, so a future edit to either side that breaks word-for-word parity
    /// fails this test instead of silently drifting.
    #[test]
    fn egress_scope_block_is_word_for_word_identical_to_the_ts_constant() {
        let ts_src = include_str!("../../src/lib/compliance.ts");
        let start = ts_src
            .find("export const EGRESS_SCOPE_BLOCK =")
            .expect("EGRESS_SCOPE_BLOCK constant not found in compliance.ts");
        let end = ts_src[start..]
            .find(";\n")
            .map(|i| start + i)
            .expect("no terminating semicolon found");
        let decl = &ts_src[start..end];
        // Reconstruct the concatenated string from `"..." + "..." + ... "...".` segments.
        let ts_text: String = decl
            .split('"')
            .skip(1)
            .step_by(2)
            .collect::<Vec<_>>()
            .join("");
        assert!(!ts_text.is_empty(), "failed to extract the TS string literal segments");
        assert_eq!(
            ts_text, EGRESS_SCOPE_BLOCK,
            "the §3.1 scope block must be byte-identical between compliance.ts and paid.rs"
        );
    }
}
