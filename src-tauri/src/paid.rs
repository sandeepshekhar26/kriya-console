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
    // Distinct verified action types (excluding the attestation marker) — used by the NIST 3.3.3
    // "review logged events" row; not policy-derived, just a count over what collect() already saw.
    let distinct_actions = rows
        .iter()
        .filter(|r| r.verified && !r.is_attestation)
        .map(|r| r.action_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();

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

    match framework {
        "NIST-800-171" => vec![
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
        ],
        "SOC2" => vec![
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
        ],
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
        "EU-AI-Act" => vec![Control {
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
        }],
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
        framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None)
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
            let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, integrity_ok, 2, None);
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

        let tampered = framework_controls("NIST-800-171", 10, 8, 2, 2, 5, 8, 3, 3, false, 2, None);
        let c = tampered.iter().find(|c| c.id == "AU.L2-3.3.8").unwrap();
        assert_eq!(c.status, "partial");
        assert!(
            c.evidence.to_lowercase().contains("detect"),
            "3.3.8 evidence should name detection when tampering is present: {}",
            c.evidence
        );

        let empty = framework_controls("NIST-800-171", 0, 0, 0, 0, 0, 0, 0, 0, false, 0, None);
        assert_eq!(
            empty.iter().find(|c| c.id == "AU.L2-3.3.8").unwrap().status,
            "gap"
        );
    }

    #[test]
    fn empty_trail_is_every_row_gap() {
        let rows = framework_controls("NIST-800-171", 0, 0, 0, 0, 0, 0, 0, 0, false, 0, None);
        assert_eq!(rows.len(), 9);
        for c in &rows {
            assert_eq!(c.status, "gap", "{} should be gap on an empty trail", c.id);
        }
    }

    #[test]
    fn soc2_iso42001_eu_ai_act_each_add_one_row() {
        assert_eq!(framework_controls("SOC2", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None).len(), 2);
        assert_eq!(framework_controls("ISO42001", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None).len(), 1);
        assert_eq!(framework_controls("EU-AI-Act", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None).len(), 1);
    }

    #[test]
    fn unknown_framework_key_returns_no_extra_controls_without_panicking() {
        assert!(framework_controls("FEDRAMP", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None).is_empty());
    }

    #[test]
    fn coverage_completeness_and_agent_span_are_cited_in_3_3_1_and_3_3_4() {
        let cov = CoverageEvidence { snapshots: 14, chain_ok: true };
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, Some(&cov));
        let c331 = rows.iter().find(|c| c.id == "AU.L2-3.3.1").unwrap();
        assert!(c331.evidence.contains("2 governed agent(s)"), "3.3.1 spans agents: {}", c331.evidence);
        assert!(c331.evidence.contains("14 signed coverage snapshot(s)"), "3.3.1 cites coverage: {}", c331.evidence);
        assert!(c331.evidence.contains("chain intact"));
        let c334 = rows.iter().find(|c| c.id == "AU.L2-3.3.4").unwrap();
        assert!(c334.evidence.contains("visible by absence"), "3.3.4 cites the heartbeat chain: {}", c334.evidence);

        // A broken coverage chain is named honestly, not hidden.
        let broken = CoverageEvidence { snapshots: 3, chain_ok: false };
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, Some(&broken));
        assert!(rows.iter().find(|c| c.id == "AU.L2-3.3.1").unwrap().evidence.contains("chain BROKEN"));

        // Without a coverage summary the evidence is unchanged (backward compatible) and 3.3.9 is
        // still a permanent gap.
        let rows = framework_controls("NIST-800-171", 10, 10, 0, 2, 5, 10, 3, 3, true, 2, None);
        assert!(!rows.iter().find(|c| c.id == "AU.L2-3.3.1").unwrap().evidence.contains("coverage snapshot"));
        assert_eq!(rows.iter().find(|c| c.id == "AU.L2-3.3.9").unwrap().status, "gap");
    }
}
