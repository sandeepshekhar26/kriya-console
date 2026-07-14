//! The Coverage Map core (W1-4/W1-5, doc-20 §4) — completeness as a signed, on-device metric.
//!
//! Two halves:
//! - **Classify**: six product-fixed lanes (`claude-code-tools`, `local-stdio-mcp`, `remote-mcp`,
//!   `desktop-apps`, `raw-file-exec`, `raw-egress`), each GREEN (configured + evidence in window),
//!   AMBER (configured but silent), or GREY (uncovered) — derived from `~/.kriya/audit/*.jsonl`
//!   plus hook-config detection. Free tier: the map IS the wedge and the honesty surface.
//! - **Attest**: a `kriya.coverage.snapshot` receipt into its own hash chain
//!   (`~/.kriya/audit/coverage.jsonl`, key `~/.kriya/keys/coverage.key`), emitted on lane-state
//!   change or every 24 h — so a silenced Console or stopped watcher is *visible-by-absence in the
//!   chain* (doc-15 invariant 6). "Green" can't be retconned.
//!
//! The snapshot signer reproduces the runtime's exact signed-byte format
//! (`crates/kriya/src/audit.rs` — canonical field order + R21 key-sorted params + R20 tail-seeded
//! chain), so the SAME verifiers (`kriya-verify`, the TS spine, `kriya-audit`) re-prove Console
//! snapshots with zero new trust machinery. Parity is enforced by tests below that round-trip a
//! written snapshot through `kriya_verify::verify_value` + `chain_break`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use serde_json::{json, Value};

use kriya_verify::{canonical_value, chain_break, sha256_hex};

use crate::audit::{default_audit_dir, home_dir};

/// The six lanes, in render order. Fixed product vocabulary (doc-20 §4) — classifiers may get
/// smarter per lane, but the lane set only changes with a docs+GTM decision.
pub const LANES: [&str; 6] = [
    "claude-code-tools",
    "local-stdio-mcp",
    "remote-mcp",
    "desktop-apps",
    "raw-file-exec",
    "raw-egress",
];

const DEFAULT_WINDOW_H: u64 = 24;
const SNAPSHOT_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000; // re-attest at least daily
const TICK: Duration = Duration::from_secs(60);

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LaneState {
    /// Configured + evidence (receipts, or a live watcher heartbeat) within the window.
    Green,
    /// Configured but silent — the channel exists, nothing observed in the window.
    Amber,
    /// Uncovered — events in this lane would leave no receipt.
    Grey,
}

/// One lane's classification. Serialized both to the UI (`coverage_status`) and, verbatim, into the
/// signed snapshot params — everything here is device-local metadata (states, counts, timestamps;
/// never paths/hosts/params), so it is safe in the snapshot and, later, allowlisted state-only in
/// envelopes (doc-20 §5).
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LaneInfo {
    pub state: LaneState,
    /// The seam providing this lane's evidence today (e.g. "hook.claude-code", "gateway").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_receipt_ms: Option<u64>,
    /// Chain files currently feeding the lane.
    pub files: usize,
    /// EG-3 (doc 24 §7.3): whether a `kriya.io.egress.*` receipt was observed on this lane within
    /// the window — `None` on a lane the egress ledger doesn't apply to (desktop-apps, raw-file-exec,
    /// and, deliberately, raw-egress: that lane belongs to E2's host watcher, and the visual gap
    /// between a green `kriya.io.*` chip here and the grey/uncovered raw-egress lane below IS the
    /// bypass disclosure — never colored to imply this ledger closes it). `Some(true)`/`Some(false)`
    /// on claude-code-tools / remote-mcp / local-stdio-mcp: whether governed-lane egress evidence
    /// showed up in-window, not whether the tier is *configured* (this repo has no toggle-receipt to
    /// prove the latter for a window with zero calls — see docs/TRUST.md's egress section).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_ledger: Option<bool>,
    /// EG-C (doc 24 §11 B14): whether a `kriya-gateway run --` containment session's bookend
    /// receipt (`kriya.io.run.start`/`run.exit`) was observed in-window. `None` on every lane but
    /// `raw-egress`, where it is the SOLE field EG-C is allowed to touch — deliberately never
    /// `state`, `source`, or `egress_ledger`, all of which stay governed entirely by the E2 host
    /// watcher's own evidence (the invariant `egress_ledger_chip_reflects_…` locks in). A contained
    /// session enforces egress for the process `run --` launched and nothing else; it is not host
    /// coverage, and this map must never present it as such. `Some(true)`/`Some(false)`: at least
    /// one `run.jsonl`-shaped file exists, fresh or stale; `None`: no contained session ever ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contained_session: Option<bool>,
}

/// What the Coverage view renders (pure read — no side effects, no snapshot writes).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageStatus {
    pub window_h: u64,
    pub lanes: BTreeMap<String, LaneInfo>,
    /// ts of the newest signed snapshot in the coverage chain, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_snapshot_ms: Option<u64>,
    /// Whether the coverage chain itself verifies end-to-end (hash-chain continuity).
    pub snapshot_chain_ok: bool,
    /// Total snapshots in the chain (the heartbeat history depth).
    pub snapshots: usize,
    /// Per-agent coverage groups (GA-2) — Claude Code and Hermes on the same substrate, with the
    /// honest cloud line. A view layer over the same audit dir; not part of the signed snapshot.
    pub agents: Vec<AgentCoverage>,
}

// ---------------------------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------------------------

/// Per-file evidence extracted in one pass: newest timestamps overall and per interesting
/// action-id family. Timestamps are receipt `ts_ms` values (device clock at signing).
#[derive(Default, Clone, Debug)]
struct Scan {
    name: String,
    last_any: Option<u64>,
    /// `claude-code__mcp__…` — MCP servers observed through the Claude Code hook.
    last_cc_mcp: Option<u64>,
    /// `kriya.watch.proc.*` / `kriya.watch.file.*` — out-of-channel exec/file evidence.
    last_watch_procfile: Option<u64>,
    /// `kriya.watch.net.*` / `kriya.watch.dns.*` — raw egress evidence.
    last_watch_net: Option<u64>,
    /// `kriya.watch.heartbeat` (+ run.start/run.exit bookends) — watcher liveness.
    last_watch_heartbeat: Option<u64>,
    /// `kriya.io.egress.*` (EG-2/EG-3, doc 24 §7.3) — governed-lane egress evidence.
    last_kriya_io_egress: Option<u64>,
    /// `kriya.io.run.start` / `kriya.io.run.exit` (EG-C, doc 24 §11 B14) — a `kriya-gateway run --`
    /// containment session bookend. Tracked separately from `last_kriya_io_egress`: a contained
    /// session is enforcement for the LAUNCHED subtree only, never a claim about lane-wide E2 host
    /// coverage — see [`LaneInfo::contained_session`].
    last_kriya_io_run: Option<u64>,
}

fn max_opt(slot: &mut Option<u64>, v: u64) {
    *slot = Some(slot.map_or(v, |cur| cur.max(v)));
}

fn scan_file(path: &Path) -> Scan {
    let mut scan = Scan {
        name: path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ..Scan::default()
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return scan;
    };
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue; // malformed lines are the Audit view's business, not coverage evidence
        };
        let Some(ts) = v.get("ts_ms").and_then(Value::as_u64) else {
            continue;
        };
        let aid = v.get("action_id").and_then(Value::as_str).unwrap_or("");
        max_opt(&mut scan.last_any, ts);
        if aid.starts_with("claude-code__mcp__") {
            max_opt(&mut scan.last_cc_mcp, ts);
        }
        if aid.starts_with("kriya.watch.proc.") || aid.starts_with("kriya.watch.file.") {
            max_opt(&mut scan.last_watch_procfile, ts);
        }
        if aid.starts_with("kriya.watch.net.") || aid.starts_with("kriya.watch.dns.") {
            max_opt(&mut scan.last_watch_net, ts);
        }
        if aid == "kriya.watch.heartbeat"
            || aid == "kriya.watch.run.start"
            || aid == "kriya.watch.run.exit"
        {
            max_opt(&mut scan.last_watch_heartbeat, ts);
        }
        if aid.starts_with("kriya.io.egress.") {
            max_opt(&mut scan.last_kriya_io_egress, ts);
        }
        if aid == "kriya.io.run.start" || aid == "kriya.io.run.exit" {
            max_opt(&mut scan.last_kriya_io_run, ts);
        }
    }
    scan
}

/// Which lanes a watcher chain *claims* to cover, by filename — a fresh heartbeat greens exactly
/// these (watcher alive + quiet ⇒ covered). Event receipts green their lane regardless of filename.
fn watch_covers(file_name: &str) -> (bool /* proc/file */, bool /* net */) {
    let stem = file_name.trim_end_matches(".jsonl");
    match stem {
        "watch-tetragon" => (true, true), // eBPF sees exec/file/net/dns (rung 2)
        "watch-es" => (true, false),      // Endpoint Security: exec/file (rung 4; net is beta-only)
        "watch-netext" => (false, true),  // transparent proxy: egress only (rung 3)
        "watch-run" => (false, true),     // launch-under: egress pin (+ tailer, spike-gated) (rung 1)
        _ => (true, true),                // unknown future watcher: trust its events, hb greens both
    }
}

/// The Claude Code user settings file, where the hook wiring lives.
pub fn claude_settings_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".claude").join("settings.json"))
}

/// Is `kriya-hook` wired into Claude Code's hooks? (Config presence = the AMBER half of
/// "configured but silent".) Robust to layout: any mention inside the `hooks` value counts.
/// `pub(crate)` so the govern-all detector reuses the one hook-detection definition (GA-0).
pub(crate) fn hook_configured(settings: Option<&Path>) -> bool {
    let Some(p) = settings else { return false };
    let Ok(text) = std::fs::read_to_string(p) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    v.get("hooks")
        .map(|h| h.to_string().contains("kriya-hook"))
        .unwrap_or(false)
}

fn state_of(fresh: bool, configured: bool) -> LaneState {
    match (fresh, configured) {
        (true, _) => LaneState::Green,
        (false, true) => LaneState::Amber,
        (false, false) => LaneState::Grey,
    }
}

/// Classify the six lanes from an audit dir + the Claude settings file, against `now_ms` and a
/// freshness window. Pure with respect to its inputs (dir-injectable for tests); does not write.
pub fn classify(
    audit_dir: &Path,
    claude_settings: Option<&Path>,
    now_ms: u64,
    window_ms: u64,
) -> BTreeMap<String, LaneInfo> {
    let fresh = |ts: Option<u64>| ts.map(|t| now_ms.saturating_sub(t) <= window_ms).unwrap_or(false);

    // One pass over the dir, bucketing files by lane family.
    let mut claude_code: Option<Scan> = None;
    let mut gateway: Vec<Scan> = Vec::new(); // per-server proxy logs
    let mut broker: Option<Scan> = None; // the W2 aggregator: one endpoint, N upstreams
    let mut desktop: Vec<Scan> = Vec::new();
    let mut watch: Vec<Scan> = Vec::new();
    let mut contained: Vec<Scan> = Vec::new(); // EG-C `kriya-gateway run --` sessions
    if let Ok(entries) = std::fs::read_dir(audit_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            match name.as_str() {
                "coverage.jsonl" => {} // the map itself is not a lane
                "claude-code.jsonl" => claude_code = Some(scan_file(&path)),
                "broker.jsonl" => broker = Some(scan_file(&path)),
                "computer_use.jsonl" | "router.jsonl" => desktop.push(scan_file(&path)),
                n if n.starts_with("reach-in-") => desktop.push(scan_file(&path)),
                n if n.starts_with("watch-") => watch.push(scan_file(&path)),
                // EG-C (doc 24 §11 B14): `kriya-gateway run --`'s default audit-log name is
                // `run.jsonl` (resolve_audit_log's slugified label "run"); an explicit
                // `--audit-log` naming convention could vary, so also catch a `run-` prefix. NOT
                // bucketed as `gateway` — a contained session is not an MCP proxy lane, and its
                // kriya.io.egress.* receipts must not spuriously light local-stdio-mcp's chip.
                n if n == "run.jsonl" || n.starts_with("run-") => {
                    contained.push(scan_file(&path))
                }
                _ => gateway.push(scan_file(&path)),
            }
        }
    }

    let hook = hook_configured(claude_settings);
    let mut lanes = BTreeMap::new();

    // claude-code-tools — the whole Claude Code lane, native + MCP, via the hook.
    {
        let last = claude_code.as_ref().and_then(|s| s.last_any);
        let present = claude_code.is_some();
        let io_last = claude_code.as_ref().and_then(|s| s.last_kriya_io_egress);
        lanes.insert(
            "claude-code-tools".into(),
            LaneInfo {
                state: state_of(fresh(last), hook || present),
                source: (hook || present).then(|| "hook.claude-code".into()),
                last_receipt_ms: last,
                files: usize::from(present),
                egress_ledger: present.then(|| fresh(io_last)),
                contained_session: None,
            },
        );
    }

    // remote-mcp — MCP servers reached outside a per-server gateway: via the Claude Code hook
    // (`claude-code__mcp__*`) OR the W2 broker (one endpoint, N upstreams, incl. hook-less clients
    // like Claude Desktop). Either seam greens the lane; the broker is the higher-fidelity path.
    {
        let hook_last = claude_code.as_ref().and_then(|s| s.last_cc_mcp);
        let broker_last = broker.as_ref().and_then(|s| s.last_any);
        let last = hook_last.max(broker_last);
        let configured = hook || hook_last.is_some() || broker.is_some();
        let source = if broker.is_some() {
            Some("broker".into())
        } else if hook || hook_last.is_some() {
            Some("hook.claude-code".into())
        } else {
            None
        };
        let io_last = claude_code
            .as_ref()
            .and_then(|s| s.last_kriya_io_egress)
            .max(broker.as_ref().and_then(|s| s.last_kriya_io_egress));
        lanes.insert(
            "remote-mcp".into(),
            LaneInfo {
                state: state_of(fresh(last), configured),
                source,
                last_receipt_ms: last,
                files: usize::from(hook_last.is_some()) + usize::from(broker.is_some()),
                egress_ledger: configured.then(|| fresh(io_last)),
                contained_session: None,
            },
        );
    }

    // local-stdio-mcp — gateway per-server chains (any MCP client wired through kriya-gateway).
    {
        let last = gateway.iter().filter_map(|s| s.last_any).max();
        let io_last = gateway.iter().filter_map(|s| s.last_kriya_io_egress).max();
        lanes.insert(
            "local-stdio-mcp".into(),
            LaneInfo {
                state: state_of(fresh(last), !gateway.is_empty()),
                source: (!gateway.is_empty()).then(|| "gateway".into()),
                last_receipt_ms: last,
                files: gateway.len(),
                egress_ledger: (!gateway.is_empty()).then(|| fresh(io_last)),
                contained_session: None,
            },
        );
    }

    // desktop-apps — reach-in / computer-use / router chains. No egress ledger: this lane's traffic
    // isn't the governed MCP/HTTP connector surface the ledger covers.
    {
        let last = desktop.iter().filter_map(|s| s.last_any).max();
        lanes.insert(
            "desktop-apps".into(),
            LaneInfo {
                state: state_of(fresh(last), !desktop.is_empty()),
                source: (!desktop.is_empty()).then(|| "reach-in/computer-use".into()),
                last_receipt_ms: last,
                files: desktop.len(),
                egress_ledger: None,
                contained_session: None,
            },
        );
    }

    // raw-file-exec / raw-egress — watcher rungs. GREEN on fresh events OR a fresh heartbeat from
    // a chain that covers the lane (alive + quiet ⇒ covered); AMBER when a covering chain exists
    // but is silent; GREY when nothing would observe the lane at all.
    for (lane, pick_events, pick_cover) in [
        (
            "raw-file-exec",
            (|s: &Scan| s.last_watch_procfile) as fn(&Scan) -> Option<u64>,
            (|n: &str| watch_covers(n).0) as fn(&str) -> bool,
        ),
        (
            "raw-egress",
            (|s: &Scan| s.last_watch_net) as fn(&Scan) -> Option<u64>,
            (|n: &str| watch_covers(n).1) as fn(&str) -> bool,
        ),
    ] {
        let covering: Vec<&Scan> = watch.iter().filter(|s| pick_cover(&s.name)).collect();
        let last_event = watch.iter().filter_map(|s| pick_events(s)).max();
        let last_hb = covering.iter().filter_map(|s| s.last_watch_heartbeat).max();
        let green = fresh(last_event) || fresh(last_hb);
        let configured = !covering.is_empty() || last_event.is_some();
        // EG-C (doc 24 §11 B14): a SEPARATE, additive signal on raw-egress ONLY — never folded
        // into `state`/`configured`/`green` above, which stay governed entirely by E2 host-watcher
        // evidence. A contained `run --` session enforces egress for the launched subtree only; it
        // must never make this lane read as host-wide E2 coverage.
        let contained_session = (lane == "raw-egress" && !contained.is_empty())
            .then(|| fresh(contained.iter().filter_map(|s| s.last_kriya_io_run).max()));
        lanes.insert(
            lane.into(),
            LaneInfo {
                state: state_of(green, configured),
                source: configured.then(|| "kriya-watch".into()),
                last_receipt_ms: last_event.max(last_hb),
                files: covering.len(),
                // raw-egress deliberately NEVER gets this chip: it belongs to E2 (the host watcher),
                // and coloring it from the governed-lane ledger would blur the exact bypass disclosure
                // this map exists to make honest (doc 24 §7.1 — "never colors the raw-egress lane").
                egress_ledger: None,
                contained_session,
            },
        );
    }

    lanes
}

// ---------------------------------------------------------------------------------------------
// Multi-agent coverage view (GA-2, doc 21 §UI) — the same substrate, grouped per agent.
//
// This is a **read-only view layer** on top of the same audit dir; it does NOT change the six
// signed lanes or the snapshot format (the chain stays byte-identical + verifiable). It answers
// "how is each of my agents governed" — Claude Code and Hermes on one map — with the honest cloud
// line (off-device surfaces greyed with their locus reason).
// ---------------------------------------------------------------------------------------------

/// One lane within an agent's coverage group.
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AgentLane {
    pub id: String,
    pub title: String,
    pub state: LaneState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_receipt_ms: Option<u64>,
    /// For an out-of-scope lane: why it can't produce an on-device receipt (the locus reason).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locus: Option<String>,
}

/// One agent's coverage group (a lane-group in the Coverage view).
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AgentCoverage {
    pub agent: String,
    pub label: String,
    pub lanes: Vec<AgentLane>,
}

/// Per-agent evidence gathered in one pass over the audit dir (newest receipt ts per family).
#[derive(Default)]
struct AgentScan {
    cc_native: Option<u64>,     // claude-code.jsonl, non-mcp actions
    cc_mcp: Option<u64>,        // claude-code__mcp__* actions
    hermes_native: Option<u64>, // hermes.jsonl (the demand-pulled hook's log)
    hermes_mcp: Option<u64>,    // any gateway per-server receipt attributed to actor.agent "hermes"
}

fn scan_agents(audit_dir: &Path) -> AgentScan {
    let mut s = AgentScan::default();
    let Ok(entries) = std::fs::read_dir(audit_dir) else {
        return s;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "coverage.jsonl" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(ts) = v.get("ts_ms").and_then(Value::as_u64) else {
                continue;
            };
            let aid = v.get("action_id").and_then(Value::as_str).unwrap_or("");
            let actor_agent = v
                .get("actor")
                .and_then(|a| a.get("agent"))
                .and_then(Value::as_str);
            if name == "claude-code.jsonl" {
                if aid.starts_with("claude-code__mcp__") {
                    max_opt(&mut s.cc_mcp, ts);
                } else if aid.starts_with("claude-code__") {
                    max_opt(&mut s.cc_native, ts);
                }
            } else if name == "hermes.jsonl" {
                max_opt(&mut s.hermes_native, ts);
            } else if actor_agent == Some("hermes") {
                // A gateway per-server chain attributed to Hermes (govern-all wraps its stdio MCP).
                max_opt(&mut s.hermes_mcp, ts);
            }
        }
    }
    s
}

/// Classify the governed surface **per agent** — Claude Code and Hermes on the same substrate. Pure
/// with respect to its inputs (audit dir + config-derived flags), so it's fixture-testable. The
/// config flags (`cc_hook`, `hermes_hook`, `hermes_gateway`) supply the AMBER "configured but silent"
/// half; the audit dir supplies the GREEN evidence.
pub fn classify_agents(
    audit_dir: &Path,
    now_ms: u64,
    window_ms: u64,
    cc_hook: bool,
    hermes_hook: bool,
    hermes_gateway: bool,
) -> Vec<AgentCoverage> {
    let fresh = |ts: Option<u64>| ts.map(|t| now_ms.saturating_sub(t) <= window_ms).unwrap_or(false);
    let s = scan_agents(audit_dir);

    let claude_code = AgentCoverage {
        agent: "claude-code".into(),
        label: "Claude Code".into(),
        lanes: vec![
            AgentLane {
                id: "native-tools".into(),
                title: "Native tools".into(),
                state: state_of(fresh(s.cc_native), cc_hook || s.cc_native.is_some()),
                source: Some("hook.claude-code".into()),
                last_receipt_ms: s.cc_native,
                locus: None,
            },
            AgentLane {
                id: "attached-mcp".into(),
                title: "Attached MCP".into(),
                state: state_of(fresh(s.cc_mcp), cc_hook || s.cc_mcp.is_some()),
                source: Some("hook.claude-code".into()),
                last_receipt_ms: s.cc_mcp,
                locus: None,
            },
            AgentLane {
                id: "cloud".into(),
                title: "Cloud".into(),
                state: LaneState::Grey,
                source: None,
                last_receipt_ms: None,
                locus: Some(
                    "Claude Code on web · Cloud Routines · hosted Cowork run in Anthropic's cloud — no on-device process, so no receipt is possible."
                        .into(),
                ),
            },
        ],
    };

    let hermes_native_covered = hermes_hook || s.hermes_native.is_some();
    let hermes = AgentCoverage {
        agent: "hermes".into(),
        label: "Hermes".into(),
        lanes: vec![
            AgentLane {
                id: "native-tools".into(),
                title: "Native tools".into(),
                state: state_of(fresh(s.hermes_native), hermes_native_covered),
                source: Some("hook.hermes".into()),
                last_receipt_ms: s.hermes_native,
                locus: (!hermes_native_covered).then(|| {
                    "Native-tool coverage needs kriya-hermes-hook (demand-pulled) — Hermes' local MCP is governed via the gateway today."
                        .into()
                }),
            },
            AgentLane {
                id: "mcp".into(),
                title: "MCP servers".into(),
                state: state_of(fresh(s.hermes_mcp), hermes_gateway || s.hermes_mcp.is_some()),
                source: Some("gateway".into()),
                last_receipt_ms: s.hermes_mcp,
                locus: None,
            },
            AgentLane {
                id: "cloud".into(),
                title: "Cloud sandbox".into(),
                state: LaneState::Grey,
                source: None,
                last_receipt_ms: None,
                locus: Some(
                    "TERMINAL_ENV=modal/daytona ships the command to a remote sandbox — locus=cloud, so no on-device receipt is possible."
                        .into(),
                ),
            },
        ],
    };

    vec![claude_code, hermes]
}

/// Read the Hermes config at the real, standard path for the two AMBER flags (production call site).
fn hermes_flags() -> (bool, bool) {
    hermes_flags_from(&crate::govern::hermes_config_path())
}

/// Is a `kriya-hermes-hook` block wired, and is any local MCP server wrapped by `kriya-gateway`?
/// Best-effort (missing/invalid config ⇒ both false). Injectable path so this is fixture-testable,
/// mirroring [`classify`]'s injectable `audit_dir` — a hermetic unit test caught this function's one
/// real bug (it originally looked up Claude's `mcpServers` key; Hermes' real on-disk key is
/// `mcp_servers`, per `hermes_cli/mcp_config.py`) where the production-only call site couldn't.
fn hermes_flags_from(path: &Path) -> (bool, bool) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (false, false);
    };
    let Ok(v) = serde_yaml::from_str::<Value>(&text) else {
        return (false, false);
    };
    let hook = v
        .get("hooks")
        .map(|h| h.to_string().contains("kriya-hermes-hook"))
        .unwrap_or(false);
    let gateway = v
        .get(crate::govern::Client::Hermes.servers_key())
        .and_then(Value::as_object)
        .map(|m| {
            m.values().any(|e| {
                e.get("command")
                    .and_then(Value::as_str)
                    .and_then(|c| Path::new(c).file_name().and_then(|n| n.to_str()).map(String::from))
                    .map(|n| n.starts_with("kriya-gateway"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    (hook, gateway)
}

// ---------------------------------------------------------------------------------------------
// The signed snapshot chain (`kriya.coverage.snapshot`)
// ---------------------------------------------------------------------------------------------

/// Actor written on snapshots. Field order (agent, then user) is load-bearing for the signature —
/// mirrors `kriya-verify::Actor` / runtime `audit.rs`.
#[derive(Serialize, Clone)]
struct ActorJson {
    agent: String,
    user: String,
}

/// The unsigned receipt in the runtime's exact declaration order (`step_id, action_id, params,
/// success, ts_ms, actor?, prev_hash?`) — these are the signed bytes. Keep in lockstep with
/// `kriya-verify`'s `CanonicalReceipt` (the parity tests below round-trip through it).
#[derive(Serialize)]
struct CanonicalReceipt<'a> {
    step_id: &'a str,
    action_id: &'a str,
    params: &'a Value,
    success: bool,
    ts_ms: u64,
    actor: &'a ActorJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<&'a str>,
}

/// The written JSONL line: the receipt fields (same order) + `public_key` + `signature` — the
/// runtime's flattened `SignedReceipt` shape.
#[derive(Serialize)]
struct SignedLine<'a> {
    step_id: &'a str,
    action_id: &'a str,
    params: &'a Value,
    success: bool,
    ts_ms: u64,
    actor: &'a ActorJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<&'a str>,
    public_key: String,
    signature: String,
}

/// `~/.kriya/keys/` — the same per-source key directory the runtime fronts use.
pub fn default_keys_dir() -> PathBuf {
    match home_dir().map(|h| h.join(".kriya").join("keys")) {
        Some(dir) if std::fs::create_dir_all(&dir).is_ok() => dir,
        _ => std::env::temp_dir(),
    }
}

/// Load or mint the coverage signing key (32-byte seed, lowercase hex, 0600 — the runtime's
/// `Signer::with_identity` on-disk format). An existing-but-invalid key is an error, never
/// silently overwritten (losing a durable identity must be explicit).
fn load_or_create_key(path: &Path) -> Result<SigningKey, String> {
    if path.exists() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let bytes = hex::decode(text.trim())
            .map_err(|e| format!("{} is not valid hex: {e}", path.display()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{} is not a 32-byte seed", path.display()))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("OS CSPRNG failed: {e}"))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(hex::encode(seed).as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// SHA-256 of the log's last non-empty line — the R20 tail seed, exactly as the runtime re-seeds
/// its chain across process restarts.
fn tail_hash(log: &Path) -> Option<String> {
    let text = std::fs::read_to_string(log).ok()?;
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(|last| sha256_hex(last.as_bytes()))
}

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

/// Append one signed `kriya.coverage.snapshot` to the coverage chain. Returns the written line.
pub fn emit_snapshot(
    audit_dir: &Path,
    keys_dir: &Path,
    lanes: &BTreeMap<String, LaneInfo>,
    window_h: u64,
    ts_ms: u64,
) -> Result<String, String> {
    let log = audit_dir.join("coverage.jsonl");
    let key = load_or_create_key(&keys_dir.join("coverage.key"))?;

    let params_raw = json!({
        "v": 1,
        "window_h": window_h,
        "lanes": lanes,
        "console_version": env!("CARGO_PKG_VERSION"),
    });
    let params = canonical_value(&params_raw); // R21 — sorted keys, byte-reproducible
    let prev = tail_hash(&log);
    let step_id = {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|e| format!("OS CSPRNG failed: {e}"))?;
        hex::encode(raw)
    };
    let actor = ActorJson {
        agent: "kriya-console".into(),
        user: os_user(),
    };

    let canon = CanonicalReceipt {
        step_id: &step_id,
        action_id: "kriya.coverage.snapshot",
        params: &params,
        success: true,
        ts_ms,
        actor: &actor,
        prev_hash: prev.as_deref(),
    };
    let msg = serde_json::to_vec(&canon).map_err(|e| format!("canonicalize: {e}"))?;
    let signature = hex::encode(key.sign(&msg).to_bytes());
    let line = serde_json::to_string(&SignedLine {
        step_id: &step_id,
        action_id: "kriya.coverage.snapshot",
        params: &params,
        success: true,
        ts_ms,
        actor: &actor,
        prev_hash: prev.as_deref(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature,
    })
    .map_err(|e| format!("serialize: {e}"))?;

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .map_err(|e| format!("cannot open {}: {e}", log.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("cannot append {}: {e}", log.display()))?;
    Ok(line)
}

/// Emit iff the lane-state vector changed since the last snapshot, or the last one is older than
/// 24 h. Timestamp-only movement (a lane's `last_receipt_ms` advancing within the same state)
/// never re-attests — the chain records *state transitions + liveness*, not traffic.
pub fn should_emit(
    prev: Option<&(BTreeMap<String, LaneState>, u64)>,
    current: &BTreeMap<String, LaneState>,
    now_ms: u64,
) -> bool {
    match prev {
        None => true,
        Some((states, ts)) => states != current || now_ms.saturating_sub(*ts) > SNAPSHOT_MAX_AGE_MS,
    }
}

fn states_of(lanes: &BTreeMap<String, LaneInfo>) -> BTreeMap<String, LaneState> {
    lanes.iter().map(|(k, v)| (k.clone(), v.state)).collect()
}

/// Recover (states, ts) of the newest snapshot from the chain tail, so an app restart doesn't
/// re-attest an unchanged map. Any parse failure just means "emit once now".
fn seed_last_emitted(log: &Path) -> Option<(BTreeMap<String, LaneState>, u64)> {
    let text = std::fs::read_to_string(log).ok()?;
    let last = text.lines().rev().find(|l| !l.trim().is_empty())?;
    let v: Value = serde_json::from_str(last).ok()?;
    let ts = v.get("ts_ms").and_then(Value::as_u64)?;
    let lanes = v.get("params")?.get("lanes")?.as_object()?;
    let mut states = BTreeMap::new();
    for (lane, info) in lanes {
        let state = match info.get("state").and_then(Value::as_str)? {
            "green" => LaneState::Green,
            "amber" => LaneState::Amber,
            "grey" => LaneState::Grey,
            _ => return None,
        };
        states.insert(lane.clone(), state);
    }
    Some((states, ts))
}

/// The heartbeat loop: classify every minute, attest on change or daily. Spawned at app startup
/// (free tier). Failures are non-fatal and retried next tick — a missing snapshot is itself the
/// signal the chain is designed to expose.
pub fn spawn_heartbeat() {
    std::thread::spawn(|| {
        let audit_dir = default_audit_dir();
        let keys_dir = default_keys_dir();
        let mut last = seed_last_emitted(&audit_dir.join("coverage.jsonl"));
        loop {
            let now = now_ms();
            let lanes = classify(
                &audit_dir,
                claude_settings_path().as_deref(),
                now,
                DEFAULT_WINDOW_H * 60 * 60 * 1000,
            );
            let states = states_of(&lanes);
            if should_emit(last.as_ref(), &states, now) {
                match emit_snapshot(&audit_dir, &keys_dir, &lanes, DEFAULT_WINDOW_H, now) {
                    Ok(_) => last = Some((states, now)),
                    Err(e) => eprintln!("kriya-console: coverage snapshot failed: {e}"),
                }
            }
            std::thread::sleep(TICK);
        }
    });
}

/// The Coverage view's read model (pure — no writes; the heartbeat thread owns emission).
#[tauri::command]
pub fn coverage_status() -> CoverageStatus {
    let audit_dir = default_audit_dir();
    let lanes = classify(
        &audit_dir,
        claude_settings_path().as_deref(),
        now_ms(),
        DEFAULT_WINDOW_H * 60 * 60 * 1000,
    );
    let log = audit_dir.join("coverage.jsonl");
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let snapshots = text.lines().filter(|l| !l.trim().is_empty()).count();
    let last_snapshot_ms = seed_last_emitted(&log).map(|(_, ts)| ts);
    let cc_hook = hook_configured(claude_settings_path().as_deref());
    let (hermes_hook, hermes_gateway) = hermes_flags();
    let agents = classify_agents(
        &audit_dir,
        now_ms(),
        DEFAULT_WINDOW_H * 60 * 60 * 1000,
        cc_hook,
        hermes_hook,
        hermes_gateway,
    );
    CoverageStatus {
        window_h: DEFAULT_WINDOW_H,
        lanes,
        last_snapshot_ms,
        snapshot_chain_ok: snapshots == 0 || chain_break(&text).is_none(),
        snapshots,
        agents,
    }
}

// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kriya_verify::verify_value;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kriya-coverage-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A minimal receipt-shaped line (classification only reads ts_ms + action_id; signatures are
    /// the verifier tests' business).
    fn line(action_id: &str, ts_ms: u64) -> String {
        json!({ "step_id": "s", "action_id": action_id, "params": {}, "success": true, "ts_ms": ts_ms })
            .to_string()
    }

    fn write_log(dir: &Path, name: &str, lines: &[String]) {
        std::fs::write(dir.join(name), lines.join("\n") + "\n").unwrap();
    }

    const NOW: u64 = 1_800_000_000_000;
    const HOUR: u64 = 60 * 60 * 1000;
    const WINDOW: u64 = 24 * HOUR;

    #[test]
    fn empty_dir_is_all_grey() {
        let dir = tmp("grey");
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes.len(), 6);
        for id in LANES {
            assert_eq!(lanes[id].state, LaneState::Grey, "{id} must be GREY on a bare machine");
        }
    }

    #[test]
    fn hook_receipts_green_claude_code_and_mcp_lanes() {
        let dir = tmp("cc");
        write_log(
            &dir,
            "claude-code.jsonl",
            &[
                line("claude-code__bash", NOW - HOUR),
                line("claude-code__mcp__github__create_issue", NOW - 2 * HOUR),
            ],
        );
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["claude-code-tools"].state, LaneState::Green);
        assert_eq!(lanes["remote-mcp"].state, LaneState::Green, "mcp__ receipts light the remote-mcp lane");
        assert_eq!(lanes["remote-mcp"].source.as_deref(), Some("hook.claude-code"));
        assert_eq!(lanes["local-stdio-mcp"].state, LaneState::Grey);
        // A stale chain (evidence exists, outside the window) is configured-but-silent, not covered.
        write_log(&dir, "claude-code.jsonl", &[line("claude-code__bash", NOW - 30 * HOUR)]);
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["claude-code-tools"].state, LaneState::Amber);
    }

    #[test]
    fn egress_ledger_chip_reflects_kriya_io_egress_receipts_in_window_only_on_the_three_lanes() {
        let dir = tmp("egress-ledger");
        // claude-code.jsonl: a governed call AND a fresh kriya.io.egress.* receipt.
        write_log(
            &dir,
            "claude-code.jsonl",
            &[
                line("claude-code__mcp__github__list_issues", NOW - HOUR),
                line("kriya.io.egress.http.allow", NOW - HOUR),
            ],
        );
        // gateway.jsonl (local-stdio-mcp): configured, but NO kriya.io.egress.* receipt in window.
        write_log(&dir, "gateway.jsonl", &[line("get_widget", NOW - HOUR)]);
        let lanes = classify(&dir, None, NOW, WINDOW);

        assert_eq!(
            lanes["claude-code-tools"].egress_ledger,
            Some(true),
            "a fresh kriya.io.egress.* receipt lights the chip ON"
        );
        assert_eq!(
            lanes["remote-mcp"].egress_ledger,
            Some(true),
            "remote-mcp shares the claude-code.jsonl scan"
        );
        assert_eq!(
            lanes["local-stdio-mcp"].egress_ledger,
            Some(false),
            "configured but no kriya.io.egress.* receipt observed in window -> chip OFF, not absent"
        );
        // Lanes the egress ledger deliberately doesn't apply to stay None (no chip rendered).
        assert_eq!(lanes["desktop-apps"].egress_ledger, None);
        assert_eq!(lanes["raw-file-exec"].egress_ledger, None);
        assert_eq!(
            lanes["raw-egress"].egress_ledger, None,
            "raw-egress must NEVER be colored by the governed-lane ledger — that's E2's lane"
        );

        // A stale (out-of-window) kriya.io.egress.* receipt reads as OFF, not ON.
        write_log(
            &dir,
            "claude-code.jsonl",
            &[
                line("claude-code__mcp__github__list_issues", NOW - HOUR),
                line("kriya.io.egress.http.allow", NOW - 30 * HOUR),
            ],
        );
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["claude-code-tools"].egress_ledger, Some(false));

        // A lane with NO kriya.io.egress.* traffic at all but not configured (grey) still reports None
        // — the chip only appears once the lane itself is at least configured/present, matching how
        // `source`/`files` behave.
        let _ = std::fs::remove_dir_all(&dir);
        let dir2 = tmp("egress-ledger-unconfigured");
        let lanes = classify(&dir2, None, NOW, WINDOW);
        assert_eq!(lanes["local-stdio-mcp"].egress_ledger, None);
        let _ = std::fs::remove_dir_all(&dir2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn contained_session_chip_reflects_kriya_io_run_receipts_only_on_raw_egress() {
        let dir = tmp("contained");
        // A gateway chain (local-stdio-mcp) with its own egress receipt, unrelated to EG-C.
        write_log(&dir, "gateway.jsonl", &[line("kriya.io.egress.http.allow", NOW - HOUR)]);
        // An EG-C `kriya-gateway run --` session: default filename `run.jsonl` (doc 24 EG-C).
        write_log(
            &dir,
            "run.jsonl",
            &[
                line("kriya.io.run.start", NOW - HOUR),
                line("kriya.io.egress.http.deny", NOW - HOUR),
                line("kriya.io.run.exit", NOW - HOUR),
            ],
        );
        let lanes = classify(&dir, None, NOW, WINDOW);

        assert_eq!(
            lanes["raw-egress"].contained_session,
            Some(true),
            "a fresh run.start/exit lights the chip ON, on raw-egress only"
        );
        assert_eq!(
            lanes["raw-egress"].state,
            LaneState::Grey,
            "contained_session must NEVER change raw-egress's own state — that stays governed \
             entirely by E2 host-watcher evidence (none present here)"
        );
        assert_eq!(
            lanes["raw-egress"].egress_ledger, None,
            "contained_session is additive; it must not also set the (deliberately absent) \
             egress_ledger chip on raw-egress"
        );
        // Every other lane stays untouched by EG-C's receipts.
        assert_eq!(lanes["claude-code-tools"].contained_session, None);
        assert_eq!(lanes["remote-mcp"].contained_session, None);
        assert_eq!(lanes["local-stdio-mcp"].contained_session, None);
        assert_eq!(lanes["desktop-apps"].contained_session, None);
        assert_eq!(lanes["raw-file-exec"].contained_session, None);
        // run.jsonl must NOT be miscounted as a local-stdio-mcp gateway chain — its own
        // kriya.io.egress.* receipt must not spuriously light that lane's ledger chip.
        assert_eq!(
            lanes["local-stdio-mcp"].egress_ledger,
            Some(true),
            "gateway.jsonl's own receipt still lights the chip"
        );
        assert_eq!(
            lanes["local-stdio-mcp"].files, 1,
            "run.jsonl must be bucketed separately from gateway.jsonl, not counted as a second \
             local-stdio-mcp chain file"
        );

        // A stale (out-of-window) run session reads as a present-but-OFF chip, not absent.
        write_log(
            &dir,
            "run.jsonl",
            &[
                line("kriya.io.run.start", NOW - 30 * HOUR),
                line("kriya.io.run.exit", NOW - 30 * HOUR),
            ],
        );
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["raw-egress"].contained_session, Some(false));

        // No run.jsonl at all -> None (never ran), not Some(false).
        let _ = std::fs::remove_dir_all(&dir);
        let dir2 = tmp("contained-none");
        let lanes = classify(&dir2, None, NOW, WINDOW);
        assert_eq!(lanes["raw-egress"].contained_session, None);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn broker_receipts_green_the_remote_mcp_lane() {
        let dir = tmp("broker");
        // The W2 broker writes one broker.jsonl for all upstreams; a fresh receipt greens remote-mcp
        // even with no Claude Code hook in sight (Claude Desktop has no hook seam).
        write_log(&dir, "broker.jsonl", &[line("github__list_issues", NOW - HOUR)]);
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["remote-mcp"].state, LaneState::Green);
        assert_eq!(lanes["remote-mcp"].source.as_deref(), Some("broker"));
        // The broker is not a Claude Code lane nor a per-server gateway (local-stdio) lane.
        assert_eq!(lanes["claude-code-tools"].state, LaneState::Grey);
        assert_eq!(lanes["local-stdio-mcp"].state, LaneState::Grey);
    }

    #[test]
    fn hook_config_without_receipts_is_amber() {
        let dir = tmp("amber");
        let settings = dir.join("settings.json");
        std::fs::write(
            &settings,
            r#"{ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "kriya-hook pre" }] }] } }"#,
        )
        .unwrap();
        let lanes = classify(&dir, Some(&settings), NOW, WINDOW);
        assert_eq!(lanes["claude-code-tools"].state, LaneState::Amber, "wired but silent");
        assert_eq!(lanes["remote-mcp"].state, LaneState::Amber);
        assert_eq!(lanes["desktop-apps"].state, LaneState::Grey, "hook config says nothing about AX");
    }

    #[test]
    fn gateway_and_desktop_files_classify_into_their_lanes() {
        let dir = tmp("lanes");
        write_log(&dir, "github-server.jsonl", &[line("create_issue", NOW - HOUR)]);
        write_log(&dir, "reach-in-numbers.jsonl", &[line("press_button_save", NOW - HOUR)]);
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["local-stdio-mcp"].state, LaneState::Green);
        assert_eq!(lanes["local-stdio-mcp"].files, 1);
        assert_eq!(lanes["desktop-apps"].state, LaneState::Green);
        assert_eq!(lanes["raw-file-exec"].state, LaneState::Grey);
    }

    #[test]
    fn watcher_heartbeat_greens_only_the_lanes_its_chain_covers() {
        let dir = tmp("watch");
        // netext covers egress only: a fresh heartbeat greens raw-egress, never raw-file-exec.
        write_log(&dir, "watch-netext.jsonl", &[line("kriya.watch.heartbeat", NOW - HOUR)]);
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["raw-egress"].state, LaneState::Green, "alive + quiet ⇒ covered");
        assert_eq!(lanes["raw-file-exec"].state, LaneState::Grey);

        // A tetragon chain with real events + stale heartbeat: events green both raw lanes.
        write_log(
            &dir,
            "watch-tetragon.jsonl",
            &[
                line("kriya.watch.proc.exec", NOW - HOUR),
                line("kriya.watch.net.connect", NOW - HOUR),
            ],
        );
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["raw-file-exec"].state, LaneState::Green);
        assert_eq!(lanes["raw-egress"].state, LaneState::Green);

        // Kill the watcher (stale everything): covering chains exist ⇒ AMBER, not GREY — the
        // heartbeat-gap behavior the Coverage Map sells.
        write_log(&dir, "watch-tetragon.jsonl", &[line("kriya.watch.proc.exec", NOW - 30 * HOUR)]);
        write_log(&dir, "watch-netext.jsonl", &[line("kriya.watch.heartbeat", NOW - 30 * HOUR)]);
        let lanes = classify(&dir, None, NOW, WINDOW);
        assert_eq!(lanes["raw-file-exec"].state, LaneState::Amber);
        assert_eq!(lanes["raw-egress"].state, LaneState::Amber);
    }

    // --- Multi-agent coverage view (GA-2) ---------------------------------------------------

    fn line_actor(action_id: &str, ts_ms: u64, agent: &str) -> String {
        json!({ "step_id": "s", "action_id": action_id, "params": {}, "success": true, "ts_ms": ts_ms, "actor": { "agent": agent, "user": "u" } })
            .to_string()
    }

    fn agent_lane<'a>(cov: &'a [AgentCoverage], agent: &str, lane_id: &str) -> &'a AgentLane {
        cov.iter()
            .find(|a| a.agent == agent)
            .unwrap_or_else(|| panic!("no agent {agent}"))
            .lanes
            .iter()
            .find(|l| l.id == lane_id)
            .unwrap_or_else(|| panic!("no lane {lane_id} for {agent}"))
    }

    #[test]
    fn agents_map_claude_code_and_hermes_on_one_substrate() {
        let dir = tmp("agents");
        write_log(
            &dir,
            "claude-code.jsonl",
            &[
                line("claude-code__bash", NOW - HOUR),
                line("claude-code__mcp__github__create_issue", NOW - HOUR),
            ],
        );
        // A gateway per-server chain attributed to Hermes (govern-all wraps its stdio MCP).
        write_log(&dir, "fs-server.jsonl", &[line_actor("read_file", NOW - HOUR, "hermes")]);

        let cov = classify_agents(&dir, NOW, WINDOW, false, false, false);
        assert_eq!(cov.len(), 2, "Claude Code and Hermes lane-groups");
        assert_eq!(agent_lane(&cov, "claude-code", "native-tools").state, LaneState::Green);
        assert_eq!(agent_lane(&cov, "claude-code", "attached-mcp").state, LaneState::Green);
        assert_eq!(agent_lane(&cov, "hermes", "mcp").state, LaneState::Green);
        assert_eq!(agent_lane(&cov, "hermes", "mcp").source.as_deref(), Some("gateway"));
        // Hermes native tools stay honestly GREY (hook demand-pulled) with a locus reason.
        let hn = agent_lane(&cov, "hermes", "native-tools");
        assert_eq!(hn.state, LaneState::Grey);
        assert!(hn.locus.as_ref().unwrap().contains("kriya-hermes-hook"));
        // Both agents carry a grey cloud lane with a locus.
        assert_eq!(agent_lane(&cov, "claude-code", "cloud").state, LaneState::Grey);
        assert!(agent_lane(&cov, "claude-code", "cloud").locus.is_some());
        assert!(agent_lane(&cov, "hermes", "cloud").locus.is_some());
    }

    #[test]
    fn agents_hermes_native_greens_from_hermes_hook_log() {
        let dir = tmp("hermes-native");
        write_log(&dir, "hermes.jsonl", &[line("hermes__terminal", NOW - HOUR)]);
        let cov = classify_agents(&dir, NOW, WINDOW, false, false, false);
        let hn = agent_lane(&cov, "hermes", "native-tools");
        assert_eq!(hn.state, LaneState::Green);
        assert_eq!(hn.source.as_deref(), Some("hook.hermes"));
        assert!(hn.locus.is_none(), "a covered lane needs no out-of-scope locus");
    }

    #[test]
    fn agents_amber_when_configured_but_silent() {
        let dir = tmp("agents-amber");
        let cov = classify_agents(&dir, NOW, WINDOW, /*cc_hook*/ true, /*hermes_hook*/ false, /*hermes_gateway*/ true);
        assert_eq!(agent_lane(&cov, "claude-code", "native-tools").state, LaneState::Amber);
        assert_eq!(agent_lane(&cov, "claude-code", "attached-mcp").state, LaneState::Amber);
        assert_eq!(agent_lane(&cov, "hermes", "mcp").state, LaneState::Amber);
        assert_eq!(agent_lane(&cov, "hermes", "native-tools").state, LaneState::Grey, "hook still deferred");
    }

    /// Regression (found live, 2026-07-08): a real Hermes config's servers live under `mcp_servers`
    /// (snake_case, verified against `hermes_cli/mcp_config.py`) — the ORIGINAL `hermes_flags` looked
    /// up Claude's `mcpServers` (camelCase) for every client, so a genuinely gateway-wrapped Hermes
    /// server was invisible: this flag stayed false, and the Coverage view's Hermes MCP lane silently
    /// stayed GREY / never went AMBER-then-GREEN, exactly mirroring the "not auto-detected in Govern
    /// everything" symptom (govern.rs's `servers_ref` had the identical bug).
    #[test]
    fn hermes_flags_reads_the_real_snake_case_mcp_servers_key() {
        let dir = tmp("hermes-flags");
        let path = dir.join("config.yaml");

        // No file yet ⇒ both false, not an error.
        assert_eq!(hermes_flags_from(&path), (false, false));

        // A real Hermes config: a gateway-wrapped server under `mcp_servers`, no hooks block yet.
        std::fs::write(
            &path,
            "mcp_servers:\n  fs:\n    command: /opt/kriya-gateway\n    args: [proxy, --, uvx, mcp-server-fs]\n",
        )
        .unwrap();
        assert_eq!(hermes_flags_from(&path), (false, true), "gateway flag must read mcp_servers, not mcpServers");

        // The camelCase key some earlier code (and this file's own original bug) assumed must NOT
        // be read as Hermes' servers — proves the two clients' keys are genuinely distinct.
        std::fs::write(
            &path,
            "mcpServers:\n  fs:\n    command: /opt/kriya-gateway\n    args: [proxy, --, uvx, mcp-server-fs]\n",
        )
        .unwrap();
        assert_eq!(hermes_flags_from(&path), (false, false), "camelCase mcpServers must not be recognized");

        // Add the (not-yet-built) hermes-hook block alongside a real mcp_servers map — both flags true.
        std::fs::write(
            &path,
            "hooks:\n  pre_tool_call: kriya-hermes-hook pre\nmcp_servers:\n  fs:\n    command: /opt/kriya-gateway\n    args: [proxy]\n",
        )
        .unwrap();
        assert_eq!(hermes_flags_from(&path), (true, true));
    }

    #[test]
    fn agents_empty_dir_is_all_grey_with_cloud_locus() {
        let dir = tmp("agents-grey");
        let cov = classify_agents(&dir, NOW, WINDOW, false, false, false);
        for a in &cov {
            for l in &a.lanes {
                assert_eq!(l.state, LaneState::Grey, "{}/{} must be grey", a.agent, l.id);
            }
            // The cloud lane always carries a locus reason.
            assert!(agent_lane(&cov, &a.agent, "cloud").locus.is_some());
        }
    }

    /// W1-5 parity: a Console-signed snapshot must verify in the SHARED verifier (`kriya-verify`,
    /// the same code the TS spine parity-tests against and `kriya-audit` ships), chain across
    /// emissions, and expose tampering — zero new trust machinery.
    #[test]
    fn snapshots_sign_chain_and_verify_in_the_shared_verifier() {
        let dir = tmp("sign");
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let lanes = classify(&dir, None, NOW, WINDOW); // all grey — fine, states are the payload

        let l1 = emit_snapshot(&dir, &keys, &lanes, 24, NOW).unwrap();
        let l2 = emit_snapshot(&dir, &keys, &lanes, 24, NOW + 1000).unwrap();

        let v1: Value = serde_json::from_str(&l1).unwrap();
        let v2: Value = serde_json::from_str(&l2).unwrap();
        verify_value(&v1).expect("snapshot 1 verifies in kriya-verify");
        verify_value(&v2).expect("snapshot 2 verifies in kriya-verify");
        assert_eq!(v1["public_key"], v2["public_key"], "one persisted coverage identity");
        assert!(v1.get("prev_hash").is_none(), "genesis snapshot is unchained");
        assert_eq!(
            v2["prev_hash"].as_str().unwrap(),
            sha256_hex(l1.as_bytes()),
            "snapshot 2 chains to the exact bytes of snapshot 1"
        );

        let text = std::fs::read_to_string(dir.join("coverage.jsonl")).unwrap();
        assert_eq!(chain_break(&text), None, "coverage chain intact");

        // Tamper with a lane state → the signature must fail in the shared verifier.
        let mut forged = v2.clone();
        forged["params"]["lanes"]["raw-egress"]["state"] = json!("green");
        assert!(verify_value(&forged).is_err(), "a retconned GREEN must not verify");
    }

    #[test]
    fn emission_is_rate_limited_to_state_changes_and_daily_liveness() {
        let mut states: BTreeMap<String, LaneState> =
            LANES.iter().map(|l| (l.to_string(), LaneState::Grey)).collect();
        assert!(should_emit(None, &states, NOW), "first ever snapshot always emits");

        let prev = (states.clone(), NOW);
        assert!(
            !should_emit(Some(&prev), &states, NOW + HOUR),
            "unchanged states within 24h stay quiet"
        );
        assert!(
            should_emit(Some(&prev), &states, NOW + 25 * HOUR),
            "daily liveness re-attest"
        );
        states.insert("raw-egress".into(), LaneState::Green);
        assert!(
            should_emit(Some(&prev), &states, NOW + HOUR),
            "a lane transition attests immediately"
        );
    }

    /// W1-8 fixture generator — run explicitly to (re)mint the committed TS-parity fixture:
    /// `cargo test --lib coverage::tests::generate_ts_parity_fixture -- --ignored`
    /// Writes two REAL console-signed snapshots (fresh key, chained) to
    /// `test/fixtures/coverage-sample.jsonl`; `test/coverage-fixture.test.ts` then proves the TS
    /// verifier re-derives byte-identical signed bytes for console-signed receipts. Ignored so the
    /// normal suite never touches the repo tree.
    #[test]
    #[ignore]
    fn generate_ts_parity_fixture() {
        let dir = tmp("fixture");
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        // A map with real variety: one green lane via a fresh receipt, the rest grey.
        write_log(&dir, "claude-code.jsonl", &[line("claude-code__bash", NOW - HOUR)]);
        let lanes = classify(&dir, None, NOW, WINDOW);
        emit_snapshot(&dir, &keys, &lanes, 24, NOW).unwrap();
        emit_snapshot(&dir, &keys, &lanes, 24, NOW + 3600_000).unwrap();

        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test/fixtures/coverage-sample.jsonl");
        std::fs::create_dir_all(out.parent().unwrap()).unwrap();
        std::fs::copy(dir.join("coverage.jsonl"), &out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_recovers_last_emitted_state_from_the_chain_tail() {
        let dir = tmp("seed");
        let keys = dir.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let lanes = classify(&dir, None, NOW, WINDOW);
        emit_snapshot(&dir, &keys, &lanes, 24, NOW).unwrap();

        let (states, ts) = seed_last_emitted(&dir.join("coverage.jsonl")).expect("tail parses");
        assert_eq!(ts, NOW);
        assert_eq!(states, states_of(&lanes), "restart must not re-attest an unchanged map");
    }
}
