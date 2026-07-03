import { useCallback, useEffect, useState } from "react";
import { coverageStatus, isTauri, onAuditChanged, type CoverageStatus, type LaneInfo, type LaneState } from "../lib/tauri";
import { Icon } from "../components/Icon";
import type { View } from "../components/Sidebar";

/**
 * Coverage Map (W1-7, doc-20 §4) — completeness as a first-class, signed surface. Six fixed lanes,
 * three states: GREEN (configured + evidence in window) · AMBER (configured but silent) · GREY
 * (uncovered — events there leave no receipt). Every non-green lane carries its one fix. The map
 * itself is attested: the backend signs a `kriya.coverage.snapshot` into its own hash chain on any
 * state change (and daily), so a silenced Console or stopped watcher is visible by absence — the
 * footer shows that chain's health.
 */

type LaneMeta = {
  id: string;
  title: string;
  desc: string;
  /** The one fix, by non-green state. */
  fix: { amber: string; grey: string };
  /** Optional in-app destination for the fix. */
  go?: View;
};

const LANE_META: LaneMeta[] = [
  {
    id: "claude-code-tools",
    title: "Claude Code tools",
    desc: "Native tools (Bash, Edit, Write, …) signed per call through the kriya-hook seam.",
    fix: {
      amber: "Hook is wired but silent — run a Claude Code session, or check ~/.claude/settings.json still calls kriya-hook.",
      grey: "Install the hook: cargo install kriya --bin kriya-hook --no-default-features, then paste the two-line hooks block into ~/.claude/settings.json.",
    },
  },
  {
    id: "remote-mcp",
    title: "Remote & attached MCP",
    desc: "MCP servers attached straight to Claude Code (mcp__server__tool), observed by the same hook — gate them per server with one policy glob.",
    fix: {
      amber: "The hook would record MCP calls, but none seen in window — attach a server or exercise one.",
      grey: "Install kriya-hook (covers every MCP server Claude Code touches); the W2 broker extends this to hook-less clients.",
    },
  },
  {
    id: "local-stdio-mcp",
    title: "Local stdio MCP",
    desc: "Servers wrapped by kriya-gateway — every tool call from any MCP client routes policy → approval → signed receipt.",
    fix: {
      amber: "A gateway chain exists but is silent — start the wrapped server or check the client config.",
      grey: "Wrap a server: kriya-gateway proxy -- <server-cmd>, or add one from Connections.",
    },
    go: "connections",
  },
  {
    id: "desktop-apps",
    title: "Desktop apps",
    desc: "No-API apps governed via reach-in (accessibility tree) or computer-use, multiplexed by the router.",
    fix: {
      amber: "A desktop front is configured but silent — drive the app once, or re-check macOS permissions.",
      grey: "Add a desktop connection (reach-in / computer-use) from Connections.",
    },
    go: "connections",
  },
  {
    id: "raw-file-exec",
    title: "Raw file & exec",
    desc: "Out-of-channel writes, spawns and execs of the governed agent subtree — the watcher rungs (Tetragon on Linux; Endpoint Security on macOS, entitlement-gated).",
    fix: {
      amber: "A watcher chain exists but its heartbeat is stale — restart kriyawatch (a gap here is itself evidence).",
      grey: "No watcher on this machine yet. Linux: install kriyawatch (Tetragon). macOS: ships with the watcher rungs (W3–W6).",
    },
  },
  {
    id: "raw-egress",
    title: "Raw egress",
    desc: "Sockets, DNS and per-flow process attribution — regardless of which channel the agent used.",
    fix: {
      amber: "Egress watcher configured but silent past its heartbeat — restart it; the chain records the gap.",
      grey: "No egress watcher yet. Linux: kriyawatch (Tetragon). macOS: launch-under egress pin (W4) or the system extension (W5).",
    },
  },
];

/** Browser/preview status so the design renders outside the desktop app (ConnectionsView idiom). */
const PREVIEW_STATUS: CoverageStatus = {
  windowH: 24,
  lanes: {
    "claude-code-tools": { state: "green", source: "hook.claude-code", lastReceiptMs: Date.now() - 40 * 60e3, files: 1 },
    "remote-mcp": { state: "amber", source: "hook.claude-code", files: 0 },
    "local-stdio-mcp": { state: "green", source: "gateway", lastReceiptMs: Date.now() - 3 * 3600e3, files: 2 },
    "desktop-apps": { state: "amber", source: "reach-in/computer-use", lastReceiptMs: Date.now() - 30 * 3600e3, files: 1 },
    "raw-file-exec": { state: "grey", files: 0 },
    "raw-egress": { state: "grey", files: 0 },
  },
  lastSnapshotMs: Date.now() - 2 * 3600e3,
  snapshotChainOk: true,
  snapshots: 14,
};

function ago(ms?: number | null): string {
  if (!ms) return "never";
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 48 * 3600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

const STATE_LABEL: Record<LaneState, string> = {
  green: "Covered",
  amber: "Configured · silent",
  grey: "Uncovered",
};
const STATE_BADGE: Record<LaneState, string> = { green: "ok", amber: "warn", grey: "" };

export function CoverageView({ onNavigate }: { onNavigate: (v: View) => void }) {
  const live = isTauri();
  const [status, setStatus] = useState<CoverageStatus | null>(live ? null : PREVIEW_STATUS);

  const refresh = useCallback(() => {
    if (!live) return;
    coverageStatus().then(setStatus).catch(() => {});
  }, [live]);

  useEffect(() => {
    refresh();
    if (!live) return;
    let unlisten: (() => void) | undefined;
    onAuditChanged(refresh).then((u) => (unlisten = u));
    return () => unlisten?.();
  }, [live, refresh]);

  const lanes = status?.lanes ?? {};
  const counts = { green: 0, amber: 0, grey: 0 } as Record<LaneState, number>;
  for (const m of LANE_META) {
    const s = lanes[m.id]?.state;
    if (s) counts[s]++;
  }

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Coverage</h1>
          <p className="page-sub">
            What on this machine leaves a signed receipt — and, just as loudly, what doesn't. Each
            lane is evidence-classified over the last {status?.windowH ?? 24}h; the map itself is
            signed into a hash chain, so "green" can't be retconned and a stopped watcher is visible
            by absence.
          </p>
        </div>
        <div className="page-actions">
          <span className="pill">
            <span className="dot ok" /> {counts.green} covered
          </span>
          <span className="pill warn">{counts.amber} silent</span>
          <span className="pill">{counts.grey} uncovered</span>
        </div>
      </header>

      <section className="panel-grid">
        {LANE_META.map((meta) => {
          const info: LaneInfo | undefined = lanes[meta.id];
          const state: LaneState = info?.state ?? "grey";
          return (
            <div className="panel" key={meta.id}>
              <div className="panel-head">
                <h2>{meta.title}</h2>
                <span className={`badge ${STATE_BADGE[state]}`}>{STATE_LABEL[state]}</span>
              </div>
              <p className="muted small" style={{ margin: "0 0 10px" }}>{meta.desc}</p>
              <p className="muted small" style={{ margin: 0 }}>
                {info?.source ? <>via <code>{info.source}</code> · </> : null}
                last receipt {ago(info?.lastReceiptMs)}
                {info && info.files > 0 ? <> · {info.files} chain file{info.files > 1 ? "s" : ""}</> : null}
              </p>
              {state !== "green" && (
                <p className="panel-note">
                  {meta.fix[state === "amber" ? "amber" : "grey"]}
                  {meta.go && (
                    <>
                      {" "}
                      <button className="link" onClick={() => onNavigate(meta.go!)}>
                        Open Connections <Icon name="arrow-right" size={12} />
                      </button>
                    </>
                  )}
                </p>
              )}
            </div>
          );
        })}
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>Signed coverage heartbeat</h2>
          <span className={`badge ${status?.snapshotChainOk ? "ok" : "bad"}`}>
            {status?.snapshotChainOk ? "chain intact" : "chain broken"}
          </span>
        </div>
        <p className="muted small" style={{ margin: 0 }}>
          {status?.snapshots ?? 0} snapshot{(status?.snapshots ?? 0) === 1 ? "" : "s"} in{" "}
          <code>~/.kriya/audit/coverage.jsonl</code> · last signed {ago(status?.lastSnapshotMs)} ·
          re-attested on every lane change and at least daily. Verify it like any receipt:{" "}
          <code>kriya-audit ~/.kriya/audit/coverage.jsonl</code>.
        </p>
      </section>
    </div>
  );
}
