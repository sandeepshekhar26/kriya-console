// Pure view-logic for the "Governed surface" dashboard (GA-1) — grouping, summarizing, and the
// state → label/badge mapping. Kept framework-free so `test/govern-view.test.ts` can exercise it
// without React. The ConnectionsView renders these; nothing here touches Tauri or the DOM.

import type { GovernableSurface, GovernState, GovernTarget } from "./tauri";

/** Render order for the detected agents (unknown agents append after, stable). */
export const AGENT_ORDER = ["claude-code", "claude-desktop", "hermes", "desktop"] as const;

export const AGENT_LABEL: Record<string, string> = {
  "claude-code": "Claude Code",
  "claude-desktop": "Claude Desktop",
  hermes: "Hermes",
  desktop: "Desktop apps",
};

export function agentLabel(agent: string): string {
  return AGENT_LABEL[agent] ?? agent;
}

export const STATE_LABEL: Record<GovernState, string> = {
  governed: "Governed",
  ungoverned: "Ungoverned",
  "needs-permission": "Needs permission",
  "out-of-scope-cloud": "Cloud · out of scope",
};

/** Maps a govern state to an existing `.badge` modifier (ok/warn/"" — grey). */
export const STATE_BADGE: Record<GovernState, string> = {
  governed: "ok",
  ungoverned: "warn",
  "needs-permission": "warn",
  "out-of-scope-cloud": "",
};

export interface SurfaceSummary {
  governed: number;
  /** Ungoverned targets that can be wired right now (their seam binary is bundled). */
  ungoverned: number;
  needsPermission: number;
  outOfScope: number;
  total: number;
}

/** Can this target be wired now (ungoverned AND its seam binary is available)? */
export function isWireable(target: GovernTarget, surface: GovernableSurface): boolean {
  if (target.state !== "ungoverned") return false;
  if (target.kind === "hook") return surface.hookAvailable;
  if (target.kind === "mcp-server") return surface.gatewayAvailable;
  return false;
}

export function summarize(surface: GovernableSurface): SurfaceSummary {
  const s: SurfaceSummary = {
    governed: 0,
    ungoverned: 0,
    needsPermission: 0,
    outOfScope: 0,
    total: surface.targets.length,
  };
  for (const t of surface.targets) {
    if (t.state === "governed") s.governed++;
    else if (t.state === "ungoverned") s.ungoverned++;
    else if (t.state === "needs-permission") s.needsPermission++;
    else if (t.state === "out-of-scope-cloud") s.outOfScope++;
  }
  return s;
}

/** How many targets the "Govern everything" button will wire (ungoverned + seam available). */
export function wireableCount(surface: GovernableSurface): number {
  return surface.targets.filter((t) => isWireable(t, surface)).length;
}

export interface AgentGroup {
  agent: string;
  label: string;
  targets: GovernTarget[];
}

/** Group the flat target list by agent in a stable render order. */
export function groupByAgent(targets: GovernTarget[]): AgentGroup[] {
  const groups = new Map<string, GovernTarget[]>();
  for (const t of targets) {
    const arr = groups.get(t.agent) ?? [];
    arr.push(t);
    groups.set(t.agent, arr);
  }
  const ordered: AgentGroup[] = [];
  const seen = new Set<string>();
  for (const agent of AGENT_ORDER) {
    const arr = groups.get(agent);
    if (arr) {
      ordered.push({ agent, label: agentLabel(agent), targets: arr });
      seen.add(agent);
    }
  }
  for (const [agent, arr] of groups) {
    if (!seen.has(agent)) ordered.push({ agent, label: agentLabel(agent), targets: arr });
  }
  return ordered;
}
