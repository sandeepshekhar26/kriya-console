import { describe, it, expect } from "vitest";
import { groupByAgent, summarize, wireableCount, isWireable, STATE_BADGE, STATE_LABEL } from "../src/lib/govern-view";
import type { GovernableSurface, GovernTarget } from "../src/lib/tauri";

const t = (id: string, agent: string, kind: string, state: GovernTarget["state"]): GovernTarget => ({
  id,
  agent,
  kind,
  seam: kind === "hook" ? "hook" : "gateway",
  state,
  label: id,
  detail: "d",
});

const surface = (
  targets: GovernTarget[],
  hookAvailable = true,
  gatewayAvailable = true,
  hermesHookAvailable = true,
): GovernableSurface => ({
  targets,
  hookAvailable,
  gatewayAvailable,
  hermesHookAvailable,
  axTrusted: false,
  desktopCandidates: [],
});

describe("govern-view helpers", () => {
  const targets = [
    t("claude-code:hook", "claude-code", "hook", "ungoverned"),
    t("claude-desktop:mcp-server:github", "claude-desktop", "mcp-server", "ungoverned"),
    t("claude-desktop:mcp-server:fs", "claude-desktop", "mcp-server", "governed"),
    t("claude-desktop:mcp-server:linear", "claude-desktop", "mcp-server", "out-of-scope-cloud"),
    t("hermes:hook", "hermes", "hook", "ungoverned"),
    t("hermes:mcp-server:x", "hermes", "mcp-server", "ungoverned"),
    t("desktop:desktop-apps", "desktop", "desktop-apps", "needs-permission"),
  ];

  it("summarize counts each state", () => {
    const s = summarize(surface(targets));
    expect(s).toEqual({ governed: 1, ungoverned: 4, needsPermission: 1, outOfScope: 1, total: 7 });
  });

  it("wireableCount counts ungoverned targets whose seam binary is available", () => {
    expect(wireableCount(surface(targets))).toBe(4); // claude-code:hook + github + hermes:hook + hermes:x
    // Without the Claude Code hook binary, only that hook target drops — Hermes' hook is unaffected.
    expect(wireableCount(surface(targets, /*hook*/ false))).toBe(3);
    // Without the gateway, both mcp-server targets drop out; both hook targets are unaffected.
    expect(wireableCount(surface(targets, true, /*gateway*/ false))).toBe(2);
    // Without the Hermes hook binary specifically, only hermes:hook drops — Claude Code's is unaffected.
    expect(wireableCount(surface(targets, true, true, /*hermesHook*/ false))).toBe(3);
  });

  it("isWireable is false for governed / cloud / needs-permission and desktop", () => {
    expect(isWireable(t("a", "claude-code", "hook", "ungoverned"), surface([]))).toBe(true);
    expect(isWireable(t("a", "claude-desktop", "mcp-server", "governed"), surface([]))).toBe(false);
    expect(isWireable(t("a", "x", "mcp-server", "out-of-scope-cloud"), surface([]))).toBe(false);
    expect(isWireable(t("a", "desktop", "desktop-apps", "needs-permission"), surface([]))).toBe(false);
  });

  it("isWireable gates Claude Code's and Hermes' hook targets on independent availability flags", () => {
    const s = surface([], true, true, false); // hookAvailable=true, hermesHookAvailable=false
    expect(isWireable(t("a", "claude-code", "hook", "ungoverned"), s)).toBe(true);
    expect(isWireable(t("a", "hermes", "hook", "ungoverned"), s)).toBe(false);
  });

  it("groupByAgent groups in a stable order and keeps rows together", () => {
    const groups = groupByAgent(targets);
    expect(groups.map((g) => g.agent)).toEqual(["claude-code", "claude-desktop", "hermes", "desktop"]);
    expect(groups[1]!.label).toBe("Claude Desktop");
    expect(groups[1]!.targets).toHaveLength(3);
    expect(groups[2]!.targets).toHaveLength(2); // hermes:hook + hermes:mcp-server:x
  });

  it("state → badge/label mapping covers every state", () => {
    expect(STATE_BADGE.governed).toBe("ok");
    expect(STATE_BADGE["out-of-scope-cloud"]).toBe("");
    expect(STATE_LABEL.ungoverned).toBe("Ungoverned");
    expect(STATE_LABEL["needs-permission"]).toBe("Needs permission");
  });
});
