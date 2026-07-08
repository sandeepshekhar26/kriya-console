import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { GovernableSurface, GovernTarget, GovernState } from "../src/lib/tauri";

// The committed fixture is emitted (and asserted against) by the Rust side in
// `src-tauri/src/govern.rs::surface_serializes_to_the_committed_ts_parity_fixture`. Loading it here
// as the typed `GovernableSurface` proves the two serialized shapes agree: if the Rust struct's
// serde field names drift, its own test fails; if the TS interface drifts incompatibly, this file
// fails to type-check / assert. One fixture, both sides.
const surface = JSON.parse(
  readFileSync(fileURLToPath(new URL("./fixtures/governable-surface-sample.json", import.meta.url)), "utf8"),
) as GovernableSurface;

const TARGET_KEYS = ["id", "agent", "kind", "seam", "state", "configPath", "label", "detail"] as const;
const VALID_STATES: GovernState[] = ["governed", "ungoverned", "needs-permission", "out-of-scope-cloud"];

describe("govern-all TS↔Rust serialized-shape parity", () => {
  it("the surface fixture is assignable to GovernableSurface with the expected top-level keys", () => {
    expect(Object.keys(surface).sort()).toEqual(
      ["axTrusted", "desktopCandidates", "gatewayAvailable", "hookAvailable", "targets"].sort(),
    );
    expect(surface.hookAvailable).toBe(true);
    expect(surface.gatewayAvailable).toBe(true);
    expect(surface.axTrusted).toBe(false);
    expect(surface.desktopCandidates).toEqual(["Numbers"]);
  });

  it("every target carries the camelCase GovernTarget keys and a valid state", () => {
    for (const t of surface.targets) {
      // Required keys always present.
      for (const k of TARGET_KEYS.filter((k) => k !== "configPath")) {
        expect(t, `target ${t.id} missing ${k}`).toHaveProperty(k);
      }
      // No unexpected keys leaked in.
      for (const k of Object.keys(t)) {
        expect(TARGET_KEYS as readonly string[]).toContain(k);
      }
      expect(VALID_STATES).toContain(t.state);
    }
  });

  it("configPath is optional — the desktop-apps target omits it (skip_serializing_if parity)", () => {
    const hook = surface.targets.find((t: GovernTarget) => t.id === "claude-code:hook");
    const desktop = surface.targets.find((t: GovernTarget) => t.id === "desktop:desktop-apps");
    expect(hook?.configPath).toBe("/home/u/.claude/settings.json");
    expect(desktop && "configPath" in desktop).toBe(false);
  });
});
