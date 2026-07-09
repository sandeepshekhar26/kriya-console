import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { DeviceCoverageRow } from "../src/lib/tauri";

// P4's BC gate (doc 22 §9-CM's acceptance line): "coverage consumed by a P2-era cockpit build still
// parses (new fields optional)". A P2-era `/v1/coverage` row already carries every P1 device-inventory
// field (P2 widened the Console's own pull client to declare them) but predates P3/P4 entirely — no
// `policy_state`-derived drift fields exist yet. The companion Rust-side proof (the SAME committed JSON,
// parsed as `store::DeviceCoverage`) lives in
// `src-tauri/crates/kriya-aggregator/src/main.rs::tests::p2_era_coverage_fixture_parses_as_new_device_coverage_shape`.
//
// Loading it here as the typed `DeviceCoverageRow[]` proves additive evolution from the TS-client side
// for P4 specifically: a NEW cockpit build (this one) reading a P2-era-shaped response — whether from an
// old cached fleet.json capture or an operator's not-yet-upgraded kriyad — still type-checks and reads
// every field it needs; the three new P4 drift fields are simply undefined, never a parse error.
const rows = JSON.parse(
  readFileSync(fileURLToPath(new URL("./fixtures/p2-era-coverage-sample.json", import.meta.url)), "utf8"),
) as DeviceCoverageRow[];

describe("kriyad /v1/coverage TS↔Rust BC-5 cross-version parity (P4)", () => {
  it("a P2-era coverage response parses as the new DeviceCoverageRow[] shape", () => {
    expect(rows.length).toBe(1);
    const row = rows[0]!;
    expect(row.device_pub).toBe("8f3c1a2b4d5e6f7089abcdef0123456789abcdef0123456789abcdef01234567");
    expect(row.status).toBe("current");
    // P1 fields still read fine through the current type — P4 only ADDED fields, never touched these.
    expect(row.device_label).toBe("laptop-east-07");
    expect(row.policy_applied_version).toBe(3);
  });

  it("every P4 drift field is genuinely absent, not null, on a P2-era artifact", () => {
    const row = rows[0]!;
    const obj = row as unknown as Record<string, unknown>;
    for (const p4Field of ["applied_policy_version", "applied_bundle_hash", "latest_bundle_version"]) {
      expect(p4Field in obj, `${p4Field} must be absent as a JSON key on a P2-era fixture`).toBe(false);
      expect(obj[p4Field]).toBeUndefined();
    }
  });
});
