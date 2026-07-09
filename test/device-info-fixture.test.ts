import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { DeviceCoverageRow } from "../src/lib/tauri";

// BC-5 cross-version fixture (doc 22 §8): an OLD-shape `/v1/coverage` response — minted BEFORE P1's
// DeviceInfo beacon existed, i.e. only the original `device_pub/org_id/business_unit/last_seq/
// max_seq_seen/last_seen_ms/status` fields, none of the new device-inventory ones. The companion
// Rust-side proof (the SAME committed JSON, parsed as the new `store::DeviceCoverage` shape) lives in
// `src-tauri/crates/kriya-aggregator/src/main.rs::tests::old_shape_coverage_fixture_parses_as_new_device_coverage_shape`.
//
// Loading it here as the typed `DeviceCoverageRow[]` proves the additive-evolution contract from the
// TS-client side: a NEW cockpit build (this one) talking to an OLD kriyad (or reading an old cached
// response) still type-checks and reads every field it needs — the new P1 fields are simply undefined,
// never a parse error, never a crash.
const rows = JSON.parse(
  readFileSync(fileURLToPath(new URL("./fixtures/pre-p1-coverage-sample.json", import.meta.url)), "utf8"),
) as DeviceCoverageRow[];

describe("kriyad /v1/coverage TS↔Rust BC-5 cross-version parity (P1)", () => {
  it("an old-shape (pre-DeviceInfo) coverage response parses as the new DeviceCoverageRow[] shape", () => {
    expect(rows.length).toBe(1);
    const row = rows[0]!;
    expect(row.device_pub).toBe("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c");
    expect(row.org_id).toBe("acme");
    expect(row.business_unit).toBeNull();
    expect(row.last_seq).toBe(2);
    expect(row.max_seq_seen).toBe(2);
    expect(row.last_seen_ms).toBe(1500);
    expect(row.status).toBe("current");
  });

  it("every P1 device-inventory field is genuinely absent, not null, on the old artifact", () => {
    const row = rows[0]!;
    const obj = row as unknown as Record<string, unknown>;
    for (const newField of [
      "console_version",
      "runtime_version",
      "verify_crate_version",
      "os_platform",
      "os_version",
      "os_arch",
      "policy_applied_version",
      "policy_bundle_hash",
      "outbox_pending",
      "enrolled_ms",
      "device_label",
      "agents",
      "info_collected_ms",
    ]) {
      expect(newField in obj, `${newField} must be absent as a JSON key on the old-shape fixture`).toBe(false);
      // And accessing it through the typed interface must be `undefined`, not throw and not be `null`
      // (undefined is what a genuinely-absent optional field reads as in TS/JS — the honest "old
      // server never sent this" signal, distinct from a P1 server that explicitly sent `null`).
      expect(obj[newField]).toBeUndefined();
    }
  });
});
