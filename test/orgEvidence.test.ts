import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { OrgEvidence } from "../src/lib/tauri";

// P5 (doc 22 §9) TS↔Rust shape parity. This fixture is the REAL `fleet_evidence::fleet_evidence()`
// output for its own committed 3-synthetic-device fixture (device A in sync, device B drifted +
// chain-broken, device C silent + never applied) — not a hand-typed stand-in. Regenerate both the
// fixture and this file's expectations together with:
//   cargo test -p kriya-console --features control-plane print_sample_org_evidence -- --ignored --nocapture
// The companion Rust-side assertions against the SAME fixture live in
// `src-tauri/src/control_plane/fleet_evidence.rs::tests::three_device_fixture_produces_the_expected_statuses`.
const evidence = JSON.parse(
  readFileSync(fileURLToPath(new URL("../src/sample/sample-org-evidence.json", import.meta.url)), "utf8"),
) as OrgEvidence;

describe("OrgEvidence TS↔Rust parity (P5)", () => {
  it("parses every top-level field the Rust struct emits", () => {
    expect(evidence.devicesTotal).toBe(3);
    expect(evidence.devicesCurrent).toBe(2);
    expect(evidence.devicesBehind).toBe(0);
    expect(evidence.devicesSilent).toBe(1);
    expect(evidence.latestBundleVersion).toBe(2);
    expect(evidence.deviceCompleteness).toHaveLength(3);
    expect(evidence.controls).toHaveLength(12);
  });

  it("device completeness rows carry the locally re-verified fields, camelCased", () => {
    const [a, b, c] = evidence.deviceCompleteness;
    expect(a!.deviceLabel).toBe("laptop-a");
    expect(a!.chainIntact).toBe(true);
    expect(a!.appliedPolicyVersion).toBe(2);

    expect(b!.deviceLabel).toBe("laptop-b");
    expect(b!.seqGaps).toEqual(["seq 1 -> 3 (1 missing)"]);
    expect(b!.chainIntact).toBe(false);
    expect(b!.appliedPolicyVersion).toBe(1);

    expect(c!.deviceLabel).toBe("server-c");
    expect(c!.liveness).toBe("silent");
    expect(c!.appliedPolicyVersion).toBeNull();
  });

  it("names both drift exceptions — behind AND never-applied are distinguished", () => {
    expect(evidence.drift).toHaveLength(2);
    expect(evidence.drift.some((d) => d.includes("laptop-b") && d.includes("applied v1"))).toBe(true);
    expect(evidence.drift.some((d) => d.includes("server-c") && d.includes("never applied"))).toBe(true);
  });

  it("carries the doc-21 honesty norms forward: 3.3.9 permanent gap, 3.3.2 permanent partial", () => {
    const c339 = evidence.controls.find((c) => c.control.startsWith("3.3.9"));
    const c332 = evidence.controls.find((c) => c.control.startsWith("3.3.2"));
    expect(c339?.status).toBe("gap");
    expect(c332?.status).toBe("partial");
  });

  it("includes the NEW CM-family controls (3.4.1/3.4.2), doc 22 §9 item 3", () => {
    const c341 = evidence.controls.find((c) => c.control.startsWith("3.4.1"));
    const c342 = evidence.controls.find((c) => c.control.startsWith("3.4.2"));
    expect(c341).toBeDefined();
    expect(c342).toBeDefined();
    expect(c342?.evidence).toContain("laptop-b");
  });

  it("includes the fleet egress-receipt roll-up (doc 24 §11 B16/EG-F)", () => {
    expect(evidence.egressReceipts).toHaveLength(3);
    expect(evidence.egressReceipts.map((r) => r.deviceLabel)).toEqual(["laptop-a", "laptop-b", "server-c"]);
    expect(evidence.egressTotals).toEqual({ verifiedReceipts: 0, allow: 0, deny: 0, approve: 0 });

    const ac4 = evidence.controls.find((c) => c.control.startsWith("AC-4"));
    expect(ac4).toBeDefined();
    expect(ac4?.status).toBe("partial");
    expect(ac4?.evidence).toContain("0 kriya.io.* receipt(s) verified across 3 device(s)");
  });

  it("every status is one of the three documented values — no stray string slips through", () => {
    for (const c of evidence.controls) {
      expect(["satisfied", "partial", "gap"]).toContain(c.status);
    }
  });

  it("includes an empty-by-default fleet destination-pattern roll-up (doc 24 §4.5/§7.5, EG-4)", () => {
    expect(evidence.egressPatterns).toHaveLength(3);
    for (const d of evidence.egressPatterns) {
      expect(d.patternEchoActive).toBe(false);
      expect(d.patterns).toEqual([]);
      expect(d.unlistedCount ?? null).toBeNull();
    }
    expect(evidence.purposeStatement ?? null).toBeNull();
  });
});
