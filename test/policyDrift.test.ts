import { describe, it, expect } from "vitest";
import {
  parsePolicyState,
  parseActions,
  computeDriftVerdict,
  driftSummaryLine,
  type DriftVerdict,
} from "../src/lib/policyDrift";

describe("parsePolicyState", () => {
  it("extracts a well-formed policy_state", () => {
    const raw = JSON.stringify({
      envelope: { policy_state: { version: 13, bundle_hash: "deadbeef", applied_ms: 1000 } },
    });
    expect(parsePolicyState(raw)).toEqual({ version: 13, bundle_hash: "deadbeef", applied_ms: 1000 });
  });

  it("returns null when absent (pre-P3 or never-applied envelope)", () => {
    expect(parsePolicyState(JSON.stringify({ envelope: {} }))).toBeNull();
  });

  it("returns null on malformed JSON, never throws", () => {
    expect(parsePolicyState("not json")).toBeNull();
  });

  it("returns null when policy_state is malformed (wrong field types)", () => {
    const raw = JSON.stringify({ envelope: { policy_state: { version: "13" } } });
    expect(parsePolicyState(raw)).toBeNull();
  });
});

describe("parseActions", () => {
  it("extracts kriya.policy.applied/stale action rollups", () => {
    const raw = JSON.stringify({
      envelope: {
        actions: [
          { action: "kriya.policy.applied", count: 1, failures: 0, destructive: false },
          { action: "other", count: 3, failures: 1, destructive: false },
        ],
      },
    });
    const actions = parseActions(raw);
    expect(actions).toHaveLength(2);
    expect(actions[0]!.action).toBe("kriya.policy.applied");
  });

  it("returns an empty array when absent or malformed", () => {
    expect(parseActions(JSON.stringify({ envelope: {} }))).toEqual([]);
    expect(parseActions("not json")).toEqual([]);
  });
});

describe("computeDriftVerdict", () => {
  it("is grey pre-downlink when nothing has ever been published", () => {
    const v = computeDriftVerdict({
      liveness: "current",
      verifiedApplied: null,
      verifiedLatest: null,
      hintAppliedVersion: null,
    });
    expect(v.tone).toBe("grey");
    expect(v.label).toBe("pre-downlink");
  });

  it("is red 'never applied' when a bundle exists but this device applied nothing", () => {
    const v = computeDriftVerdict({
      liveness: "current",
      verifiedApplied: null,
      verifiedLatest: { version: 3, bundle_hash: "h3" },
      hintAppliedVersion: null,
    });
    expect(v.tone).toBe("bad");
    expect(v.label).toBe("never applied");
  });

  it("is green when applied matches latest (version AND hash)", () => {
    const v = computeDriftVerdict({
      liveness: "current",
      verifiedApplied: { version: 3, bundle_hash: "h3" },
      verifiedLatest: { version: 3, bundle_hash: "h3" },
      hintAppliedVersion: 3,
    });
    expect(v.tone).toBe("ok");
    expect(v.label).toBe("v3");
    expect(v.mismatch).toBe(false);
  });

  it("is red 'stale' on a hash mismatch at the SAME version — the tamper signal", () => {
    const v = computeDriftVerdict({
      liveness: "current",
      verifiedApplied: { version: 3, bundle_hash: "wrong-hash" },
      verifiedLatest: { version: 3, bundle_hash: "h3" },
      hintAppliedVersion: 3,
    });
    expect(v.tone).toBe("bad");
    expect(v.label).toContain("stale");
    expect(v.mismatch).toBe(true);
  });

  it("is amber 'behind' when reachable but behind", () => {
    const v = computeDriftVerdict({
      liveness: "current",
      verifiedApplied: { version: 1, bundle_hash: "h1" },
      verifiedLatest: { version: 2, bundle_hash: "h2" },
      hintAppliedVersion: 1,
    });
    expect(v.tone).toBe("warn");
    expect(v.label).toBe("behind (v1 < v2)");
  });

  it("is red 'silent — behind' when unreachable AND behind (the worst combination)", () => {
    const v = computeDriftVerdict({
      liveness: "silent",
      verifiedApplied: { version: 1, bundle_hash: "h1" },
      verifiedLatest: { version: 2, bundle_hash: "h2" },
      hintAppliedVersion: 1,
    });
    expect(v.tone).toBe("bad");
    expect(v.label).toContain("silent");
    expect(v.label).toContain("behind");
  });

  it("is green (not amber) when locally-verified applied is AHEAD of this cockpit's own visibility", () => {
    const v = computeDriftVerdict({
      liveness: "current",
      verifiedApplied: { version: 5, bundle_hash: "h5" },
      verifiedLatest: { version: 3, bundle_hash: "h3" },
      hintAppliedVersion: 5,
    });
    expect(v.tone).toBe("ok");
  });

  it("flags a mismatch when kriyad's hint disagrees with the locally re-verified truth", () => {
    // kriyad's coverage row claims v2, but the device's OWN signed envelope (re-verified locally)
    // says v1 — the local truth wins for the VERDICT, but the disagreement itself is flagged.
    const v = computeDriftVerdict({
      liveness: "current",
      verifiedApplied: { version: 1, bundle_hash: "h1" },
      verifiedLatest: { version: 1, bundle_hash: "h1" },
      hintAppliedVersion: 2,
    });
    // The verdict itself is computed from the LOCAL truth, not kriyad's hint — only the mismatch flag
    // reflects the disagreement.
    expect(v.tone).toBe("ok");
    expect(v.mismatch).toBe(true);
  });

  it("does not flag a mismatch when there's nothing to compare (no hint, or no verified data)", () => {
    expect(
      computeDriftVerdict({
        liveness: "current",
        verifiedApplied: null,
        verifiedLatest: null,
        hintAppliedVersion: null,
      }).mismatch,
    ).toBe(false);
  });
});

describe("driftSummaryLine", () => {
  it("renders the exact doc-22 example shape", () => {
    const verdicts: DriftVerdict[] = [
      ...Array(47).fill({ tone: "ok", label: "v13", detail: "", mismatch: false }),
      ...Array(2).fill({ tone: "warn", label: "behind (v12 < v13)", detail: "", mismatch: false }),
      { tone: "bad", label: "silent — behind (v12 < v13)", detail: "", mismatch: false },
    ];
    expect(driftSummaryLine(13, verdicts)).toBe("bundle v13 — applied 47/50 · behind 2 · silent 1");
  });

  it("says nothing published yet when latestVersion is null", () => {
    expect(driftSummaryLine(null, [])).toBe("no policy bundle published yet");
  });

  it("omits zero-count buckets", () => {
    const verdicts: DriftVerdict[] = [{ tone: "ok", label: "v1", detail: "", mismatch: false }];
    expect(driftSummaryLine(1, verdicts)).toBe("bundle v1 — applied 1/1");
  });
});
