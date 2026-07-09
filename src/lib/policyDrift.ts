// P4 (doc 22 §9-CM) — the drift view's trust rule, made concrete: kriyad's `GET /v1/coverage`
// `applied_policy_version`/`applied_bundle_hash`/`latest_bundle_version` are the HINT (fast to render,
// server-computed, never independently proven). The verdict this module computes is derived from
// RE-VERIFIED data the cockpit already re-checks locally (BC-5: `fleet_device_evidence`'s per-envelope
// `verified: boolean`, never trusted blindly) — kriyad's row is never the last word. On disagreement
// between the hint and the locally-verified truth, the local truth wins and the mismatch is flagged
// loudly in the UI — that IS the tamper story doc 22 §9 calls out.

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export interface PolicyStateEcho {
  version: number;
  bundle_hash: string;
  applied_ms: number;
}

/** Extract `envelope.policy_state` from a raw signed-envelope JSON string, if present + well-formed.
 *  Display-only parsing (mirrors `ControlPlaneDrillIn`'s own envelope field extraction) — the caller
 *  must have already confirmed `verified: true` (via `fleet_device_evidence`) before trusting this. */
export function parsePolicyState(raw: string): PolicyStateEcho | null {
  try {
    const j = JSON.parse(raw) as { envelope?: Record<string, unknown> };
    const ps = j.envelope?.policy_state as Record<string, unknown> | undefined;
    if (
      !ps ||
      typeof ps.version !== "number" ||
      typeof ps.bundle_hash !== "string" ||
      typeof ps.applied_ms !== "number"
    ) {
      return null;
    }
    return { version: ps.version, bundle_hash: ps.bundle_hash, applied_ms: ps.applied_ms };
  } catch {
    return null;
  }
}

/** One minimized action's rollup — parity with Rust `kriya_verify::MinimizedAction`. Used to surface
 *  `kriya.policy.applied`/`kriya.policy.stale` counts per window in the drill-in's policy history. */
export interface MinimizedActionLike {
  action: string;
  count: number;
  failures: number;
  destructive: boolean;
}

/** Extract `envelope.actions[]` from a raw signed-envelope JSON string, if present + well-formed. */
export function parseActions(raw: string): MinimizedActionLike[] {
  try {
    const j = JSON.parse(raw) as { envelope?: { actions?: unknown } };
    const actions = j.envelope?.actions;
    if (!Array.isArray(actions)) return [];
    return actions.filter(
      (a): a is MinimizedActionLike =>
        !!a &&
        typeof a.action === "string" &&
        typeof a.count === "number" &&
        typeof a.failures === "number" &&
        typeof a.destructive === "boolean",
    );
  } catch {
    return [];
  }
}

export type DriftTone = "ok" | "warn" | "bad" | "grey";

export interface DriftVerdict {
  tone: DriftTone;
  label: string;
  detail: string;
  /** `true` when the locally re-verified truth DISAGREES with kriyad's own served hint (a version or
   *  hash mismatch) — surfaced loudly regardless of the verdict's own tone, since a disagreement is
   *  itself the finding, independent of which side turns out to be "worse". */
  mismatch: boolean;
}

/** Compute one device's drift verdict, per doc 22 §9-CM's rule (§5, §9): green only when the LOCALLY
 *  re-verified applied version+hash match the LOCALLY re-verified fleet latest; amber when genuinely
 *  behind but still reachable; red for "never applied", a hash mismatch at the same version (the tamper
 *  signal), or "behind AND silent" (the worst combination — unreachable and stale); grey when nothing
 *  has ever been published fleet-wide (nothing to be behind ON). */
export function computeDriftVerdict(input: {
  /** The device's own liveness, from its coverage row (`"current"` | `"behind"` | `"silent"`). */
  liveness: string;
  /** Locally re-verified from the device's OWN latest signed envelope (`fleet_device_evidence` +
   *  `parsePolicyState`) — `null` when no envelope has ever carried a `policy_state`. */
  verifiedApplied: { version: number; bundle_hash: string } | null;
  /** Locally re-verified fleet-wide latest bundle (from the operator's own publish-preview fetch,
   *  hashed via `bundleHash`) — `null` when nothing has ever been published. */
  verifiedLatest: { version: number; bundle_hash: string } | null;
  /** kriyad's own served hint — used ONLY for the mismatch check, never as the basis of the verdict. */
  hintAppliedVersion: number | null;
}): DriftVerdict {
  const { liveness, verifiedApplied, verifiedLatest, hintAppliedVersion } = input;

  const mismatch =
    hintAppliedVersion !== null &&
    verifiedApplied !== null &&
    hintAppliedVersion !== verifiedApplied.version;

  if (verifiedLatest === null) {
    return {
      tone: "grey",
      label: "pre-downlink",
      detail: "no policy bundle has ever been published to this kriyad.",
      mismatch,
    };
  }

  if (verifiedApplied === null) {
    return {
      tone: "bad",
      label: "never applied",
      detail: `bundle v${verifiedLatest.version} is published, but this device has never applied a policy bundle.`,
      mismatch,
    };
  }

  if (verifiedApplied.version === verifiedLatest.version) {
    if (verifiedApplied.bundle_hash !== verifiedLatest.bundle_hash) {
      return {
        tone: "bad",
        label: `stale (v${verifiedApplied.version} hash mismatch)`,
        detail: `applied v${verifiedApplied.version} does not match the hash kriyad has on file for v${verifiedLatest.version} — a tamper or corruption signal, not just a version lag.`,
        mismatch: true,
      };
    }
    return { tone: "ok", label: `v${verifiedApplied.version}`, detail: "up to date.", mismatch };
  }

  if (verifiedApplied.version > verifiedLatest.version) {
    // Only possible if this cockpit's OWN visibility of "latest" is narrower than what the device
    // actually received (e.g. a narrowly BU/device-scoped bundle this preview fetch can't see) — not a
    // drift problem from the device's side, so never red/amber for this.
    return {
      tone: "ok",
      label: `v${verifiedApplied.version}`,
      detail: "ahead of what this cockpit's own preview fetch can see (likely a narrowly-scoped bundle).",
      mismatch,
    };
  }

  if (liveness === "silent") {
    return {
      tone: "bad",
      label: `silent — behind (v${verifiedApplied.version} < v${verifiedLatest.version})`,
      detail: "unreachable AND has not applied the latest policy — the worst combination.",
      mismatch,
    };
  }

  return {
    tone: "warn",
    label: `behind (v${verifiedApplied.version} < v${verifiedLatest.version})`,
    detail: "reachable; will apply on its next heartbeat pull.",
    mismatch,
  };
}

/** The drift summary header, e.g. "bundle v13 — applied 47/50 · behind 2 · silent 1". Only non-zero
 *  buckets are shown, in a fixed, stable order. */
export function driftSummaryLine(latestVersion: number | null, verdicts: DriftVerdict[]): string {
  if (latestVersion === null) return "no policy bundle published yet";
  const total = verdicts.length;
  const applied = verdicts.filter((v) => v.tone === "ok").length;
  const behind = verdicts.filter((v) => v.label.startsWith("behind")).length;
  const silentBehind = verdicts.filter((v) => v.label.startsWith("silent")).length;
  const neverApplied = verdicts.filter((v) => v.label === "never applied").length;
  const staleMismatch = verdicts.filter((v) => v.label.startsWith("stale")).length;

  const parts = [`applied ${applied}/${total}`];
  if (behind > 0) parts.push(`behind ${behind}`);
  if (silentBehind > 0) parts.push(`silent ${silentBehind}`);
  if (neverApplied > 0) parts.push(`never applied ${neverApplied}`);
  if (staleMismatch > 0) parts.push(`stale ${staleMismatch}`);
  return `bundle v${latestVersion} — ${parts.join(" · ")}`;
}

export type { Json };
