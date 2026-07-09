import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyPolicyBundle, supersedes, bundleHash, type SignedPolicyBundle } from "../src/lib/policyBundle";

const here = dirname(fileURLToPath(import.meta.url));
// A real PolicyBundle signed by kriya-verify (Rust). If the TS canonicalization were off by a single
// byte, the Ed25519 signature would not verify — the policy-bundle half of the trust spine (doc 22 §5),
// extending the envelope/device-info/heartbeat parity already in this suite. Regenerate both together
// with:
//   cargo test -p kriya-verify print_sample_policy_bundle -- --ignored --nocapture
const fixture = JSON.parse(
  readFileSync(join(here, "../src/sample/sample-policy-bundle.json"), "utf8"),
) as SignedPolicyBundle;

// The pinned org_policy_pub for the fixture above — printed by the same `--ignored --nocapture` run
// that emitted the fixture. A policy bundle carries no embedded public key (see `policy.rs`'s module
// docs), so this constant is the out-of-band trust anchor, exactly like a device/kriyad would pin
// `org-policy.pub` from enrollment/MDM.
const FIXTURE_ORG_POLICY_PUB = "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565";

describe("policy bundle parity — TS re-verifies a Rust-signed PolicyBundle", () => {
  it("verifies the committed Rust-signed bundle against the pinned org key", async () => {
    const outcome = await verifyPolicyBundle(fixture, FIXTURE_ORG_POLICY_PUB);
    expect(outcome.ok, outcome.reason).toBe(true);
  });

  it("rejects the same bundle against the WRONG pinned key", async () => {
    const wrongKey = "00".repeat(32);
    const outcome = await verifyPolicyBundle(fixture, wrongKey);
    expect(outcome.ok).toBe(false);
  });

  it("rejects a tampered top-level field", async () => {
    const tampered: SignedPolicyBundle = {
      ...fixture,
      bundle: { ...fixture.bundle, version: 999 },
    };
    expect((await verifyPolicyBundle(tampered, FIXTURE_ORG_POLICY_PUB)).ok).toBe(false);
  });

  it("rejects a tampered nested govern[] field", async () => {
    const tampered: SignedPolicyBundle = {
      ...fixture,
      bundle: {
        ...fixture.bundle,
        govern: [{ target: "evil-agent", action: "wire" }, ...(fixture.bundle.govern ?? []).slice(1)],
      },
    };
    expect((await verifyPolicyBundle(tampered, FIXTURE_ORG_POLICY_PUB)).ok).toBe(false);
  });

  it("rejects a tampered opaque policy payload", async () => {
    const tampered: SignedPolicyBundle = {
      ...fixture,
      bundle: { ...fixture.bundle, policy: { rules: [{ action: "*", allow: false }] } },
    };
    expect((await verifyPolicyBundle(tampered, FIXTURE_ORG_POLICY_PUB)).ok).toBe(false);
  });
});

describe("supersedes — TS/Rust parity for the anti-rollback version check", () => {
  it("matches the Rust semantics exactly", () => {
    expect(supersedes(1, null)).toBe(true);
    expect(supersedes(2, 1)).toBe(true);
    expect(supersedes(1, 1)).toBe(false);
    expect(supersedes(1, 2)).toBe(false);
  });
});

describe("bundleHash — P4 (doc 22 §9-CM) TS/Rust parity", () => {
  it("matches the committed Rust-computed hash for the fixture bundle", async () => {
    // The SAME constant `kriya_verify::policy::tests::bundle_hash_matches_the_committed_ts_parity_constant`
    // asserts — a canonicalization drift on either side is caught by both suites independently.
    const hash = await bundleHash(fixture.bundle as unknown as Parameters<typeof bundleHash>[0]);
    expect(hash).toBe("1295bcc0ec28992b4228b85cd4ecde943fa4456a5ef252ae01d6b471e66d151f");
  });

  it("changes when the bundle content changes", async () => {
    const h1 = await bundleHash(fixture.bundle as unknown as Parameters<typeof bundleHash>[0]);
    const h2 = await bundleHash({
      ...(fixture.bundle as unknown as Record<string, unknown>),
      version: 999,
    } as Parameters<typeof bundleHash>[0]);
    expect(h1).not.toBe(h2);
  });
});
