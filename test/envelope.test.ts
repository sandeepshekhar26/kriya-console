import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyEnvelope, type SignedEnvelope } from "../src/lib/envelope";

const here = dirname(fileURLToPath(import.meta.url));
// A real AttestationEnvelope signed by kriya-verify (Rust). If the TS canonicalization were off by a
// single byte, the Ed25519 signature would not verify — this is the envelope half of the trust spine,
// extending the receipt parity in verify.test.ts. Regenerate with:
//   cargo test -p kriya-verify print_sample_envelope -- --ignored --nocapture
const fixture = JSON.parse(
  readFileSync(join(here, "../src/sample/sample-envelope.json"), "utf8"),
) as SignedEnvelope;

describe("envelope parity — TS re-verifies a Rust-signed AttestationEnvelope", () => {
  it("verifies the committed Rust-signed envelope (byte-identical canonicalization)", async () => {
    const outcome = await verifyEnvelope(fixture);
    expect(outcome.ok, outcome.reason).toBe(true);
  });

  it("rejects a tampered envelope field", async () => {
    const tampered: SignedEnvelope = {
      ...fixture,
      envelope: { ...fixture.envelope, org_id: "evil-corp" },
    };
    expect((await verifyEnvelope(tampered)).ok).toBe(false);
  });

  it("rejects a device_pub != public_key mismatch", async () => {
    const tampered: SignedEnvelope = {
      ...fixture,
      envelope: { ...fixture.envelope, device_pub: "0".repeat(64) },
    };
    expect((await verifyEnvelope(tampered)).ok).toBe(false);
  });
});

// BC-5 cross-version parity (doc 22 §8, P3): `sample-envelope.json` (above) is genuinely v1.0-shaped —
// no `policy_state` at all. `sample-envelope-v1.1.json` carries `policy_state` (envelope v1.1, P3).
// TS's `canonicalJson` is already fully generic over whatever keys are present (never a typed struct
// that could silently drop an unknown one), so both verify unchanged with NO code change on this side —
// this test proves that, and is the companion to Rust's
// `kriya_verify::envelope::tests::cross_version_fixtures_both_verify`.
const v1_1Fixture = JSON.parse(
  readFileSync(join(here, "../src/sample/sample-envelope-v1.1.json"), "utf8"),
) as SignedEnvelope;

describe("envelope v1.1 policy_state — BC-5 cross-version parity", () => {
  it("verifies the v1.0 fixture (no policy_state) unchanged", async () => {
    expect(fixture.envelope.policy_state).toBeUndefined();
    const outcome = await verifyEnvelope(fixture);
    expect(outcome.ok, outcome.reason).toBe(true);
  });

  it("verifies the v1.1 fixture (with policy_state present)", async () => {
    expect(v1_1Fixture.envelope.policy_state).toBeDefined();
    const outcome = await verifyEnvelope(v1_1Fixture);
    expect(outcome.ok, outcome.reason).toBe(true);
  });

  it("rejects a tampered policy_state field", async () => {
    const tampered: SignedEnvelope = {
      ...v1_1Fixture,
      envelope: {
        ...v1_1Fixture.envelope,
        policy_state: { ...(v1_1Fixture.envelope.policy_state as Record<string, unknown>), version: 999 },
      },
    };
    expect((await verifyEnvelope(tampered)).ok).toBe(false);
  });
});
