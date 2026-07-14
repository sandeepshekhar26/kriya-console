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

// BC-5 cross-version parity (doc 24 §7.5, EG-4): `sample-envelope-v1.1.json` (above) predates
// `io_destinations`. `sample-envelope-v1.2.json` carries it (envelope v1.2, EG-4 pattern-echo).
// Companion to Rust's `kriya_verify::envelope::tests::cross_version_fixtures_v1_1_and_v1_2_both_verify`.
const v1_2Fixture = JSON.parse(
  readFileSync(join(here, "../src/sample/sample-envelope-v1.2.json"), "utf8"),
) as SignedEnvelope;

describe("envelope v1.2 io_destinations — BC-5 cross-version parity", () => {
  it("verifies the v1.1 fixture (no io_destinations) unchanged", async () => {
    expect(v1_1Fixture.envelope.io_destinations).toBeUndefined();
    const outcome = await verifyEnvelope(v1_1Fixture);
    expect(outcome.ok, outcome.reason).toBe(true);
  });

  it("verifies the v1.2 fixture (with io_destinations present)", async () => {
    expect(v1_2Fixture.envelope.io_destinations).toBeDefined();
    const outcome = await verifyEnvelope(v1_2Fixture);
    expect(outcome.ok, outcome.reason).toBe(true);
  });

  it("only ever carries bundle-authored pattern strings or the unlisted sentinel — never a raw host", () => {
    const patterns = (v1_2Fixture.envelope.io_destinations as Array<{ pattern: string }>).map((p) => p.pattern);
    expect(patterns).toEqual(["*.vendor.com", "unlisted"]);
    expect(JSON.stringify(v1_2Fixture)).not.toContain("unknown-tenant.example");
  });

  it("rejects a tampered io_destinations field", async () => {
    const destinations = v1_2Fixture.envelope.io_destinations as Array<Record<string, unknown>>;
    const tampered = structuredClone(v1_2Fixture) as SignedEnvelope;
    (tampered.envelope.io_destinations as Array<Record<string, unknown>>)[0] = {
      ...destinations[0],
      count: 999,
    };
    expect((await verifyEnvelope(tampered)).ok).toBe(false);
  });
});

// EG-3 (doc 24 §4.2/§8.5): the `kriya.io.*` governed-lane egress/ingress vocabulary needs ZERO
// envelope schema change — `actions[].action` is just a string, so new ids are new values inside the
// existing shape. This fixture pins that the TS verifier re-proves a real Rust-signed envelope
// carrying `kriya.io.*` action strings byte-identically. Companion to Rust's
// `kriya_verify::envelope::tests::egress_fixture_verifies_and_carries_kriya_io_actions`. Regenerate
// with: cargo test -p kriya-verify print_sample_envelope_egress -- --ignored --nocapture
const egressFixture = JSON.parse(
  readFileSync(join(here, "../src/sample/sample-envelope-egress.json"), "utf8"),
) as SignedEnvelope;

describe("envelope kriya.io.* actions — EG-3 no-schema-change parity", () => {
  it("genuinely carries kriya.io.* action ids", () => {
    const actions = egressFixture.envelope.actions as Array<{ action: string; count: number }>;
    expect(actions.some((a) => a.action === "kriya.io.egress.mcp.allow" && a.count === 2)).toBe(true);
    expect(actions.some((a) => a.action === "kriya.io.egress.mcp.deny")).toBe(true);
  });

  it("verifies the committed egress fixture (byte-identical canonicalization)", async () => {
    const outcome = await verifyEnvelope(egressFixture);
    expect(outcome.ok, outcome.reason).toBe(true);
  });

  it("rejects a tampered kriya.io.* action count", async () => {
    const actions = (egressFixture.envelope.actions as Array<{ action: string; count: number }>).map((a) =>
      a.action === "kriya.io.egress.mcp.allow" ? { ...a, count: 999 } : a,
    );
    const tampered: SignedEnvelope = { ...egressFixture, envelope: { ...egressFixture.envelope, actions } };
    expect((await verifyEnvelope(tampered)).ok).toBe(false);
  });
});
