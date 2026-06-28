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
