import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadAuditLog } from "../src/lib/receipts";
import { buildEvidence, renderJson, renderMarkdown } from "../src/lib/compliance";
import { defaultPolicy, type Policy } from "../src/lib/policy";
import type { AuditRow, SignedReceipt } from "../src/lib/types";

const here = dirname(fileURLToPath(import.meta.url));
// On-device attestation + sealed action + 2 actor receipts + 1 tampered line — all REAL
// Rust-signed receipts (plus one deliberately corrupted), so the integrity check is exercised.
const sample = readFileSync(join(here, "../src/sample/sample-compliance.jsonl"), "utf8");
const AT = Date.UTC(2026, 5, 19); // fixed generatedAt for stable output

async function bundle(policy: Policy = defaultPolicy()) {
  const rows = await loadAuditLog(sample, "compliance-sample");
  return buildEvidence(rows, policy, { generatedAt: AT, organization: "Acme" });
}

describe("buildEvidence — integrity", () => {
  it("counts verified vs failed and distinct signers from real receipts", async () => {
    const b = await bundle();
    expect(b.integrity.totalReceipts).toBe(5);
    expect(b.integrity.verified).toBe(4);
    expect(b.integrity.failed).toBe(1); // the tampered line
    expect(b.integrity.distinctSigners).toBe(2);
  });

  it("flags the integrity control as partial when a receipt fails", async () => {
    const b = await bundle();
    const cc72 = b.controls.find((c) => c.control.startsWith("CC7.2"));
    expect(cc72?.status).toBe("partial");
  });
});

describe("buildEvidence — attribution (R8) + on-device (R13)", () => {
  it("reports actor coverage and the agents/operators seen", async () => {
    const b = await bundle();
    expect(b.attribution.attributed).toBe(4);
    expect(b.attribution.coveragePct).toBe(100);
    expect(b.attribution.agents).toEqual(["claude-desktop", "scripted"]);
    expect(b.attribution.users).toEqual(["alice", "skumar"]);
  });

  it("counts on-device attestations and names the sealed backend", async () => {
    const b = await bundle();
    expect(b.onDevice.attestations).toBe(1);
    expect(b.onDevice.sealedBackends).toEqual(["scripted"]);
    const residency = b.controls.find((c) => c.framework === "Data residency");
    expect(residency?.status).toBe("satisfied");
  });
});

describe("buildEvidence — gateway provenance (R24)", () => {
  // A pre-verified in-memory row (signature is checked elsewhere; buildEvidence trusts outcome.ok).
  function row(action_id: string, params: SignedReceipt["params"]): AuditRow {
    return {
      source: "test",
      lineNo: 1,
      raw: "",
      receipt: {
        step_id: "s",
        action_id,
        params,
        success: true,
        ts_ms: AT,
        public_key: "pk",
        signature: "sig",
      } as SignedReceipt,
      outcome: { ok: true },
    };
  }

  it("surfaces the governed component from a gateway on-device attestation", () => {
    // Gateway sessions attest with `component` (no inference `backend`) — the R24 shape.
    const rows: AuditRow[] = [
      row("kriya.attestation.on_device", {
        component: "kriya-gateway",
        network_profile: "gateway-proxy",
        egress: false,
      }),
      row("delete_note", { id: "n1" }),
    ];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    expect(b.onDevice.attestations).toBe(1);
    expect(b.onDevice.components).toEqual(["kriya-gateway"]);
    expect(b.onDevice.sealedBackends).toEqual([]); // a gateway session seals no inference backend
    const residency = b.controls.find((c) => c.framework === "Data residency");
    expect(residency?.evidence).toContain("kriya-gateway");
    expect(renderMarkdown(b)).toContain("via kriya-gateway");
  });
});

describe("buildEvidence — inventory + oversight", () => {
  it("inventories verified app actions (excluding the attestation marker) with policy tiers", async () => {
    // A finance policy: categorize allowed, delete behind approval, everything else denied.
    const policy: Policy = {
      rules: [
        { action: "categorize_*", tier: "allow" },
        { action: "create_*", tier: "allow" },
        { action: "delete_*", tier: "approval" },
        { action: "*", tier: "deny" },
      ],
      maxActionsPerMinute: 30,
      maxApiCallsPerHour: null,
    };
    const b = await bundle(policy);
    const ids = b.actionInventory.map((a) => a.action).sort();
    expect(ids).toEqual(["categorize_transaction", "create_note", "delete_transaction"]);
    expect(ids).not.toContain("kriya.attestation.on_device");
    const del = b.actionInventory.find((a) => a.action === "delete_transaction");
    expect(del?.tier).toBe("approval");
    expect(del?.destructive).toBe(true);
    expect(b.humanOversight.approvalGatedActions).toContain("delete_transaction");
  });
});

describe("renderers", () => {
  it("renderJson round-trips to the same bundle", async () => {
    const b = await bundle();
    expect(JSON.parse(renderJson(b))).toEqual(b);
  });

  it("renderMarkdown includes the key sections and control table", async () => {
    const md = renderMarkdown(await bundle());
    expect(md).toContain("# Compliance evidence — Acme");
    expect(md).toContain("## Audit integrity");
    expect(md).toContain("## Control mapping");
    expect(md).toContain("EU AI Act");
    expect(md).toContain("Art. 12");
  });
});

describe("buildEvidence — NIST 800-171 AU family (R1-1)", () => {
  // A pre-verified in-memory row (signature checked elsewhere) so status rules can be exercised
  // without real crypto — same pattern as the R24 gateway-provenance block above.
  function row(action_id: string, opts: { ok?: boolean; actor?: { agent: string; user: string } } = {}): AuditRow {
    return {
      source: "test-app",
      lineNo: 1,
      raw: "",
      receipt: {
        step_id: "s",
        action_id,
        params: {},
        success: true,
        ts_ms: AT,
        public_key: "pk",
        signature: "sig",
        actor: opts.actor,
      } as SignedReceipt,
      outcome: opts.ok === false ? { ok: false, reason: "bad signature" } : { ok: true },
    };
  }

  it("maps all 9 AU-family practices", async () => {
    const b = await bundle();
    const nist = b.controls.filter((c) => c.framework === "NIST 800-171");
    expect(nist.length).toBe(9);
  });

  it("3.3.8 is satisfied and 3.3.9 is a deliberate gap on a clean, fully-verified trail", () => {
    const rows: AuditRow[] = [
      row("create_note", { actor: { agent: "claude-desktop", user: "alice" } }),
      row("categorize_transaction", { actor: { agent: "claude-desktop", user: "alice" } }),
    ];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    const c338 = b.controls.find((c) => c.control.startsWith("3.3.8"));
    const c339 = b.controls.find((c) => c.control.startsWith("3.3.9"));
    expect(c338?.status).toBe("satisfied");
    expect(c339?.status).toBe("gap");
  });

  it("3.3.9 stays a gap even on that same clean trail's evidence text (never fabricated satisfied)", () => {
    const rows: AuditRow[] = [row("create_note", { actor: { agent: "claude-desktop", user: "alice" } })];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    const c339 = b.controls.find((c) => c.control.startsWith("3.3.9"));
    expect(c339?.status).toBe("gap");
    expect(c339?.evidence).toMatch(/self-asserted|privileged/i);
  });

  it("3.3.8 drops to partial and names detection when a row fails verification", () => {
    const rows: AuditRow[] = [
      row("create_note", { actor: { agent: "claude-desktop", user: "alice" } }),
      row("delete_note", { ok: false, actor: { agent: "claude-desktop", user: "alice" } }),
    ];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    const c338 = b.controls.find((c) => c.control.startsWith("3.3.8"));
    expect(c338?.status).toBe("partial");
    expect(c338?.evidence).toMatch(/detect/i);
  });

  it("renderMarkdown includes the NIST framework and the non-certification footer", async () => {
    const md = renderMarkdown(await bundle());
    expect(md).toContain("NIST 800-171");
    expect(md).toContain("evidence, not a certification");
  });
});
