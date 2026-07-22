import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadAuditLog } from "../src/lib/receipts";
import { buildEvidence, EGRESS_SCOPE_BLOCK, renderJson, renderMarkdown } from "../src/lib/compliance";
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
      egress: null,
      detection: null,
      secrets: null,
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

describe("buildEvidence — coverage-completeness citation (GA-3)", () => {
  it("cites the signed coverage chain + agent span in NIST 3.3.1 and 3.3.4 when supplied", async () => {
    const rows = await loadAuditLog(sample, "compliance-sample");
    const b = buildEvidence(rows, defaultPolicy(), {
      generatedAt: AT,
      organization: "Acme",
      coverage: { snapshots: 14, chainOk: true },
    });
    const c331 = b.controls.find((c) => c.control.startsWith("3.3.1"))!;
    expect(c331.evidence).toContain("governed agent(s)");
    expect(c331.evidence).toContain("14 signed coverage snapshot(s)");
    expect(c331.evidence).toContain("chain intact");
    const c334 = b.controls.find((c) => c.control.startsWith("3.3.4"))!;
    expect(c334.evidence).toContain("visible by absence");
  });

  it("omits the citation when no coverage summary is supplied (backward compatible)", async () => {
    const b = await bundle();
    const c331 = b.controls.find((c) => c.control.startsWith("3.3.1"))!;
    expect(c331.evidence).not.toContain("coverage snapshot");
    // The agent span is still surfaced (that part is unconditional).
    expect(c331.evidence).toContain("governed agent(s)");
  });

  it("names a broken coverage chain honestly", async () => {
    const rows = await loadAuditLog(sample, "compliance-sample");
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, coverage: { snapshots: 3, chainOk: false } });
    const c331 = b.controls.find((c) => c.control.startsWith("3.3.1"))!;
    expect(c331.evidence).toContain("chain BROKEN");
  });
});

describe("buildEvidence — egress/ingress ledger controls (EG-3, doc 24 §3)", () => {
  // A pre-verified in-memory row, mirroring the R24 helper above but with a `success` param so a
  // deny receipt (signed success:false) can be constructed.
  function row(action_id: string, params: SignedReceipt["params"], success = true): AuditRow {
    return {
      source: "test",
      lineNo: 1,
      raw: "",
      receipt: { step_id: "s", action_id, params, success, ts_ms: AT, public_key: "pk", signature: "sig" } as SignedReceipt,
      outcome: { ok: true },
    };
  }

  const FORBIDDEN = ["3.13.1", "3.13.6", "SC-7", "SC-8", "CC6.6", "DLP"];

  it("adds no egress control rows or scope block on a trail with zero kriya.io.* receipts", async () => {
    const b = await bundle();
    expect(b.egress).toBeNull();
    expect(b.controls.some((c) => c.control.includes("3.1.3"))).toBe(false);
    expect(renderMarkdown(b)).not.toContain(EGRESS_SCOPE_BLOCK);
  });

  it("posture: not_monitored when the governed surface itself is silent (no receipts at all)", () => {
    const b = buildEvidence([], defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    expect(b.egressPosture.state).toBe("not_monitored");
    const md = renderMarkdown(b);
    expect(md).toContain("NOT MONITORED");
    expect(md).not.toContain("zero egress"); // the exact banned phrase (§6-H1), case-sensitive
    expect(md.toLowerCase()).not.toContain("nothing left at all");
  });

  it("posture: zero_observed when governed-lane activity exists but no egress receipts do", async () => {
    const b = await bundle(); // the sample trail has app-action receipts, no kriya.io.*
    expect(b.egressPosture.state).toBe("zero_observed");
    expect(b.egressPosture.governedLaneReceipts).toBeGreaterThan(0);
    expect(b.egressPosture.egressReceipts).toBe(0);
    const md = renderMarkdown(b);
    expect(md).toContain("does NOT prove the egress ledger was continuously enabled");
    expect(md).toContain("Coverage Map");
  });

  it("posture: egress_present when kriya.io.egress.* receipts are observed, and ingress never inflates the egress count", () => {
    const rows: AuditRow[] = [
      row("create_note", { title: "hi" }),
      row("kriya.io.egress.mcp.allow", { dest_host: "api.vendor.com" }),
      row("kriya.io.ingress.mcp.allow", { bytes_in: 10 }),
    ];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    expect(b.egressPosture.state).toBe("egress_present");
    expect(b.egressPosture.egressReceipts, "ingress receipts must not count as egress").toBe(1);
    expect(renderMarkdown(b)).toContain("NOT zero — 1 kriya.io.egress.* receipt(s)");
  });

  it("computes egress evidence from verified kriya.io.* receipts only and excludes them from the action inventory", () => {
    const rows: AuditRow[] = [
      row("create_note", { title: "hi" }),
      row("kriya.io.egress.mcp.allow", { dest_host: "api.vendor.com", decision: "allow" }),
      row("kriya.io.egress.mcp.allow", { dest_host: "api.vendor.com", decision: "allow" }),
      row("kriya.io.egress.mcp.deny", { dest_host: "evil.example", decision: "deny" }, false),
      row("kriya.io.egress.http.approve", { dest_host: "partner.example", decision: "approve" }),
    ];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });

    expect(b.egress).toEqual({ verifiedReceipts: 4, allow: 2, deny: 1, approve: 1 });
    expect(b.actionInventory.some((a) => a.action.startsWith("kriya.io."))).toBe(false);
    expect(b.actionInventory.some((a) => a.action === "create_note")).toBe(true);
  });

  it("adds exactly the doc 24 §3 rows, all capped at partial, and NEVER the killed controls or DLP", () => {
    const rows: AuditRow[] = [
      row("kriya.io.egress.mcp.allow", { dest_host: "api.vendor.com" }),
      row("kriya.io.egress.mcp.deny", { dest_host: "evil.example" }, false),
    ];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });

    const expectedControls = [
      "3.1.3", "3.4.2", "3.14.6/3.14.7", "AC-4", "SI-4", "CC6.1", "CC6.7",
      "CC7.2 — Anomaly monitoring (governed-lane egress)",
      "Art. 12 — Record-keeping (governed-lane egress)", "Art. 28(3)", "Art. 10(2)",
    ];
    for (const c of expectedControls) {
      const found = b.controls.find((row) => row.control.includes(c));
      expect(found, `expected a control row containing "${c}"`).toBeTruthy();
      expect(found!.status).toBe("partial");
    }

    const full = renderJson(b) + renderMarkdown(b);
    for (const banned of FORBIDDEN) {
      expect(full, `"${banned}" must never appear in an egress-bearing export`).not.toContain(banned);
    }
  });

  it("embeds the §3.1 scope block verbatim in both JSON and Markdown when egress-bearing", () => {
    const rows: AuditRow[] = [row("kriya.io.egress.mcp.allow", { dest_host: "api.vendor.com" })];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    expect(renderJson(b)).toContain(EGRESS_SCOPE_BLOCK.slice(0, 60));
    const md = renderMarkdown(b);
    expect(md).toContain("Egress/ingress ledger");
    expect(md).toContain(EGRESS_SCOPE_BLOCK);
    expect(md).toContain("evidence, not a certification"); // the footer is unchanged
  });

  it("cites deny counts honestly when zero denials have been observed", () => {
    const rows: AuditRow[] = [row("kriya.io.egress.mcp.allow", { dest_host: "api.vendor.com" })];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    const si4 = b.controls.find((c) => c.control.includes("3.14.6"))!;
    expect(si4.evidence).toContain("No denials observed");
  });
});

describe("buildEvidence — run-correlation appendix (S3)", () => {
  // A verified in-memory row optionally carrying kriya.corr.
  function row(
    stepId: string,
    action_id: string,
    corr?: { run_id?: string; parent_step_id?: string; agent_id?: string },
  ): AuditRow {
    const params: Record<string, unknown> = { x: 1 };
    if (corr) params["kriya.corr"] = corr;
    return {
      source: "test",
      lineNo: 1,
      raw: "",
      receipt: {
        step_id: stepId,
        action_id,
        params,
        success: !action_id.includes("deny"),
        ts_ms: AT,
        public_key: "pk",
        signature: "sig",
      } as SignedReceipt,
      outcome: { ok: true },
    };
  }

  it("omits the appendix entirely when no receipts are correlated (byte-identical export)", () => {
    const rows: AuditRow[] = [row("s1", "create_note"), row("s2", "list_notes")];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    expect(b.correlation).toBeUndefined();
    // The JSON must not gain a `correlation` KEY (the word appears in unrelated control text), and
    // the Markdown must not gain the appendix heading.
    expect(renderJson(b)).not.toContain('"correlation":');
    expect(renderMarkdown(b)).not.toContain("Session correlation");
  });

  it("emits the appendix numbers when correlated receipts exist", () => {
    const rows: AuditRow[] = [
      row("m1", "claude-code__task", { run_id: "sess" }),
      row("s1", "claude-code__bash", { run_id: "sess", agent_id: "sub-A" }),
      row("s2", "claude-code__bash", { run_id: "sess", agent_id: "sub-A" }),
    ];
    const b = buildEvidence(rows, defaultPolicy(), { generatedAt: AT, organization: "Acme" });
    expect(b.correlation).toEqual({ runs: 1, subAgents: 1, spawns: 1, actions: 3, blocked: 0 });
    const md = renderMarkdown(b);
    expect(md).toContain("## Session correlation (appendix)");
    expect(md).toContain("**1** run(s)");
    expect(md).toContain("**1** sub-agent(s) observed");
    // The correlation field also appears in the JSON.
    expect(JSON.parse(renderJson(b)).correlation.runs).toBe(1);
  });
});
