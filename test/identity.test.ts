import { describe, it, expect } from "vitest";
import type { Actor, AuditRow, SignedReceipt } from "../src/lib/types";
import {
  summarizeIdentities,
  defaultRbac,
  roleOf,
  can,
  assignRole,
  ROLE_CAPS,
} from "../src/lib/identity";

function row(
  source: string,
  tsMs: number,
  opts: { action_id?: string; actor?: Actor; success?: boolean; ok?: boolean } = {},
): AuditRow {
  const receipt: SignedReceipt = {
    step_id: "s",
    action_id: opts.action_id ?? "create_note",
    params: {},
    success: opts.success ?? true,
    ts_ms: tsMs,
    ...(opts.actor ? { actor: opts.actor } : {}),
    public_key: "pk",
    signature: "sig",
  };
  return {
    source,
    lineNo: 1,
    raw: "",
    receipt,
    outcome: opts.ok === false ? { ok: false, reason: "bad" } : { ok: true },
  };
}

const alice: Actor = { agent: "claude-desktop", user: "alice" };
const bob: Actor = { agent: "cursor", user: "bob" };

describe("summarizeIdentities", () => {
  it("aggregates verified actions per operator with success rate, apps, counterparts", () => {
    const rows = [
      row("pos", 1000, { actor: alice, action_id: "sell" }),
      row("pos", 2000, { actor: alice, action_id: "refund", success: false }),
      row("crm", 3000, { actor: alice, action_id: "sell" }),
      row("pos", 4000, { actor: bob, action_id: "sell" }),
    ];
    const a = summarizeIdentities(rows, "user").find((u) => u.id === "alice")!;
    expect(a.actions).toBe(3);
    expect(a.successes).toBe(2);
    expect(a.successRate).toBeCloseTo(2 / 3);
    expect(a.apps).toEqual(["crm", "pos"]);
    expect(a.actionIds).toEqual(["refund", "sell"]);
    expect(a.counterparts).toEqual(["claude-desktop"]); // the agent alice drove
    expect(a.firstSeenMs).toBe(1000);
    expect(a.lastSeenMs).toBe(3000);
    expect(summarizeIdentities(rows, "user")[0]!.id).toBe("alice"); // busiest first
  });

  it("groups by agent and links back to the operators it ran for", () => {
    const rows = [row("a", 1, { actor: alice }), row("a", 2, { actor: bob }), row("a", 3, { actor: alice })];
    const cd = summarizeIdentities(rows, "agent").find((u) => u.id === "claude-desktop")!;
    expect(cd.actions).toBe(2);
    expect(cd.counterparts).toEqual(["alice"]);
  });

  it("excludes failed-verification rows (untrusted actor) and the attestation marker", () => {
    const rows = [
      row("a", 1, { actor: alice }),
      row("a", 2, { actor: alice, ok: false }), // tampered → excluded
      row("a", 3, { actor: alice, action_id: "kriya.attestation.on_device" }), // marker → excluded
    ];
    expect(summarizeIdentities(rows, "user").find((u) => u.id === "alice")!.actions).toBe(1);
  });

  it("buckets unattributed (pre-R8) receipts", () => {
    const users = summarizeIdentities([row("a", 1)], "user"); // no actor
    expect(users[0]!.id).toBe("(unattributed)");
    expect(users[0]!.counterparts).toEqual([]);
  });
});

describe("RBAC", () => {
  it("unassigned users fall to the default role", () => {
    const r = defaultRbac();
    expect(roleOf(r, "nobody")).toBe("viewer");
    expect(can(r, "nobody", "approve")).toBe(false);
    expect(can(r, "nobody", "viewAudit")).toBe(true);
  });

  it("capabilities follow the assigned role", () => {
    let r = defaultRbac();
    r = assignRole(r, "alice", "approver");
    r = assignRole(r, "bob", "admin");
    expect(can(r, "alice", "approve")).toBe(true);
    expect(can(r, "alice", "editPolicy")).toBe(false); // an approver can't edit policy
    expect(can(r, "bob", "editPolicy")).toBe(true);
    expect(ROLE_CAPS.admin).toContain("approve");
  });

  it("assignRole is immutable", () => {
    const r0 = defaultRbac();
    const r1 = assignRole(r0, "alice", "admin");
    expect(r0.assignments).toEqual({}); // original untouched
    expect(r1.assignments).toEqual({ alice: "admin" });
  });
});
