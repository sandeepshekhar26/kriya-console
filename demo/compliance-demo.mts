// R7 — compliance-evidence export demo.
//
//   node --experimental-strip-types demo/compliance-demo.mts
//   (or: npm run demo:compliance)
//
// Verifies the sample audit trail (on-device attestation + sealed action + 2 attributed
// receipts + 1 tampered line), builds the evidence bundle against a finance policy, and prints
// the Markdown report an auditor would receive — control mapping and all.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyReceipt } from "../src/lib/verify.ts";
import { buildEvidence, renderMarkdown } from "../src/lib/compliance.ts";
import type { AuditRow, SignedReceipt } from "../src/lib/types.ts";
import type { Policy } from "../src/lib/policy.ts";

const here = dirname(fileURLToPath(import.meta.url));
const text = readFileSync(join(here, "../src/sample/sample-compliance.jsonl"), "utf8");

// Verify each receipt locally (no receipts.ts import — keep the demo a single self-contained
// dependency chain), building the rows the evidence builder consumes.
const rows: AuditRow[] = [];
let lineNo = 0;
for (const raw of text.split("\n")) {
  lineNo++;
  if (raw.trim() === "") continue;
  const receipt = JSON.parse(raw) as SignedReceipt;
  rows.push({ source: "finance-app", lineNo, raw, receipt, outcome: await verifyReceipt(receipt) });
}

const policy: Policy = {
  rules: [
    { action: "categorize_*", tier: "allow" },
    { action: "create_*", tier: "allow" },
    { action: "delete_*", tier: "approval" },
    { action: "close_*", tier: "approval" },
    { action: "*", tier: "deny" },
  ],
  maxActionsPerMinute: 30,
};

const bundle = buildEvidence(rows, policy, { generatedAt: Date.UTC(2026, 5, 19), organization: "Acme Finance" });

console.log(renderMarkdown(bundle));
console.log("---");
console.log(
  `Summary: ${bundle.integrity.verified}/${bundle.integrity.totalReceipts} verified, ` +
    `${bundle.integrity.failed} tampered · ${bundle.attribution.coveragePct}% attributed · ` +
    `${bundle.onDevice.attestations} on-device attestation(s) · ` +
    `${bundle.controls.filter((c) => c.status === "satisfied").length}/${bundle.controls.length} controls satisfied`,
);
