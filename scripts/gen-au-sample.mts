// gen-au-sample.mts — the NIST 800-171 (CMMC L2) AU-family sample evidence pack (R1-1), the
// template-(c) C3PAO outreach leave-behind. Builds from the same PII-free, genuinely Ed25519-signed
// capture dataset used for marketing screenshots (demo/capture/gen-capture-data.mjs → committed at
// src/demo/capture/capture-audit.jsonl), verified through the app's real verifier
// (src/lib/verify.ts) — the same signature check the Console runs — so the sample reflects a
// genuinely verified (and one deliberately tampered) trail, not fabricated data. Verifies each line
// directly (no receipts.ts import) so this runs under plain Node type-stripping — same reason
// demo/compliance-demo.mts does it this way.
//
//   node --experimental-strip-types scripts/gen-au-sample.mts
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyReceipt } from "../src/lib/verify.ts";
import { buildEvidence, renderJson, renderMarkdown } from "../src/lib/compliance.ts";
import type { AuditRow, SignedReceipt } from "../src/lib/types.ts";
import type { Policy } from "../src/lib/policy.ts";

const here = dirname(fileURLToPath(import.meta.url));
const text = readFileSync(join(here, "../src/demo/capture/capture-audit.jsonl"), "utf8");

const rows: AuditRow[] = [];
let lineNo = 0;
for (const raw of text.split("\n")) {
  lineNo++;
  if (raw.trim() === "") continue;
  const receipt = JSON.parse(raw) as SignedReceipt;
  rows.push({ source: "capture-audit", lineNo, raw, receipt, outcome: await verifyReceipt(receipt) });
}

// A representative posture: routine reads/updates allowed, destructive or infra-changing actions
// held for human approval, everything else denied — mirrors demo/compliance-demo.mts's approach of
// a realistic policy rather than the bare defaultPolicy().
const policy: Policy = {
  rules: [
    { action: "list_*", tier: "allow" },
    { action: "get_*", tier: "allow" },
    { action: "categorize_*", tier: "allow" },
    { action: "create_*", tier: "allow" },
    { action: "update_*", tier: "allow" },
    { action: "delete_*", tier: "approval" },
    { action: "restart_*", tier: "approval" },
    { action: "scale_*", tier: "approval" },
    { action: "deploy", tier: "approval" },
    { action: "*", tier: "deny" },
  ],
  maxActionsPerMinute: 60,
  maxApiCallsPerHour: null,
};

const bundle = buildEvidence(rows, policy, {
  generatedAt: Date.UTC(2026, 6, 6),
  organization: "Sample contractor — illustrative data",
  // GA-3: cite the signed coverage-completeness chain as AU-2/AU-12 completeness evidence. Illustrative
  // (like the rest of this sample) — a real export reads the count + chain health from coverage.jsonl.
  coverage: { snapshots: 14, chainOk: true },
});

const outDir = join(here, "../docs/gtm/samples/au-family-sample");
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "evidence.md"), renderMarkdown(bundle));
writeFileSync(join(outDir, "evidence.json"), renderJson(bundle));

const nistRows = bundle.controls.filter((c) => c.framework === "NIST 800-171");
console.log(
  `✓ AU-family sample written to ${outDir}\n` +
    `  ${bundle.integrity.verified}/${bundle.integrity.totalReceipts} receipts verified ` +
    `(${bundle.integrity.failed} failed/tampered — proves forgery is caught)\n` +
    `  ${nistRows.length} NIST 800-171 rows: ` +
    `${nistRows.filter((c) => c.status === "satisfied").length} satisfied, ` +
    `${nistRows.filter((c) => c.status === "partial").length} partial, ` +
    `${nistRows.filter((c) => c.status === "gap").length} gap`,
);
