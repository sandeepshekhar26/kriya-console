// gen-capture-data.mjs — mint a clean, PII-free, genuinely Ed25519-signed dataset for marketing
// screenshots. Output passes the SAME verifier the app uses (src/lib/verify.ts), so the captured
// Console shows real green "verified" state — no mocks. NO PII: role/team handles only, opaque ids,
// no people-names, no emails. Deterministic (fixed signer keys) so the committed jsonl is stable.
//
//   node demo/capture/gen-capture-data.mjs   →   src/demo/capture/{capture-audit,capture-approvals}.jsonl
import * as ed from "@noble/ed25519";
import { mkdirSync, writeFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const subtle = (globalThis.crypto ?? webcrypto).subtle;
ed.etc.sha512Async = async (...m) =>
  new Uint8Array(await subtle.digest("SHA-512", ed.etc.concatBytes(...m)));

const enc = new TextEncoder();
const hex = (u) => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));

// --- canonical receipt bytes — byte-identical to src/lib/verify.ts (declaration order; params keys
//     sorted; actor + prev_hash signed last). The only way the signature can verify is a byte match. ---
const cnum = (n) => String(n);
function cjson(v) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") return cnum(v);
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(cjson).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + cjson(v[k])).join(",") + "}";
}
function canonicalReceiptBytes(r) {
  const actor = r.actor === undefined ? "" :
    ',"actor":{"agent":' + JSON.stringify(r.actor.agent) + ',"user":' + JSON.stringify(r.actor.user) + "}";
  const prev = r.prev_hash === undefined ? "" : ',"prev_hash":' + JSON.stringify(r.prev_hash);
  return enc.encode(
    "{" + '"step_id":' + JSON.stringify(r.step_id) + ',"action_id":' + JSON.stringify(r.action_id) +
    ',"params":' + cjson(r.params) + ',"success":' + (r.success ? "true" : "false") +
    ',"ts_ms":' + cnum(r.ts_ms) + actor + prev + "}",
  );
}

// --- fixed synthetic signer keys (one Ed25519 key per governed app) ---
const PRIV = {
  "budget-app": fromHex("a1b2c3d4e5f6071829303a4b5c6d7e8f90a1b2c3d4e5f6071829303a4b5c6d7e"),
  "crm-app":    fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"),
  "devops-app": fromHex("5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344"),
};
const ACTOR = {
  "budget-app": { agent: "claude-desktop", user: "fin-ops" },
  "crm-app":    { agent: "cursor", user: "sales-ops" },
  "devops-app": { agent: "claude-desktop", user: "platform-eng" },
};

// --- the action log (PII-free: opaque ids, no names, no emails) ---
const ROWS = [
  ["budget-app", "list_transactions", { accountId: "acct-checking", startDate: "2026-06-01", endDate: "2026-06-30" }],
  ["budget-app", "categorize_transaction", { id: "txn-4821", category: "groceries" }],
  ["budget-app", "categorize_transaction", { id: "txn-4822", category: "utilities" }],
  ["crm-app", "list_contacts", { segment: "q3-pipeline" }],
  ["devops-app", "list_services", { env: "staging" }],
  ["budget-app", "get_balance", { accountId: "acct-checking" }],
  ["crm-app", "update_contact", { id: "ct-7781", field: "stage", value: "qualified" }],
  ["devops-app", "get_logs", { service: "api-gateway", window: "1h" }],
  ["budget-app", "categorize_transaction", { id: "txn-4830", category: "income" }],
  ["crm-app", "create_note", { entity: "deal-3310", topic: "follow-up" }],
  ["devops-app", "restart_service", { service: "worker-2", env: "staging" }],
  ["budget-app", "list_transactions", { accountId: "acct-savings", startDate: "2026-06-01", endDate: "2026-06-30" }],
  ["crm-app", "list_deals", { stage: "open" }],
  ["devops-app", "get_logs", { service: "db-primary", window: "15m" }],
  ["budget-app", "delete_transaction", { id: "txn-4799" }], // <- TAMPERED (see TAMPER_INDEX): proves forgery is caught
  ["crm-app", "update_contact", { id: "ct-7782", field: "owner", value: "sales-ops" }],
  ["devops-app", "scale_service", { service: "api-gateway", replicas: 4 }],
  ["budget-app", "categorize_transaction", { id: "txn-4840", category: "dining" }],
  ["crm-app", "create_note", { entity: "deal-3315", topic: "pricing" }],
  ["devops-app", "list_services", { env: "prod" }],
  ["budget-app", "categorize_transaction", { id: "txn-4851", category: "transport" }],
  ["crm-app", "list_contacts", { segment: "renewals" }],
  ["devops-app", "get_logs", { service: "api-gateway", window: "6h" }],
  ["budget-app", "get_balance", { accountId: "acct-savings" }],
  ["crm-app", "update_contact", { id: "ct-7790", field: "stage", value: "won" }],
  ["devops-app", "deploy", { service: "web", version: "v0.9.4" }],
  ["budget-app", "categorize_transaction", { id: "txn-4860", category: "software" }],
  ["crm-app", "create_note", { entity: "deal-3320", topic: "renewal" }],
];
const TAMPER_INDEX = 14;
const BASE = 1781700000000;

// --- governed-lane egress/ingress ledger rows (EG-2/EG-3, doc 24 §4.2) — action ids from the closed
//     kriya.io.<direction>.<kind>.<decision> set; params byte-shaped like the real runtime fixture
//     (kriya-verify/fixtures/runtime-egress-ledger.jsonl): decision is in the id AND params, hashes are
//     wire-byte sha256, `corr` ties the flow to the app action that caused it. PII-free (hosts only). ---
const IO_SHA = (n) => String(n).repeat(64).slice(0, 64);
const IO_ROWS = [
  ["devops-app", "kriya.io.egress.http.allow", { bytes_in: 2048, bytes_out: 14210, content_sha256: IO_SHA(2), corr: "devops-app-026", decision: "allow", dest_host: "api.github.com", dest_kind: "http", hash_scheme: "wire-bytes", method: "POST", policy_rule: "*.github.com", server: "github" }],
  ["crm-app", "kriya.io.egress.mcp.allow", { bytes_in: 3110, bytes_out: 6120, content_sha256: IO_SHA(3), corr: "crm-app-025", decision: "allow", dest_host: "mcp.linear.app", dest_kind: "mcp", hash_scheme: "wire-bytes", method: "tools/call", policy_rule: "mcp.linear.app", server: "linear" }],
  ["budget-app", "kriya.io.egress.model.allow", { bytes_in: 8412, bytes_out: 20480, content_sha256: IO_SHA(4), corr: "budget-app-027", decision: "allow", dest_host: "api.anthropic.com", dest_kind: "model", hash_scheme: "wire-bytes", method: "messages.create", policy_rule: "api.anthropic.com", server: "anthropic" }],
  ["devops-app", "kriya.io.egress.http.deny", { bytes_in: 0, bytes_out: 0, content_sha256: IO_SHA(5), corr: "devops-app-023", decision: "deny", dest_host: "metrics.unknown-vendor.io", dest_kind: "http", hash_scheme: "wire-bytes", method: "POST", policy_rule: "(deny-by-default)", server: "github" }],
  ["crm-app", "kriya.io.egress.http.approve", { bytes_in: 512, bytes_out: 51200, content_sha256: IO_SHA(6), corr: "crm-app-028", decision: "approve", dest_host: "exports.partner-crm.com", dest_kind: "http", hash_scheme: "wire-bytes", method: "PUT", policy_rule: "ask:exports.partner-crm.com", server: "crm-export" }],
  ["devops-app", "kriya.io.ingress.http.allow", { bytes_in: 88420, bytes_out: 0, content_sha256: IO_SHA(7), corr: "devops-app-026", decision: "allow", dest_host: "registry.npmjs.org", dest_kind: "http", hash_scheme: "wire-bytes", method: "GET", policy_rule: "registry.npmjs.org", server: "github" }],
];

// --- pending approvals (high-risk actions a policy holds for a human); same role handles, no emails ---
const APPROVALS = [
  ["budget-app", "delete_transaction", { id: "txn-5012" }, "Looks like a duplicate charge"],
  ["budget-app", "transfer_funds", { from: "acct-checking", to: "acct-vendor", amount: 1840 }, "Pay the approved invoice INV-2231"],
  ["devops-app", "restart_service", { service: "payments-api", env: "prod" }, "Clear the stuck worker queue"],
  ["budget-app", "close_account", { accountId: "acct-savings" }, "Unused account cleanup"],
  ["crm-app", "send_email", { template: "q3-followup", segment: "stalled-deals" }, "Re-engage the stalled Q3 pipeline"],
  ["devops-app", "scale_service", { service: "api-gateway", replicas: 8 }, "Scale for the campaign traffic window"],
  ["crm-app", "bulk_update", { segment: "churned", field: "status" }, "Mark the churned segment for archival"],
];

async function main() {
  const auditLines = [];
  for (let i = 0; i < ROWS.length; i++) {
    const [app, action_id, params] = ROWS[i];
    const receipt = {
      step_id: `${app}-${String(i + 1).padStart(3, "0")}`,
      action_id,
      params,
      success: true,
      ts_ms: BASE + i * 145000 + (i % 4) * 31000,
      actor: ACTOR[app],
    };
    const priv = PRIV[app];
    const pub = await ed.getPublicKeyAsync(priv);
    let signature = hex(await ed.signAsync(canonicalReceiptBytes(receipt), priv));
    if (i === TAMPER_INDEX) signature = (signature[0] === "f" ? "0" : "f") + signature.slice(1); // forge → fails verify
    auditLines.push(JSON.stringify({ ...receipt, source: app, public_key: hex(pub), signature }));
  }

  // io-ledger rows: runtime-style step ids, timestamped after the app actions so Monitor tails them
  for (let i = 0; i < IO_ROWS.length; i++) {
    const [app, action_id, params] = IO_ROWS[i];
    const ts_ms = BASE + ROWS.length * 145000 + i * 97000;
    const receipt = { step_id: `${action_id}-${ts_ms}`, action_id, params, success: true, ts_ms, actor: ACTOR[app] };
    const priv = PRIV[app];
    const pub = await ed.getPublicKeyAsync(priv);
    const signature = hex(await ed.signAsync(canonicalReceiptBytes(receipt), priv));
    auditLines.push(JSON.stringify({ ...receipt, source: app, public_key: hex(pub), signature }));
  }

  const apprLines = APPROVALS.map(([app, action_id, params, reasoning], i) =>
    JSON.stringify({
      id: `ap-${String(i + 1).padStart(3, "0")}`,
      source: app,
      actor: ACTOR[app],
      action_id,
      params,
      reasoning,
      requested_ms: BASE + 4_000_000 + i * 210000,
    }),
  );

  // --- self-verify: every line except the one tamper must verify; and zero PII tokens ---
  let verified = 0;
  for (const line of auditLines) {
    const o = JSON.parse(line);
    if (await ed.verifyAsync(o.signature, canonicalReceiptBytes(o), o.public_key)) verified++;
  }
  const corpus = auditLines.join("\n") + "\n" + apprLines.join("\n");
  const pii = corpus.match(/\b(alice|bob|carol|dave|eve)\b|[\w.+-]+@[\w.-]+/i);
  if (verified !== auditLines.length - 1) throw new Error(`expected ${auditLines.length - 1} verified, got ${verified}`);
  if (pii) throw new Error(`PII token leaked: ${pii[0]}`);

  const dir = "src/demo/capture";
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/capture-audit.jsonl`, auditLines.join("\n") + "\n");
  writeFileSync(`${dir}/capture-approvals.jsonl`, apprLines.join("\n") + "\n");
  console.log(`✓ ${auditLines.length} receipts (${verified} verified, 1 tampered), ${apprLines.length} approvals — PII-free`);
}

main().catch((e) => { console.error(e); process.exit(1); });
