// gen-egress-demo.mts — mint the EG-1 self-verifying egress-receipt artifact (doc 24 §4.4).
//
//   npm run gen:egress-demo
//
// Produces docs/samples/egress-receipt-demo/{kriya-egress-receipts.html, receipts.jsonl, README.md}:
// 7 Ed25519-signed, hash-chained, egress-shaped receipts on the EXISTING schema (the kriya.io.*
// vocabulary, §4.2 — no schema change), that re-verify themselves offline in the browser using the
// Console's REAL verifier (src/lib/verify.ts, bundled into the page by esbuild) plus the shared TS
// hash-chain check (src/lib/chain.ts). Copies the gen-capture-data.mjs idiom: deterministic keys,
// PII-free role handles, self-checked before writing.
//
// PRIVACY GUARDRAILS (§6-P5 — this artifact pattern must not become an ungoverned egress channel):
//   * every receipt is signed by a DEDICATED, PUBLISHED demo key and carries params.synthetic:true,
//     so real and demo receipts stay cryptographically distinguishable forever;
//   * this script REFUSES any input path under ~/.kriya/audit/ (hard error) — it renders synthetic
//     receipts only; rendering REAL receipts through the template is gated on a redaction profile
//     (see the guardrail note in src/lib/selfverify.ts).
import * as ed from "@noble/ed25519";
import { createHash, webcrypto } from "node:crypto";
import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, sep } from "node:path";
import { canonicalReceiptBytes, verifyReceipt } from "../src/lib/verify.ts";
import { renderSelfVerifyingHtml } from "../src/lib/selfverify.ts";
import type { SignedReceipt } from "../src/lib/types.ts";

const subtle = (globalThis.crypto ?? (webcrypto as unknown as Crypto)).subtle;
ed.etc.sha512Async = async (...m: Uint8Array[]) =>
  new Uint8Array(await subtle.digest("SHA-512", ed.etc.concatBytes(...m)));

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const enc = new TextEncoder();
const hex = (u: Uint8Array): string => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (s: string): Uint8Array => Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));
const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

/**
 * Hard-refuse any argument that resolves under ~/.kriya/audit/. This generator mints synthetic data
 * and takes no real input; the guard exists so a future edit that adds an input path can never quietly
 * pipe a real audit log through the (un-redacted) demo template.
 */
function refuseRealAuditInput(args: string[]): void {
  const auditDir = resolve(homedir(), ".kriya", "audit");
  for (const a of args) {
    if (a.startsWith("-")) continue;
    const p = resolve(a);
    if (p === auditDir || p.startsWith(auditDir + sep)) {
      throw new Error(
        `refusing to read real audit input under ${auditDir}: "${a}". This template renders SYNTHETIC ` +
          "demo receipts only; rendering real receipts is gated on a redaction profile (see src/lib/selfverify.ts).",
      );
    }
  }
}

// --- the dedicated, PUBLISHED demo signer key (NEVER used for real receipts) ---
const DEMO_PRIV = fromHex("de70de70de70de70de70de70de70de70de70de70de70de70de70de70de70de70");
// PII-free role handles only — no people-names, no emails.
const ACTOR = { agent: "claude-code", user: "platform-eng" };
const BASE = 1781700000000;

// The 7 governed-I/O rows (doc 24 §4.4): allow w/ dest+bytes+hash · ingress provenance · model call ·
// DENY against default-deny · second vendor call · APPROVE w/ approved_by · ingress http. action_id =
// kriya.io.<direction>.<kind>.<decision>; dest_kind is pinned to the id's kind facet (§4.2.5).
interface Row {
  action_id: string;
  success: boolean;
  params: Record<string, string | number>;
}
const ROWS: Row[] = [
  {
    action_id: "kriya.io.egress.mcp.allow",
    success: true,
    params: {
      dest_host: "api.vendor-crm.example", dest_kind: "mcp", method: "tools/call",
      bytes_out: 4300, bytes_in: 18240, content_sha256: sha256("synthetic:egress:vendor-crm:call"),
      hash_scheme: "wire-bytes", policy_rule: "*.vendor-crm.example", decision: "allow",
    },
  },
  {
    action_id: "kriya.io.ingress.mcp.allow", // ingress provenance — the response the connector returned
    success: true,
    params: {
      dest_host: "api.vendor-crm.example", dest_kind: "mcp", method: "tools/call",
      bytes_out: 0, bytes_in: 18240, content_sha256: sha256("synthetic:ingress:vendor-crm:resp"),
      hash_scheme: "wire-bytes", policy_rule: "*.vendor-crm.example", decision: "allow",
    },
  },
  {
    action_id: "kriya.io.egress.model.allow", // a model call
    success: true,
    params: {
      dest_host: "api.model-provider.example", dest_kind: "model", method: "messages",
      bytes_out: 2100, bytes_in: 6400, content_sha256: sha256("synthetic:egress:model:messages"),
      hash_scheme: "wire-bytes", policy_rule: "api.model-provider.example", decision: "allow",
    },
  },
  {
    action_id: "kriya.io.egress.http.deny", // DENY against default-deny (blocked before send)
    success: false, // blocked/failed attempts are receipts too, success:false (runtime convention)
    params: {
      dest_host: "api.unknown-3p.example", dest_kind: "http", method: "POST",
      bytes_out: 0, bytes_in: 0, hash_scheme: "wire-bytes",
      policy_rule: "default-deny", decision: "deny",
    },
  },
  {
    action_id: "kriya.io.egress.mcp.allow", // a second, different vendor
    success: true,
    params: {
      dest_host: "api.vendor-search.example", dest_kind: "mcp", method: "tools/call",
      bytes_out: 880, bytes_in: 5120, content_sha256: sha256("synthetic:egress:vendor-search:call"),
      hash_scheme: "wire-bytes", policy_rule: "*.vendor-search.example", decision: "allow",
    },
  },
  {
    action_id: "kriya.io.egress.http.approve", // APPROVE with approved_by
    success: true,
    params: {
      dest_host: "hooks.partner-webhook.example", dest_kind: "http", method: "POST",
      bytes_out: 1536, bytes_in: 64, content_sha256: sha256("synthetic:egress:webhook:post"),
      hash_scheme: "wire-bytes", policy_rule: "approve:hooks.partner-webhook.example",
      decision: "approve", approved_by: "secops-oncall",
    },
  },
  {
    action_id: "kriya.io.ingress.http.allow", // ingress http (hook lane → canonical-json hash scheme)
    success: true,
    params: {
      dest_host: "docs.partner-feed.example", dest_kind: "http", method: "GET",
      bytes_out: 0, bytes_in: 9400, content_sha256: sha256("synthetic:ingress:partner-feed:get"),
      hash_scheme: "canonical-json", policy_rule: "docs.partner-feed.example", decision: "allow",
    },
  },
];

const HONESTY_NOTE =
  "These are governed-lane records: kriya signs the calls it proxies (MCP connectors, tool calls). " +
  "Host-level egress — a spawned curl, a subprocess, a stdio server's own outbound HTTP — is the " +
  "watcher layer, not claimed here. Full-fidelity records stay on the device; only minimized counts " +
  "ever leave it. Flip any byte in this file and the verdict below goes red — that's the point.";

async function main(): Promise<void> {
  refuseRealAuditInput(process.argv.slice(2));

  const pub = hex(await ed.getPublicKeyAsync(DEMO_PRIV));
  const lines: string[] = [];
  let prevHash: string | null = null;

  for (let i = 0; i < ROWS.length; i++) {
    const row = ROWS[i]!;
    const params = { corr: `act-${String(i + 1).padStart(4, "0")}`, ...row.params, synthetic: true };
    // Field order mirrors the signed struct; prev_hash present only after the genesis line.
    const receipt: SignedReceipt = {
      step_id: `kriya-io-${String(i + 1).padStart(4, "0")}`,
      action_id: row.action_id,
      params,
      success: row.success,
      ts_ms: BASE + i * 137000,
      actor: ACTOR,
      ...(prevHash !== null ? { prev_hash: prevHash } : {}),
      // public_key/signature appended below
    } as SignedReceipt;
    const signature = hex(await ed.signAsync(canonicalReceiptBytes(receipt), DEMO_PRIV));
    const line = JSON.stringify({ ...receipt, public_key: pub, signature });
    lines.push(line);
    prevHash = sha256(line); // R20: prev_hash of the NEXT line = SHA-256 of THIS raw line's bytes
  }

  // ---- self-checks: a false green here is unrecoverable, so verify everything before writing ----
  // (1) every signature verifies as committed.
  let verified = 0;
  for (const line of lines) {
    if ((await verifyReceipt(JSON.parse(line) as SignedReceipt)).ok) verified++;
  }
  if (verified !== lines.length) throw new Error(`expected all ${lines.length} to verify, got ${verified}`);

  // (2) the hash-chain links line N to N-1 (recompute independently of how we built it).
  let expected: string | null = null;
  for (let i = 0; i < lines.length; i++) {
    const declared = (JSON.parse(lines[i]!) as { prev_hash?: string }).prev_hash ?? null;
    if (declared !== expected) throw new Error(`chain break at line ${i + 1}: ${declared} !== ${expected}`);
    expected = sha256(lines[i]!);
  }

  // (3) the deny receipt records a blocked attempt (success:false); (4) exactly one deny.
  const denyIdx = ROWS.findIndex((r) => r.action_id.endsWith(".deny"));
  if (denyIdx < 0 || ROWS[denyIdx]!.success !== false) throw new Error("the deny receipt must be success:false");

  const jsonl = lines.join("\n");
  // (5) PII-free, and (6) ASCII-only so the browser's UTF-8 bytes equal the bytes Rust hashed.
  const pii = jsonl.match(/\b(alice|bob|carol|dave|eve)\b|[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
  if (pii) throw new Error(`PII / email token leaked: ${pii[0]}`);
  const nonAscii = [...jsonl].find((c) => c.charCodeAt(0) > 0x7f);
  if (nonAscii) throw new Error(`non-ASCII byte in receipts (breaks hash byte-parity): ${JSON.stringify(nonAscii)}`);
  if (/<\/script/i.test(jsonl)) throw new Error("receipts contain </script — would break the embedded JSON block");

  // ---- bundle the in-artifact runtime to a self-contained minified IIFE ----
  const esbuild = join(repoRoot, "node_modules", ".bin", "esbuild");
  const entry = join(repoRoot, "src", "selfverify", "runtime.ts");
  const verifierJs = execSync(`"${esbuild}" "${entry}" --bundle --format=iife --minify --target=es2020`, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (/<\/script/i.test(verifierJs)) throw new Error("bundled verifier contains </script — cannot inline safely");

  const html = renderSelfVerifyingHtml(
    {
      title: "kriya — governed egress receipts (verifies itself)",
      generatedAt: "kriya governed-egress sample · synthetic dataset (2026-06)",
      jsonl,
      honestyNote: HONESTY_NOTE,
    },
    verifierJs,
  );
  // (7) no external references in the rendered page (test enforces this too; assert here as a tripwire).
  for (const re of [/\b(?:src|href)\s*=\s*["']?https?:\/\//i, /url\(\s*['"]?https?:\/\//i, /@import[^;]*https?:\/\//i]) {
    if (re.test(html)) throw new Error(`rendered HTML has an external reference matching ${re}`);
  }

  const outDir = join(repoRoot, "docs", "gtm", "samples", "egress-receipt-demo");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "receipts.jsonl"), jsonl + "\n");
  writeFileSync(join(outDir, "kriya-egress-receipts.html"), html);
  writeFileSync(join(outDir, "README.md"), readme(pub, html.length));

  console.log(
    `✓ ${lines.length} egress receipts (${verified} verified, chain intact, 1 deny), ` +
      `HTML ${(html.length / 1024).toFixed(1)} KB, PII-free — wrote ${outDir}`,
  );
}

function readme(pubKey: string, htmlBytes: number): string {
  return `# Self-verifying egress receipts (EG-1 sample)

\`kriya-egress-receipts.html\` is one self-contained file (~${(htmlBytes / 1024).toFixed(0)} KB) that
**re-verifies itself in your browser, offline**. Open it directly from disk (\`file://\`) with
networking off: it re-checks every Ed25519 signature and the hash-chain and shows a green verdict —
zero network requests. Press **Tamper one byte** (or hand-edit a \`bytes_out\` value in a text editor
and reopen) and the verdict goes red, naming the receipt and field.

It is the same verifier the Console runs (\`src/lib/verify.ts\`), bundled into the page — not a mock.

## What's in it

Seven signed, hash-chained receipts on the existing schema, using the \`kriya.io.*\` vocabulary
(doc 24 §4.2 — \`kriya.io.<direction>.<kind>.<decision>\`):

| # | action_id | what it shows |
|---|---|---|
| 1 | \`kriya.io.egress.mcp.allow\` | an **allowed** connector call — destination, bytes, content hash |
| 2 | \`kriya.io.ingress.mcp.allow\` | **ingress provenance** — the response that came back |
| 3 | \`kriya.io.egress.model.allow\` | a **model** call |
| 4 | \`kriya.io.egress.http.deny\` | a **DENY** against \`default-deny\` (\`success:false\`) |
| 5 | \`kriya.io.egress.mcp.allow\` | a **second vendor** |
| 6 | \`kriya.io.egress.http.approve\` | an **APPROVE**, with \`approved_by\` |
| 7 | \`kriya.io.ingress.http.allow\` | **ingress http** (hook lane → \`canonical-json\` hash scheme) |

Each \`kriya.io.*\` receipt carries \`hash_scheme\` (\`wire-bytes\` on the gateway lane,
\`canonical-json\` on the hook lane) so the record says exactly what its \`content_sha256\` commits to.

## Verify it yourself, three ways

1. **In the browser** — open \`kriya-egress-receipts.html\`. No server, no network.
2. **With the open CLI** — \`kriya-audit receipts.jsonl\` (signature-gated; also reports the chain):
   \`\`\`
   ./dist-audit/kriya-audit docs/samples/egress-receipt-demo/receipts.jsonl
   \`\`\`
3. **Flip a byte** — edit any digit in \`receipts.jsonl\` and re-run the CLI, or edit the embedded
   block in the HTML and reopen it. Both go red.

## Regenerate

\`\`\`
npm run gen:egress-demo
\`\`\`

Deterministic: fixed demo key + fixed timestamps, so the committed files are byte-stable across runs.

## The demo key (published on purpose)

These receipts are signed by a **dedicated demo key** and every one carries \`params.synthetic:true\`,
so demo receipts are cryptographically distinguishable from real ones forever. The key is published so
anyone can regenerate and re-verify:

- private (32-byte seed, hex): \`de70de70…de70\` (repeated \`de70\`) — see \`scripts/gen-egress-demo.mts\`
- public: \`${pubKey}\`

It is **never** used for real receipts.

## Scope (honest ceiling — read this)

These are **governed-lane** records: kriya signs the calls it proxies (MCP connectors, tool calls).
Host-level egress — a spawned \`curl\`, a subprocess, a stdio server's own outbound HTTP — is the
watcher layer, not claimed here. Rendering **real** receipts through this template is gated on a
redaction profile (actor pseudonymized, \`content_sha256\` omitted or keyed, \`dest_host\` only where
the export's stated purpose requires it) and the export itself is receipted — see the guardrail note
in \`src/lib/selfverify.ts\`.
`;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
