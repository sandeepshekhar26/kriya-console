//! The code that runs INSIDE the self-verifying artifact (bundled to a minified IIFE by esbuild and
//! inlined into the HTML). It re-verifies the embedded receipts entirely on-device:
//!   1. every signature, via the Console's real `verifyReceipt` (src/lib/verify.ts) — reused, not
//!      re-implemented, so the artifact's verdict is the same code the desktop app runs;
//!   2. the hash-chain, via `chainBreak` (src/lib/chain.ts) — the shared TS chain check.
//!
//! It NEVER fails open: if WebCrypto is unavailable (some `file://` / sandbox configs) it says so and
//! renders a neutral "not verified" banner — never green. Any parse/verify surprise renders red.
//!
//! Vanilla DOM only; no framework. Kept deliberately small so the whole artifact stays well under the
//! size budget and readable at 375px.

import { verifyReceipt } from "../lib/verify";
import type { SignedReceipt } from "../lib/types";
import { chainBreak } from "../lib/chain";
import { tamperOneByte, type TamperResult } from "../lib/selfverify";

const RECEIPTS_ID = "kriya-receipts";
const APP_ID = "app";
// The "allow with dest/bytes/hash" money-shot row — what the "Tamper one byte" button corrupts.
const TAMPER_TARGET_INDEX = 0;

interface Parsed {
  dir: string;
  kind: string;
  decision: string;
  host: string;
  bytesOut: number | null;
  bytesIn: number | null;
  ts: number | null;
  actionId: string;
  approvedBy: string | null;
  hashScheme: string | null;
}

/** Read the embedded JSONL verbatim and split into raw, non-empty lines (bytes preserved). */
function readEmbeddedLines(): string[] {
  const el = document.getElementById(RECEIPTS_ID);
  const text = el?.textContent ?? "";
  // Keep each line VERBATIM (the chain hashes these exact bytes); only drop whitespace-only lines.
  return text.split("\n").filter((l) => l.trim() !== "");
}

function parseReceipt(line: string): { receipt: SignedReceipt | null; view: Parsed } {
  const blank: Parsed = {
    dir: "?", kind: "?", decision: "?", host: "—", bytesOut: null, bytesIn: null, ts: null,
    actionId: "(unparseable)", approvedBy: null, hashScheme: null,
  };
  let receipt: SignedReceipt | null = null;
  try {
    receipt = JSON.parse(line) as SignedReceipt;
  } catch {
    return { receipt: null, view: blank };
  }
  const p = (receipt.params ?? {}) as Record<string, unknown>;
  // action_id shape: kriya.io.<direction>.<kind>.<decision>
  const facets = String(receipt.action_id ?? "").split(".");
  const isIo = facets[0] === "kriya" && facets[1] === "io";
  const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
  return {
    receipt,
    view: {
      dir: isIo ? facets[2] ?? "?" : "?",
      kind: str(p["dest_kind"]) ?? (isIo ? facets[3] ?? "?" : "?"),
      decision: str(p["decision"]) ?? (isIo ? facets[4] ?? "?" : "?"),
      host: str(p["dest_host"]) ?? "—",
      bytesOut: num(p["bytes_out"]),
      bytesIn: num(p["bytes_in"]),
      ts: num(receipt.ts_ms),
      actionId: String(receipt.action_id ?? "(none)"),
      approvedBy: str(p["approved_by"]),
      hashScheme: str(p["hash_scheme"]),
    },
  };
}

function fmtTime(ts: number | null): string {
  if (ts === null) return "—";
  const iso = new Date(ts).toISOString(); // 2026-06-18T09:32:41.000Z
  return iso.slice(0, 19).replace("T", " ") + "Z";
}

function fmtBytes(view: Parsed): string {
  const o = view.bytesOut === null ? "—" : String(view.bytesOut);
  const i = view.bytesIn === null ? "—" : String(view.bytesIn);
  return `↑${o} ↓${i}`;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  if (text !== undefined) node.textContent = text;
  return node;
}

// ---- module state --------------------------------------------------------------------------------
const original = readEmbeddedLines();
let working = [...original];
let lastTamper: TamperResult | null = null;
let showRaw = false;
let renderToken = 0;

function verdictBanner(
  kind: "ok" | "bad" | "warn",
  icon: string,
  headline: string,
  detail: string,
  bullets: string[] = [],
): HTMLElement {
  const box = el("div", { class: `verdict ${kind}` });
  box.append(el("div", { class: "icon" }, icon));
  const body = el("div");
  body.append(el("div", { class: "headline" }, headline));
  body.append(el("div", { class: "detail" }, detail));
  if (bullets.length) {
    const ul = el("ul");
    for (const b of bullets) ul.append(el("li", {}, b));
    body.append(ul);
  }
  box.append(body);
  return box;
}

function buildTable(views: Parsed[], sigOk: boolean[]): HTMLElement {
  const wrap = el("div", { class: "tablewrap" });
  const table = el("table");
  const thead = el("thead");
  const htr = el("tr");
  for (const h of ["Time (UTC)", "Dir", "Destination", "Kind", "Bytes", "Decision", "Signature"]) {
    htr.append(el("th", {}, h));
  }
  thead.append(htr);
  table.append(thead);
  const tbody = el("tbody");
  views.forEach((v, i) => {
    const tr = el("tr");
    tr.append(el("td", {}, fmtTime(v.ts)));
    tr.append(el("td", { class: "dir" }, v.dir === "egress" ? "egress ↑" : v.dir === "ingress" ? "ingress ↓" : v.dir));
    const host = el("td", { class: "host" }, v.host);
    if (v.hashScheme) host.title = `content hash scheme: ${v.hashScheme}`;
    tr.append(host);
    tr.append(el("td", {}, v.kind));
    tr.append(el("td", { class: "bytes" }, fmtBytes(v)));
    const dec = el("td");
    const badge = el("span", { class: `badge ${v.decision}` }, v.decision);
    if (v.approvedBy) badge.title = `approved_by: ${v.approvedBy}`;
    dec.append(badge);
    tr.append(dec);
    const ok = sigOk[i] ?? false;
    tr.append(el("td", { class: `sig ${ok ? "ok" : "bad"}` }, ok ? "✓ valid" : "✗ invalid"));
    tbody.append(tr);
  });
  table.append(tbody);
  wrap.append(table);
  return wrap;
}

function buildControls(): HTMLElement {
  const c = el("div", { class: "controls" });

  const rawBtn = el("button", {}, showRaw ? "Hide raw JSONL" : "View raw JSONL");
  rawBtn.addEventListener("click", () => {
    showRaw = !showRaw;
    void render();
  });
  c.append(rawBtn);

  const tamperBtn = el("button", { class: "primary" }, "Tamper one byte");
  if (lastTamper) tamperBtn.setAttribute("disabled", "true");
  tamperBtn.addEventListener("click", () => {
    const target = working[TAMPER_TARGET_INDEX];
    if (target === undefined) return;
    const result = tamperOneByte(target);
    working = working.map((l, i) => (i === TAMPER_TARGET_INDEX ? result.line : l));
    lastTamper = result;
    void render();
  });
  c.append(tamperBtn);

  const restoreBtn = el("button", {}, "Restore");
  if (!lastTamper) restoreBtn.setAttribute("disabled", "true");
  restoreBtn.addEventListener("click", () => {
    working = [...original];
    lastTamper = null;
    void render();
  });
  c.append(restoreBtn);

  return c;
}

async function render(): Promise<void> {
  const app = document.getElementById(APP_ID);
  if (!app) return;
  const token = ++renderToken;

  // Fail-closed: without WebCrypto we cannot verify anything — say so, never imply a pass.
  if (typeof crypto === "undefined" || !crypto.subtle) {
    app.replaceChildren(
      verdictBanner(
        "warn",
        "⚠",
        "WebCrypto blocked — not verified",
        "This browser/context did not expose the cryptographic API (crypto.subtle) needed to check " +
          "these signatures. Verification did NOT run — this is not a pass. Open the file directly in a " +
          "current browser, or re-verify with the open kriya-audit CLI.",
      ),
    );
    return;
  }

  if (working.length === 0) {
    app.replaceChildren(
      verdictBanner("bad", "✗", "No receipts found", "The embedded receipt block is empty or was removed."),
    );
    return;
  }

  // Verify signatures (reusing the Console's verifier) and the hash-chain independently.
  const parsed = working.map(parseReceipt);
  const sigResults = await Promise.all(
    parsed.map((p) =>
      p.receipt ? verifyReceipt(p.receipt) : Promise.resolve({ ok: false as const, reason: "line is not valid JSON" }),
    ),
  );
  const chainIdx = await chainBreak(working);
  if (token !== renderToken) return; // a newer render superseded this one

  const sigOk = sigResults.map((r) => r.ok === true);
  const allSigsOk = sigOk.every(Boolean);
  const chainOk = chainIdx === null;

  const controls = buildControls();
  const table = buildTable(parsed.map((p) => p.view), sigOk);

  let banner: HTMLElement;
  if (allSigsOk && chainOk) {
    banner = verdictBanner(
      "ok",
      "✓",
      `Verified offline — ${working.length} signed receipts`,
      "Every Ed25519 signature is valid and the hash-chain is intact. This ran entirely in your " +
        "browser — nothing left your machine.",
    );
  } else {
    const bullets: string[] = [];
    if (lastTamper) {
      bullets.push(`You changed ${lastTamper.before} → ${lastTamper.after} on receipt #${TAMPER_TARGET_INDEX + 1}.`);
    }
    parsed.forEach((p, i) => {
      if (!sigOk[i]) {
        const reason = sigResults[i]?.ok === false ? sigResults[i]?.reason : "signature does not match";
        bullets.push(`Receipt #${i + 1} (${p.view.actionId}): signature invalid — ${reason}.`);
      }
    });
    if (chainIdx !== null) {
      bullets.push(
        `Hash-chain break at receipt #${chainIdx}: prev_hash ≠ SHA-256 of the previous line ` +
          "(a line was altered, inserted, deleted, or reordered).",
      );
    }
    banner = verdictBanner(
      "bad",
      "✗",
      "Tampering detected",
      "At least one check failed. Two independent mechanisms caught it — the per-receipt signature " +
        "and the hash-chain over the raw lines.",
      bullets,
    );
  }

  const children: Node[] = [banner, controls, table];
  const legend = el(
    "div",
    { class: "legend" },
    "Signature = the receipt's own Ed25519 signature over its canonical bytes. " +
      "Chain = each line's prev_hash is the SHA-256 of the previous raw line. Both re-checked here, offline.",
  );
  children.push(legend);
  if (showRaw) {
    children.push(el("pre", { class: "raw" }, working.join("\n")));
  }
  app.replaceChildren(...children);
}

void render();
