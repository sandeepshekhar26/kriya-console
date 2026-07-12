//! `renderSelfVerifyingHtml` — render a set of signed, hash-chained receipts into ONE self-contained
//! HTML file that re-verifies itself in the browser, offline, with zero external references. The
//! bundled verifier (esbuild IIFE of `src/selfverify/runtime.ts`) is inlined by the caller; this
//! module only lays out the page and embeds the RAW JSONL verbatim (re-serializing would change the
//! bytes the hash-chain committed to, so the embedded lines must be byte-identical to what was
//! signed). It is the reusable core R5-1 later extends with an `EvidenceBundle` (see the payload type).
//!
//! GUARDRAIL (binding on R5-1): rendering REAL receipts through this template is gated on a redaction
//! profile — actor pseudonymized, content_sha256 omitted or keyed, dest_host only where the export's
//! stated purpose requires it — and the export itself is receipted. The shipped demo uses only
//! SYNTHETIC receipts (dedicated published key, `params.synthetic: true`) so real and demo artifacts
//! stay cryptographically distinguishable forever.

/**
 * Forward-declared seam for R5-1: a computed evidence bundle (deny-by-default, approval gates, budget
 * caps, coverage statement, framework mapping — the same facts `compliance.ts` renders) that a future
 * runtime will paint above the receipt table. Intentionally open; the egress demo passes none.
 */
export interface EvidenceBundle {
  [key: string]: unknown;
}

/** The inputs to a self-verifying artifact. `jsonl` is load-bearing: RAW lines, verbatim. */
export interface SelfVerifyPayload {
  /** Document title + <title>. */
  title: string;
  /** Human-readable "generated" stamp shown in the header (kept fixed for reproducible artifacts). */
  generatedAt: string;
  /** The receipts as RAW JSONL — one receipt per line, LF-separated, exactly as signed and hashed. */
  jsonl: string;
  /** The honesty note, rendered verbatim in the footer (scope ceiling — no overclaim). */
  honestyNote: string;
  /** Optional; R5-1 will populate + render this. Embedded as a second JSON block when present. */
  bundle?: EvidenceBundle;
}

/** What `tamperOneByte` changed — surfaced in the artifact's red banner so the demo names the field. */
export interface TamperResult {
  /** The mutated JSONL line (exactly one value byte changed). */
  line: string;
  /** The field whose value was altered. */
  field: string;
  /** Original value, for the banner ("bytes_out=4300"). */
  before: string;
  /** Altered value, for the banner ("bytes_out=5300"). */
  after: string;
}

// Prefer a human-visible data field so the demo reads clearly; the signature fallback guarantees the
// function ALWAYS returns a line that fails verification, whatever shape the receipt has.
const TAMPER_TARGETS = ["bytes_out", "bytes_in", "ts_ms", "dest_host"] as const;

/**
 * Flip exactly one byte of one receipt line so it no longer verifies — the interactive "Tamper one
 * byte" act. Reused by both the artifact runtime and the test suite so there is a single definition of
 * "what a tamper is". Changing any signed field breaks the Ed25519 signature (the verifier
 * re-canonicalizes from the fields); changing any byte also breaks the downstream hash-chain link.
 */
export function tamperOneByte(line: string): TamperResult {
  for (const field of TAMPER_TARGETS) {
    // numeric field: "field":123
    const numRe = new RegExp(`("${field}":)(\\d+)`);
    const nm = numRe.exec(line);
    if (nm) {
      const digits = nm[2] as string;
      const first = digits[0] as string;
      const newFirst = first === "9" ? "8" : String(Number(first) + 1);
      const flipped = newFirst + digits.slice(1);
      return {
        line: line.replace(numRe, `$1${flipped}`),
        field,
        before: `${field}=${digits}`,
        after: `${field}=${flipped}`,
      };
    }
    // string field: "field":"abc"
    const strRe = new RegExp(`("${field}":")([^"\\\\]+)(")`);
    const sm = strRe.exec(line);
    if (sm) {
      const val = sm[2] as string;
      const first = val[0] as string;
      const flipped = (first === "a" ? "b" : "a") + val.slice(1);
      return {
        line: line.replace(strRe, `$1${flipped}$3`),
        field,
        before: `${field}=${val}`,
        after: `${field}=${flipped}`,
      };
    }
  }
  // Fallback: corrupt one hex nibble of the signature — always present, always breaks verification.
  const sigRe = /("signature":")([0-9a-f])([0-9a-f]{127}")/;
  const sm = sigRe.exec(line);
  if (sm) {
    const first = sm[2] as string;
    const flipped = first === "a" ? "b" : "a";
    return {
      line: line.replace(sigRe, `$1${flipped}$3`),
      field: "signature",
      before: `signature[0]=${first}`,
      after: `signature[0]=${flipped}`,
    };
  }
  throw new Error("tamperOneByte: no tamperable field found in line");
}

// Escape for a TEXT-node context (all interpolations below are element text, never attribute values).
// Only `& < >` are special in text content; apostrophes/quotes are left as-is so the honesty note and
// title appear byte-verbatim in the source, not just on screen.
const escapeText = (s: string): string =>
  s.replace(/[&<>]/g, (c) => (c === "&" ? "&amp;" : c === "<" ? "&lt;" : "&gt;"));

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --panel: #ffffff; --ink: #1a1d21; --muted: #5b6470; --line: #e2e6ea;
  --accent: #2f6feb; --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --ok-bg: #e7f6ec; --ok-ink: #0f7a37; --ok-line: #b6e2c6;
  --bad-bg: #fdeaea; --bad-ink: #c0322b; --bad-line: #f3c2bf;
  --warn-bg: #fdf4e3; --warn-ink: #9a6a10; --warn-line: #f0dcae;
  --neutral-bg: #eef1f4; --neutral-ink: #45505c;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171b; --panel: #1c2026; --ink: #e8ebee; --muted: #98a2ad; --line: #2a2f36;
    --accent: #5b8cf0;
    --ok-bg: #102c1b; --ok-ink: #55d089; --ok-line: #1f5236;
    --bad-bg: #331817; --bad-ink: #f08a83; --bad-line: #63302c;
    --warn-bg: #2e2611; --warn-ink: #e0b357; --warn-line: #574716;
    --neutral-bg: #232830; --neutral-ink: #aeb8c2;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  -webkit-text-size-adjust: 100%;
}
.wrap { max-width: 900px; margin: 0 auto; padding: 24px 16px 48px; }
header.doc { margin-bottom: 18px; }
header.doc h1 { font-size: 20px; margin: 0 0 4px; letter-spacing: -0.01em; }
header.doc .sub { color: var(--muted); font-size: 13px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }
#app { margin: 16px 0; }
.verdict {
  display: flex; gap: 12px; align-items: flex-start; padding: 16px 18px; border-radius: 12px;
  border: 1px solid var(--line); background: var(--neutral-bg);
}
.verdict .icon { font-size: 22px; line-height: 1.1; }
.verdict .headline { font-weight: 650; font-size: 16px; }
.verdict .detail { color: var(--muted); font-size: 13.5px; margin-top: 3px; }
.verdict.ok { background: var(--ok-bg); border-color: var(--ok-line); }
.verdict.ok .headline, .verdict.ok .icon { color: var(--ok-ink); }
.verdict.bad { background: var(--bad-bg); border-color: var(--bad-line); }
.verdict.bad .headline, .verdict.bad .icon { color: var(--bad-ink); }
.verdict.warn { background: var(--warn-bg); border-color: var(--warn-line); }
.verdict.warn .headline, .verdict.warn .icon { color: var(--warn-ink); }
.verdict ul { margin: 8px 0 0; padding-left: 18px; }
.verdict li { font-size: 13px; margin: 2px 0; }
.controls { display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0; }
button {
  font: inherit; font-size: 13.5px; font-weight: 550; cursor: pointer;
  background: var(--panel); color: var(--ink); border: 1px solid var(--line);
  border-radius: 8px; padding: 8px 13px;
}
button:hover { border-color: var(--accent); }
button.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
button:disabled { opacity: 0.5; cursor: default; }
.tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; background: var(--panel); }
table { border-collapse: collapse; width: 100%; font-size: 13px; min-width: 640px; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }
th { color: var(--muted); font-weight: 600; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.04em; }
tr:last-child td { border-bottom: none; }
td.host { font-family: var(--mono); font-size: 12px; }
td.bytes { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11.5px; font-weight: 600; }
.badge.allow { background: var(--ok-bg); color: var(--ok-ink); }
.badge.deny { background: var(--bad-bg); color: var(--bad-ink); }
.badge.approve { background: var(--warn-bg); color: var(--warn-ink); }
.sig.ok { color: var(--ok-ink); font-weight: 650; }
.sig.bad { color: var(--bad-ink); font-weight: 650; }
.dir { color: var(--muted); }
pre.raw {
  margin: 12px 0 0; padding: 14px; background: var(--panel); border: 1px solid var(--line);
  border-radius: 12px; overflow-x: auto; font-family: var(--mono); font-size: 11.5px; line-height: 1.5;
  white-space: pre; color: var(--ink);
}
footer.note {
  margin-top: 24px; padding: 16px 18px; background: var(--panel); border: 1px solid var(--line);
  border-radius: 12px; color: var(--muted); font-size: 12.5px; line-height: 1.6;
}
footer.note b { color: var(--ink); }
.legend { color: var(--muted); font-size: 12px; margin-top: 10px; }
@media (max-width: 420px) {
  .wrap { padding: 16px 10px 40px; }
  header.doc h1 { font-size: 18px; }
}
`.trim();

/**
 * Render a complete, standalone HTML document (doctype → body) that verifies its own embedded receipts
 * offline. `verifierJs` is the minified IIFE bundle of the runtime — inlined as-is. The caller
 * guarantees `jsonl` and `verifierJs` contain no `</script` sequence (asserted at generation time).
 */
export function renderSelfVerifyingHtml(payload: SelfVerifyPayload, verifierJs: string): string {
  const bundleBlock = payload.bundle
    ? `\n<script type="application/json" id="kriya-bundle">\n${JSON.stringify(payload.bundle)}\n</script>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeText(payload.title)}</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
  <header class="doc">
    <h1>${escapeText(payload.title)}</h1>
    <div class="sub">${escapeText(payload.generatedAt)} · verifies offline in your browser — no server, no network</div>
  </header>
  <main id="app">
    <div class="verdict warn">
      <div class="icon">…</div>
      <div>
        <div class="headline">Verifying…</div>
        <div class="detail">Re-checking every signature and the hash-chain, locally.</div>
      </div>
    </div>
    <noscript>
      <div class="verdict warn" style="margin-top:12px">
        <div class="icon">⚠</div>
        <div><div class="headline">JavaScript is off</div><div class="detail">Live verification needs JavaScript. The receipts are embedded below and can be re-verified with the open <code>kriya-audit</code> CLI.</div></div>
      </div>
    </noscript>
  </main>
  <footer class="note">${escapeText(payload.honestyNote)}</footer>
</div>
<script type="application/json" id="kriya-receipts">
${payload.jsonl}
</script>${bundleBlock}
<script>${verifierJs}</script>
</body>
</html>
`;
}
