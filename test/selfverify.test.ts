import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyReceipt } from "../src/lib/verify";
import { chainBreak, sha256Hex } from "../src/lib/chain";
import { renderSelfVerifyingHtml, tamperOneByte } from "../src/lib/selfverify";
import type { SignedReceipt } from "../src/lib/types";

const here = dirname(fileURLToPath(import.meta.url));
const sampleDir = join(here, "../docs/gtm/samples/egress-receipt-demo");
const jsonlFile = readFileSync(join(sampleDir, "receipts.jsonl"), "utf8");
const htmlFile = readFileSync(join(sampleDir, "kriya-egress-receipts.html"), "utf8");

// The committed receipts.jsonl, as raw lines (the exact bytes signed + hashed).
const lines = jsonlFile.split("\n").filter((l) => l.trim() !== "");

/** Pull the embedded JSONL back out of the artifact exactly as the in-browser runtime reads it. */
function embeddedJsonl(html: string): string {
  const m = /<script type="application\/json" id="kriya-receipts">\n([\s\S]*?)\n<\/script>/.exec(html);
  if (!m) throw new Error("embedded receipts block not found");
  return m[1] as string;
}

describe("EG-1 self-verifying egress artifact", () => {
  it("has the expected 7 receipts", () => {
    expect(lines).toHaveLength(7);
  });

  // (a) the embedded JSONL round-trips verbatim — byte-identical to the standalone receipts.jsonl.
  it("(a) embeds the JSONL verbatim (re-serializing would break the chain)", () => {
    const embedded = embeddedJsonl(htmlFile);
    expect(embedded).toBe(jsonlFile.replace(/\n$/, ""));
    expect(embedded.split("\n")).toEqual(lines);
  });

  // (b) all 7 lines pass verifyReceipt AND the hash-chain check.
  it("(b) every receipt's signature verifies and the chain is intact", async () => {
    for (const line of lines) {
      const receipt = JSON.parse(line) as SignedReceipt;
      expect((await verifyReceipt(receipt)).ok).toBe(true);
    }
    expect(await chainBreak(lines)).toBeNull();
  });

  it("(b') the chain links line N to the SHA-256 of raw line N-1", async () => {
    for (let i = 1; i < lines.length; i++) {
      const declared = (JSON.parse(lines[i] as string) as { prev_hash?: string }).prev_hash;
      expect(declared).toBe(await sha256Hex(lines[i - 1] as string));
    }
    // The genesis line must carry no prev_hash.
    expect((JSON.parse(lines[0] as string) as { prev_hash?: string }).prev_hash).toBeUndefined();
  });

  // (c) tamperOneByte breaks verification for EVERY receipt index.
  it("(c) flipping one byte breaks verification for every receipt", async () => {
    for (let i = 0; i < lines.length; i++) {
      const { line: tampered, field } = tamperOneByte(lines[i] as string);
      expect(tampered).not.toBe(lines[i]);
      expect(field.length).toBeGreaterThan(0);
      const receipt = JSON.parse(tampered) as SignedReceipt;
      expect((await verifyReceipt(receipt)).ok).toBe(false);
    }
  });

  // (d) the rendered HTML has no external reference (nothing loads off-box).
  it("(d) contains no external references", () => {
    const external = [
      /\b(?:src|href)\s*=\s*["']?https?:\/\//i,
      /url\(\s*['"]?https?:\/\//i,
      /@import[^;]*https?:\/\//i,
    ];
    for (const re of external) expect(htmlFile).not.toMatch(re);
    // and the same guard on a freshly rendered page (not just the committed one).
    const rendered = renderSelfVerifyingHtml(
      { title: "t", generatedAt: "g", jsonl: lines.join("\n"), honestyNote: "n" },
      "/* inert verifier */",
    );
    for (const re of external) expect(rendered).not.toMatch(re);
  });

  // (e) deleting a middle line breaks the chain at the right index.
  it("(e) deleting a middle line breaks the chain at that position", async () => {
    const withoutMiddle = lines.filter((_, i) => i !== 3); // drop the 4th line (0-based 3)
    // Lines 1..3 still chain; the line now at position 3 (0-based) declares a prev_hash for the
    // line that used to precede it → break at 1-based index 4.
    expect(await chainBreak(withoutMiddle)).toBe(4);
    // Dropping the genesis line breaks at line 1 (the new first line points back at nothing).
    expect(await chainBreak(lines.slice(1))).toBe(1);
    // Reordering two lines also breaks it.
    const swapped = [...lines];
    [swapped[2], swapped[3]] = [swapped[3] as string, swapped[2] as string];
    expect(await chainBreak(swapped)).not.toBeNull();
  });
});

describe("EG-1 honesty + privacy guards", () => {
  it("renders the honesty note verbatim in the footer", () => {
    expect(htmlFile).toContain(
      "Host-level egress — a spawned curl, a subprocess, a stdio server's own outbound HTTP — is the",
    );
    expect(htmlFile).toContain("Flip any byte in this file and the verdict below goes red — that's the point.");
  });

  it("never uses the word DLP, and carries no PII", () => {
    expect(htmlFile).not.toMatch(/\bDLP\b/);
    expect(jsonlFile).not.toMatch(/\bDLP\b/);
    expect(jsonlFile).not.toMatch(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
    expect(jsonlFile).not.toMatch(/\b(alice|bob|carol|dave|eve)\b/i);
  });

  it("marks every receipt synthetic and signs them all with the one demo key", () => {
    const keys = new Set<string>();
    for (const line of lines) {
      const r = JSON.parse(line) as SignedReceipt & { params: { synthetic?: boolean } };
      expect(r.params.synthetic).toBe(true);
      keys.add(r.public_key);
    }
    expect(keys.size).toBe(1); // a single dedicated demo key
  });
});
