import { verifyReceipt } from "./verify";
import type { AuditRow, SignedReceipt } from "./types";

/**
 * Parse a JSONL audit log and verify every line. `source` labels where the log
 * came from (a filename), which is how the viewer groups receipts per app.
 * Malformed or non-receipt lines become failed rows rather than throwing.
 */
export async function loadAuditLog(text: string, source: string): Promise<AuditRow[]> {
  const lines = text.split("\n");
  const rows: AuditRow[] = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string;
    if (raw.trim() === "") continue;
    const lineNo = i + 1;

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      const reason = `JSON parse error: ${e instanceof Error ? e.message : String(e)}`;
      rows.push({ source, lineNo, raw, outcome: { ok: false, reason } });
      continue;
    }

    const receipt = asSignedReceipt(parsed);
    if (!receipt) {
      rows.push({ source, lineNo, raw, outcome: { ok: false, reason: "not a signed receipt (missing required fields)" } });
      continue;
    }

    rows.push({ source, lineNo, raw, receipt, outcome: await verifyReceipt(receipt) });
  }
  return rows;
}

function asSignedReceipt(v: unknown): SignedReceipt | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const valid =
    typeof o.step_id === "string" &&
    typeof o.action_id === "string" &&
    "params" in o &&
    typeof o.success === "boolean" &&
    typeof o.ts_ms === "number" &&
    typeof o.public_key === "string" &&
    typeof o.signature === "string";
  return valid ? (o as unknown as SignedReceipt) : null;
}
