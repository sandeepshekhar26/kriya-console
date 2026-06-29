import { execSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// Strings that must NEVER appear in a shipped (non-demo) production bundle — they are sample/demo-only:
// a sample receipt signature prefix, the fabricated peer-fleet device ids, the demo "forge" value, the
// demo aggregator host, and the demo license holder. CLEAN-1/CLEAN-2 make the demo seed a build-time
// (`__KRIYA_DEMO__`) dynamic import so it is dead-code-eliminated; this test fails the build if any of
// them regress back into the shipped bundle.
const FORBIDDEN = [
  "80257feb7333cdfc34f011cc", // a sample-audit.jsonl signature prefix
  "fin-analyst-12", // fabricated peer device
  "ci-runner-02", // fabricated peer device
  "risk-desk-03", // fabricated peer device
  "evil-corp", // demo "forge a field" value
  "aggregator.acme.internal", // demo aggregator host
  "Acme Corp", // demo license holder
];

describe("production bundle is sample/demo-free", () => {
  it(
    "ships no sample/demo markers when built with KRIYA_DEMO unset",
    () => {
      // Build the SHIPPED configuration (KRIYA_DEMO unset → the demo seed tree-shakes out), so this test
      // reflects exactly what the desktop app bundles regardless of any prior demo build in this tree.
      execSync("npm run build", {
        cwd: root,
        env: { ...process.env, KRIYA_DEMO: "" },
        stdio: "pipe",
      });

      const assetsDir = join(root, "dist", "assets");
      const jsFiles = readdirSync(assetsDir).filter((f) => f.endsWith(".js"));
      expect(jsFiles.length).toBeGreaterThan(0);

      const hits: string[] = [];
      for (const file of jsFiles) {
        const text = readFileSync(join(assetsDir, file), "utf8");
        for (const marker of FORBIDDEN) {
          if (text.includes(marker)) hits.push(`${file}: "${marker}"`);
        }
      }

      expect(
        hits,
        `sample/demo markers leaked into the production bundle:\n  ${hits.join("\n  ")}`,
      ).toEqual([]);
    },
    180_000,
  );
});
