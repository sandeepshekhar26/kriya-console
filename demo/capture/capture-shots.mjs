// capture-shots.mjs — clean marketing stills of each Console view from the ?capture=1 dataset.
// Spawns its OWN `KRIYA_DEMO=1` dev server (so the PII-free signed capture seed loads + paid views
// unlock), screenshots each view at 1440x900 @2x in the default light theme, writes PNGs to
// docs/screenshots/, then tears the server down. Run:  npm run capture
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

const PORT = 1455;
const SHOTS = "docs/screenshots";
mkdirSync(SHOTS, { recursive: true });

const server = spawn("npx", ["vite", "--port", String(PORT), "--clearScreen", "false"], {
  env: { ...process.env, KRIYA_DEMO: "1" },
  stdio: "ignore",
});

async function waitReady() {
  for (let i = 0; i < 90; i++) {
    try { if ((await fetch(`http://localhost:${PORT}/`)).ok) return; } catch { /* not up yet */ }
    await sleep(500);
  }
  throw new Error(`dev server did not start on :${PORT}`);
}

const VIEWS = [
  ["monitor", "Monitor"],
  ["coverage", "Coverage"],
  ["audit", "Audit log"],
  ["approvals", "Approvals"],
  ["policy", "Policy"],
  ["budgets", "Budgets & rate"],
  ["identity", "Identity & access"],
  ["evidence", "Evidence"],
  ["fleet", "Fleet"],
  ["connections", "Connections"],
];

let browser;
try {
  await waitReady();
  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  await page.goto(`http://localhost:${PORT}/?capture=1`, { waitUntil: "networkidle" });
  await page.waitForSelector(".stat-value", { timeout: 20000 });
  await sleep(1200); // let the async verify + render settle

  for (const [file, label] of VIEWS) {
    await page.locator(".nav-item", { hasText: label }).first().click();
    await sleep(700);
    await page.screenshot({ path: `${SHOTS}/${file}.png` });
    console.log("shot:", file);
  }

  // Egress (EG-2/EG-3): the Policy egress-destinations card and the evidence rows computed from the
  // seeded kriya.io.* receipts — scrolled into frame; skipped (not failed) if the anchor is absent.
  try {
    await page.locator(".nav-item", { hasText: "Policy" }).first().click();
    await sleep(600);
    // Turn the egress tier ON and author real destination rules so the shot shows the editor working
    // (round-trips through the same YAML the runtime's EgressPolicy enforces) — not the Off state.
    const govEgress = page.locator("label", { hasText: "Govern egress" }).locator("input[type=checkbox]");
    if (!(await govEgress.isChecked())) await govEgress.click();
    await sleep(300);
    const egressSection = page.locator("section", { has: page.locator("h2", { hasText: "Egress destinations" }) });
    for (const [host, tier] of [["*.github.com", "allow"], ["api.anthropic.com", "allow"], ["exports.partner-crm.com", "approval"]]) {
      await egressSection.locator("button", { hasText: "+ Add destination" }).click();
      const row = egressSection.locator(".rules .rule").last();
      await row.locator("input").fill(host);
      await row.locator("select").selectOption(tier);
    }
    await egressSection.locator(".budget select").first().selectOption("deny"); // unlisted → deny-by-default
    await page.locator("h2", { hasText: "Egress destinations" }).scrollIntoViewIfNeeded();
    await sleep(400);
    await page.screenshot({ path: `${SHOTS}/policy-egress.png` });
    console.log("shot: policy-egress");
  } catch (e) { console.log("skip: policy-egress —", e.message.split("\n")[0]); }
  try {
    await page.locator(".nav-item", { hasText: "Evidence" }).first().click();
    await sleep(700);
    await page.getByText("governed connector lanes", { exact: false }).first().scrollIntoViewIfNeeded();
    await sleep(400);
    await page.screenshot({ path: `${SHOTS}/evidence-egress.png` });
    console.log("shot: evidence-egress");
  } catch (e) { console.log("skip: evidence-egress —", e.message.split("\n")[0]); }

  // Control plane: re-prove offline → capture the all-green verdict (not the empty/initial state).
  await page.locator(".nav-item", { hasText: "On-prem aggregator" }).first().click();
  await sleep(500);
  await page.locator("button", { hasText: "Re-prove offline" }).first().click();
  await page.waitForSelector(".cp-verdict.ok", { timeout: 20000 });
  await page.locator(".cp-verdict.ok").scrollIntoViewIfNeeded(); // bring the green verdict into frame
  await sleep(400);
  await page.screenshot({ path: `${SHOTS}/controlplane.png` });
  console.log("shot: controlplane");
} finally {
  if (browser) await browser.close();
  server.kill("SIGTERM");
}
console.log("done →", SHOTS);
