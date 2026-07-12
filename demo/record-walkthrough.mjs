// Records a captioned pitch walkthrough of the kriya Console (on-device) + the on-prem aggregator
// (Control plane) by driving the REAL running web app with Playwright. Output: demo/video/*.webm
// (converted to demo/kriya-gui-demo.mp4 by the caller). Run: node demo/record-walkthrough.mjs
import { chromium } from "playwright";

const URL = process.env.DEMO_URL || "http://localhost:1420";
const W = 1440, H = 900;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function caption(page, text) {
  await page.evaluate((t) => {
    let bar = document.getElementById("__cap");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "__cap";
      bar.style.cssText =
        "position:fixed;left:0;right:0;bottom:0;z-index:2147483647;display:flex;justify-content:center;pointer-events:none;font-family:-apple-system,BlinkMacSystemFont,Inter,sans-serif;";
      const inner = document.createElement("div");
      inner.id = "__capi";
      inner.style.cssText =
        "margin:0 0 30px;max-width:78%;background:rgba(17,20,28,0.93);color:#fff;padding:13px 24px;border-radius:11px;font-size:19px;font-weight:500;letter-spacing:-0.2px;box-shadow:0 10px 34px rgba(0,0,0,0.34);text-align:center;line-height:1.42;transition:opacity .35s ease;";
      bar.appendChild(inner);
      document.body.appendChild(bar);
    }
    const inner = document.getElementById("__capi");
    inner.style.opacity = "0";
    setTimeout(() => {
      inner.textContent = t;
      inner.style.opacity = "1";
    }, 180);
  }, text);
}

async function titleCard(page, show) {
  await page.evaluate((s) => {
    let el = document.getElementById("__title");
    if (!el) {
      el = document.createElement("div");
      el.id = "__title";
      el.style.cssText =
        "position:fixed;inset:0;z-index:2147483646;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;background:#0b0d12;color:#edf0f5;font-family:-apple-system,BlinkMacSystemFont,Inter,sans-serif;transition:opacity .5s ease;";
      el.innerHTML =
        '<div style="display:flex;align-items:center;gap:13px"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#7e89e8" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 19 6v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6z"/><path d="m9 11.5 2 2 4-4.5"/></svg><span style="font-size:40px;font-weight:600;letter-spacing:-1px">kriya</span></div>' +
        '<div style="font-size:21px;color:#a4aebe;font-weight:500">The agent-governance control plane</div>' +
        '<div style="font-size:15px;color:#6c7787;margin-top:6px">on-device console · on-prem aggregator · verified, nothing leaves your boundary</div>';
      document.body.appendChild(el);
    }
    el.style.opacity = s ? "1" : "0";
    if (!s) setTimeout(() => el.remove(), 520);
  }, show);
}

async function nav(page, label) {
  await page.locator(".nav-item", { hasText: label }).first().click();
  await sleep(700);
}

async function main() {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: W, height: H },
    deviceScaleFactor: 2,
    recordVideo: { dir: "demo/video", size: { width: W, height: H } },
  });
  const page = await context.newPage();
  await page.goto(URL, { waitUntil: "networkidle" });
  await page.waitForSelector(".stat-value", { timeout: 15000 });
  await sleep(600);

  // ── Title card ──────────────────────────────────────────────────────────────
  await titleCard(page, true);
  await sleep(3200);
  await titleCard(page, false);
  await sleep(700);

  // ── On-device Console ─────────────────────────────────────────────────────────
  await nav(page, "Monitor");
  await caption(page, "The on-device Console — every agent action, a signed receipt, re-verified live.");
  await sleep(4200);

  await nav(page, "Audit log");
  await caption(page, "One tamper-evident audit trail. Ed25519-signed, hash-chained.");
  await sleep(4200);

  await nav(page, "Approvals");
  await caption(page, "Risky actions route to a human — with full RBAC.");
  await sleep(4000);

  await nav(page, "Policy");
  await caption(page, "Author the policy the runtime enforces — deny by default.");
  await sleep(4000);

  // Egress (EG-2/EG-3): turn the egress tier ON live and author a rule — the YAML pane updates in real
  // time, so the beat shows control being created, not a static card. Skipped on a pre-egress build.
  try {
    const sec = page.locator("section", { has: page.locator("h2", { hasText: "Egress destinations" }) });
    await sec.scrollIntoViewIfNeeded({ timeout: 3000 });
    await caption(page, "NEW — egress governance. Turn it on: destinations become policy.");
    await sleep(1800);
    const cb = sec.locator("input[type=checkbox]").first();
    if (!(await cb.isChecked())) await cb.click();
    await sleep(1000);
    await sec.locator("button", { hasText: "+ Add destination" }).click();
    const row = sec.locator(".rules .rule").last();
    await row.locator("input").fill("*.github.com");
    await sleep(600);
    await sec.locator(".budget select").first().selectOption("deny");
    await caption(page, "Allow what you name, approve the sensitive, deny the rest — signed per decision.");
    await sleep(3800);
  } catch { /* pre-egress build — skip the beat */ }

  await nav(page, "Evidence");
  await caption(page, "Compliance evidence — SOC 2 / ISO 42001 / EU AI Act — generated on-device.");
  await sleep(4400);

  // ── On-prem control plane ─────────────────────────────────────────────────────
  await nav(page, "On-prem aggregator");
  await caption(page, "Now the on-prem control plane: the whole fleet, on a box YOU run. No egress.");
  await sleep(4600);

  await page.locator(".cp-cover").scrollIntoViewIfNeeded();
  await caption(page, "Coverage across every device — current, behind, or gone silent.");
  await sleep(4200);

  // Re-prove offline
  await page.locator(".cp-verify").scrollIntoViewIfNeeded();
  await sleep(500);
  await caption(page, "Re-prove a device's signed evidence offline — trusting neither device nor server.");
  await page.getByRole("button", { name: "Re-prove offline" }).click();
  await sleep(2600);
  await caption(page, "Re-derived bytes, signatures, the hash-chain, the tail anchor — all green.");
  await sleep(2600);

  // Attacks
  await caption(page, "Now let an attacker try. Forge a field after signing…");
  await page.getByRole("button", { name: "Forge a field" }).click();
  await sleep(2400);
  await caption(page, "…caught. The signature no longer matches the bytes.");
  await sleep(2000);

  await caption(page, "Flip a single byte of what the server returned…");
  await page.getByRole("button", { name: "Flip a byte" }).click();
  await sleep(2400);
  await caption(page, "…caught.");
  await sleep(1500);

  await caption(page, "Or have the server hide the newest receipt…");
  await page.getByRole("button", { name: "Hide newest" }).click();
  await sleep(2600);
  await caption(page, "…caught — the device's signed heartbeat proves what was withheld.");
  await sleep(2800);

  // Closing
  await caption(page, "Signed at the source. Re-verified on your box. Provably nothing hidden.");
  await sleep(3800);
  await caption(page, "kriya — the agent-governance control plane.");
  await sleep(2600);

  await context.close(); // finalizes the video
  await browser.close();
  console.log("recorded");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
