// Render the Kriya Console app icon (a brand shield-check, matching the in-app mark) to a 1024px PNG.
// Then `npx tauri icon scripts/icon/icon-source.png` regenerates src-tauri/icons/* for every platform.
// Uses the already-installed Playwright chromium (no new dependency).
import { chromium } from "playwright";

// A macOS-style rounded tile on the brand gradient (saffron → violet), with a white filled shield and a
// bold saffron check — the same shield-check the Console uses as its brand mark.
const SVG = `
<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#ff8a4d"/>
      <stop offset="0.5" stop-color="#ff5a1f"/>
      <stop offset="1" stop-color="#c084fc"/>
    </linearGradient>
    <filter id="s" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="10" stdDeviation="18" flood-color="#000000" flood-opacity="0.18"/>
    </filter>
  </defs>
  <rect x="80" y="80" width="864" height="864" rx="196" fill="url(#g)"/>
  <svg x="252" y="214" width="520" height="520" viewBox="0 0 24 24" filter="url(#s)">
    <path d="M12 2.6 19.5 5.6v5.2c0 4.7-3.2 8.1-7.5 9.6-4.3-1.5-7.5-4.9-7.5-9.6V5.6z" fill="#ffffff"/>
    <path d="m8.4 11.9 2.5 2.5 4.8-5.4" fill="none" stroke="#ff5a1f" stroke-width="2.1"
          stroke-linecap="round" stroke-linejoin="round"/>
  </svg>
</svg>`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1024, height: 1024 }, deviceScaleFactor: 1 });
await page.setContent(
  `<!doctype html><html><head><style>*{margin:0;padding:0}html,body{width:1024px;height:1024px;background:transparent}</style></head><body>${SVG}</body></html>`,
  { waitUntil: "networkidle" },
);
await page.screenshot({
  path: "scripts/icon/icon-source.png",
  omitBackground: true,
  clip: { x: 0, y: 0, width: 1024, height: 1024 },
});
await browser.close();
console.log("wrote scripts/icon/icon-source.png (1024x1024, transparent)");
