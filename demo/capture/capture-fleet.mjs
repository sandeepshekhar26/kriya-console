// capture-fleet.mjs — marketing stills of the P2–P6 fleet cockpit (Fleet / drill-in / Policy /
// Evidence), which the `?capture=1` demo build cannot reach (ControlPlaneView's demo short-circuit
// renders the old ControlPlaneDemo dashboard instead — BC-3).
//
// Instead of the earlier temporary-index.html Tauri-IPC hack, this injects the stub with Playwright's
// addInitScript, so NO source file is ever modified: `window.__TAURI_INTERNALS__.invoke` answers the
// real cockpit's real commands (license_status, fleet_coverage, fleet_policy_preview,
// fleet_device_evidence, fleet_org_evidence, org_policy_keygen) with a realistic 4-device dataset —
// one green/in-sync, one behind-with-mismatch-badge, one silent+red, one liveness-behind — while the
// actual production components (drift verdicts included) run unmodified. Run:  npm run capture:fleet
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

const PORT = 1456;
const SHOTS = "docs/screenshots";
mkdirSync(SHOTS, { recursive: true });

const server = spawn("npx", ["vite", "--port", String(PORT), "--clearScreen", "false"], {
  stdio: "ignore",
});

async function waitReady() {
  for (let i = 0; i < 90; i++) {
    try { if ((await fetch(`http://localhost:${PORT}/`)).ok) return; } catch { /* not up yet */ }
    await sleep(500);
  }
  throw new Error(`dev server did not start on :${PORT}`);
}

// Runs inside the page BEFORE any app script (addInitScript): the whole mock backend.
function tauriStub() {
  const now = Date.now();
  const hex = (seed, len) => {
    // Deterministic pseudo-hex so pubs/hashes look real but stay stable across runs.
    let h = 2166136261 >>> 0;
    const out = [];
    for (let i = 0; i < len; i++) {
      h = Math.imul(h ^ (seed.charCodeAt(i % seed.length) + i), 16777619) >>> 0;
      out.push((h % 16).toString(16));
    }
    return out.join("");
  };

  const BUNDLE = {
    org_id: "acme-federal",
    version: 3,
    issued_ms: now - 2 * 24 * 3600e3,
    expires_ms: null,
    scope: { business_unit: null, device_pubs: null },
    policy: {
      rules: [
        { action: "delete_*", allow: true, require_approval: true },
        { action: "payments.*", allow: false },
        { action: "*", allow: true },
      ],
    },
    budgets: { max_actions_per_minute: 60 },
    govern: [
      { target: "claude-code", action: "wire" },
      { target: "hermes", action: "wire" },
    ],
    envelope_verbosity: "standard",
  };

  // Same canonicalizer + hash as src/lib/policyBundle.ts, so the green devices' policy_state hash
  // matches what the drift view derives from the preview bundle.
  const canonicalJson = (v) => {
    if (v === null) return "null";
    if (typeof v === "boolean") return v ? "true" : "false";
    if (typeof v === "number") return String(v);
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
  };
  const bundleHashP = crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(canonicalJson(BUNDLE)))
    .then((d) => Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join(""));

  const H2 = hex("bundle-v2", 64);
  const H1 = hex("bundle-v1", 64);

  const DEVICES = [
    {
      device_pub: hex("eng-0142", 64), org_id: "acme-federal", business_unit: "platform-eng",
      last_seq: 184, max_seq_seen: 184, last_seen_ms: now - 40e3, status: "current",
      console_version: "0.2.3", runtime_version: "kriya-host 0.4.2", verify_crate_version: "kriya-verify 0.1.0",
      os_platform: "macos", os_version: "15.5", os_arch: "aarch64",
      outbox_pending: 0, enrolled_ms: now - 21 * 24 * 3600e3, device_label: "ENG-0142",
      agents: [
        { id: "claude-code", version: "2.1.8", adapter: "kriya-hook", adapter_version: "r30", wired: true },
        { id: "hermes", version: "1.3.2", adapter: "kriya-hermes-hook", adapter_version: "0.2", wired: true },
      ],
      info_collected_ms: now - 3600e3,
      policy_applied_version: 3, policy_bundle_hash: "H3",
      applied_policy_version: 3, latest_bundle_version: 3,
      _applied: { version: 3, hash: "H3" }, _transitionAt: 176,
    },
    {
      device_pub: hex("fin-0027", 64), org_id: "acme-federal", business_unit: "finance",
      last_seq: 97, max_seq_seen: 97, last_seen_ms: now - 2 * 60e3, status: "current",
      console_version: "0.2.2", runtime_version: "kriya-host 0.4.1", verify_crate_version: "kriya-verify 0.1.0",
      os_platform: "macos", os_version: "14.7", os_arch: "x86_64",
      outbox_pending: 2, enrolled_ms: now - 18 * 24 * 3600e3, device_label: "FIN-0027",
      agents: [
        { id: "claude-code", version: "2.1.8", adapter: "kriya-hook", adapter_version: "r30", wired: true },
        { id: "hermes", version: "1.3.0", adapter: "kriya-hermes-hook", adapter_version: "0.2", wired: false },
      ],
      info_collected_ms: now - 7200e3,
      policy_applied_version: 2, policy_bundle_hash: "H2",
      // kriyad's served HINT claims v3 — the device's own signed envelopes say v2. The cockpit's
      // locally-re-verified truth wins and the loud mismatch badge appears in the Policy column.
      applied_policy_version: 3, latest_bundle_version: 3,
      _applied: { version: 2, hash: H2 },
    },
    {
      device_pub: hex("rsk-0009", 64), org_id: "acme-federal", business_unit: "risk-controls",
      last_seq: 41, max_seq_seen: 41, last_seen_ms: now - 5 * 3600e3, status: "silent",
      console_version: "0.2.1", runtime_version: "kriya-host 0.4.0", verify_crate_version: "kriya-verify 0.1.0",
      os_platform: "macos", os_version: "15.3", os_arch: "aarch64",
      outbox_pending: 7, enrolled_ms: now - 30 * 24 * 3600e3, device_label: "RSK-0009",
      agents: [{ id: "claude-code", version: "2.0.9", adapter: "kriya-hook", adapter_version: "r28", wired: true }],
      info_collected_ms: now - 5 * 3600e3,
      policy_applied_version: 1, policy_bundle_hash: "H1",
      applied_policy_version: 1, latest_bundle_version: 3,
      _applied: { version: 1, hash: H1 },
    },
    {
      device_pub: hex("ops-0230", 64), org_id: "acme-federal", business_unit: "platform-eng",
      last_seq: 226, max_seq_seen: 231, last_seen_ms: now - 9 * 60e3, status: "behind",
      console_version: "0.2.3", runtime_version: "kriya-host 0.4.2", verify_crate_version: "kriya-verify 0.1.0",
      os_platform: "macos", os_version: "15.5", os_arch: "aarch64",
      outbox_pending: 5, enrolled_ms: now - 12 * 24 * 3600e3, device_label: "OPS-0230",
      agents: [
        { id: "claude-code", version: "2.1.8", adapter: "kriya-hook", adapter_version: "r30", wired: true },
        { id: "hermes", version: "1.3.2", adapter: "kriya-hermes-hook", adapter_version: "0.2", wired: true },
      ],
      info_collected_ms: now - 1800e3,
      policy_applied_version: 3, policy_bundle_hash: "H3",
      applied_policy_version: 3, latest_bundle_version: 3,
      _applied: { version: 3, hash: "H3" },
    },
  ];

  async function envelopesFor(dev, fromSeq, toSeq) {
    const h3 = await bundleHashP;
    const applied = { ...dev._applied, hash: dev._applied.hash === "H3" ? h3 : dev._applied.hash };
    const out = [];
    for (let seq = fromSeq; seq <= toSeq; seq++) {
      // For the green device, show a genuine v2 → v3 transition inside the drill-in window.
      const preTransition = dev._transitionAt !== undefined && seq < dev._transitionAt;
      const ps = preTransition
        ? { version: 2, bundle_hash: H2, applied_ms: now - 3 * 24 * 3600e3 }
        : { version: applied.version, bundle_hash: applied.hash, applied_ms: now - 26 * 3600e3 };
      const actions = [
        { action: "fs.write", count: 6 + ((seq * 7) % 9), failures: 0, destructive: false },
        { action: "bash.exec", count: 3 + ((seq * 5) % 6), failures: seq % 11 === 0 ? 1 : 0, destructive: false },
      ];
      if (dev._transitionAt !== undefined && seq === dev._transitionAt) {
        actions.push({ action: "kriya.policy.applied", count: 1, failures: 0, destructive: false });
      }
      const envelope = {
        v: "1.1", seq,
        device_pub: dev.device_pub,
        window_from: now - (toSeq - seq + 1) * 3600e3,
        window_to: now - (toSeq - seq) * 3600e3,
        merkle_root: hex(dev.device_pub + "merkle" + seq, 64),
        prev_envelope_hash: hex(dev.device_pub + "env" + (seq - 1), 64),
        policy_state: ps,
        actions,
      };
      out.push({ raw: JSON.stringify({ envelope, signature: hex(dev.device_pub + "sig" + seq, 128) }), verified: true, error: null });
    }
    return out;
  }

  const controls = [
    { framework: "NIST 800-171", control: "3.3.1", requirement: "Create and retain system audit logs and records", evidence: "4/4 devices emit signed, hash-chained evidence envelopes; chain intact on every device in the window; 1 silent device named as a red cell (RSK-0009).", status: "satisfied" },
    { framework: "NIST 800-171", control: "3.3.2", requirement: "Trace actions to individual users", evidence: "Operators appear only as HMAC pseudonyms at the aggregator (the employee-privacy design working as intended); individual attribution resolves on-device. Permanently partial at the org level.", status: "partial" },
    { framework: "NIST 800-171", control: "3.3.4", requirement: "Alert on audit logging process failure", evidence: "Heartbeat-sequence gap detection: a silenced device surfaces as behind/silent within one interval — RSK-0009 is currently flagged.", status: "satisfied" },
    { framework: "NIST 800-171", control: "3.3.8", requirement: "Protect audit information from unauthorized modification/deletion", evidence: "Every envelope Ed25519-signed by its device key and re-verified locally in this cockpit; 0 envelope-level re-verification failures in the window; receipt-level failure counts tracked separately.", status: "satisfied" },
    { framework: "NIST 800-171", control: "3.3.9", requirement: "Limit audit management to a privileged subset", evidence: "Permanent gap: kriya cannot restrict OS-level administrative access to on-device logs. Stated, not hidden.", status: "gap" },
    { framework: "NIST 800-171", control: "3.4.1 (CM)", requirement: "Establish and maintain baseline configurations", evidence: "Signed policy chain: bundle v3 authored (org-key signature) → verified-applied on 2/4 devices, from each device's OWN locally re-verified envelopes — never kriyad's serving hint.", status: "satisfied" },
    { framework: "NIST 800-171", control: "3.4.2 (CM)", requirement: "Enforce security configuration settings", evidence: "2/4 devices at bundle v3; drift exceptions named: FIN-0027 (v2, mismatch vs served hint), RSK-0009 (v1, silent). Anti-rollback enforced on-device.", status: "partial" },
    { framework: "NIST 800-53", control: "AC-4", requirement: "Enforce approved authorizations for controlling the flow of information", evidence: "42 kriya.io.* receipts verified fleet-wide (38 allow, 3 deny, 1 approve). Governed lanes only — a spawned subprocess bypasses this on every device.", status: "partial" },
  ];

  const orgEvidence = (organization, windowMs) => ({
    generatedMs: now, organization,
    windowFromMs: now - (windowMs || 90 * 24 * 3600e3), windowToMs: now,
    devicesTotal: 4, devicesCurrent: 2, devicesBehind: 1, devicesSilent: 1,
    deviceCompleteness: DEVICES.map((d) => ({
      devicePub: d.device_pub, deviceLabel: d.device_label, liveness: d.status,
      envelopesInWindow: Math.min(d.last_seq, 90), seqGaps: [], chainIntact: true, chainBreakAt: null,
      appliedPolicyVersion: d._applied.version, appliedBundleHash: null,
      consoleVersion: d.console_version, runtimeVersion: d.runtime_version,
    })),
    latestBundleVersion: 3,
    drift: [
      "FIN-0027 — applied v2 < published v3 (device's own signed envelopes; kriyad's hint disagrees)",
      "RSK-0009 — silent AND applied v1 < published v3",
    ],
    egressReceipts: DEVICES.map((d, i) => ({
      devicePub: d.device_pub, deviceLabel: d.device_label,
      verifiedReceipts: i === 0 ? 42 : 0, allow: i === 0 ? 38 : 0, deny: i === 0 ? 3 : 0, approve: i === 0 ? 1 : 0,
    })),
    egressTotals: { verifiedReceipts: 42, allow: 38, deny: 3, approve: 1 },
    controls,
    markdown: [
      `# Fleet evidence — ${organization}`, "",
      `Generated ${new Date(now).toISOString()} · window: last 90 days · 4 devices`, "",
      "## Coverage completeness", "",
      "| Device | Liveness | Envelopes | Chain | Applied policy |", "|---|---|---|---|---|",
      ...DEVICES.map((d) => `| ${d.device_label} | ${d.status} | ${Math.min(d.last_seq, 90)} | intact | v${d._applied.version} |`),
      "", "## Controls", "",
      ...controls.map((c) => `- **${c.control}** (${c.status}) — ${c.evidence}`),
      "", "---", "*This report is evidence, not a certification.*", "",
    ].join("\n"),
    json: "",
  });

  const handlers = {
    license_status: () => ({
      tier: "pro", valid: true, holder: "Acme Federal (design partner)",
      features: ["control-plane", "fleet-console"], expiresMs: null, licenseId: "KRIYA-ACME-0001", reason: null,
    }),
    fleet_coverage: async () => {
      const h3 = await bundleHashP;
      return DEVICES.map(({ _applied, _transitionAt, ...row }) => ({
        ...row,
        policy_bundle_hash: row.policy_bundle_hash === "H3" ? h3 : row.policy_bundle_hash,
      }));
    },
    fleet_policy_preview: () => ({ bundle: BUNDLE, signature: hex("org-sig-v3", 128) }),
    org_policy_keygen: () => ({ orgPolicyPub: hex("org-policy-pub", 64), pubPath: "/Users/operator/.kriya/console/org-policy.pub", generated: false }),
    fleet_publish_policy: () => ({ version: 4, duplicate: false }),
    fleet_device_evidence: async (args) => {
      const dev = DEVICES.find((d) => d.device_pub === args.devicePub);
      if (!dev) throw new Error("unknown device");
      const envelopes = await envelopesFor(dev, args.fromSeq, Math.min(args.toSeq, dev.last_seq));
      return { envelopes, heartbeat: { raw: JSON.stringify({ heartbeat: { seq_seen: dev.max_seq_seen, ts_ms: dev.last_seen_ms } }), verified: true, error: null } };
    },
    fleet_org_evidence: (args) => {
      const e = orgEvidence(args.organization || "Fleet", args.windowMs);
      e.json = JSON.stringify({ ...e, markdown: undefined, json: undefined }, null, 2);
      return e;
    },
    read_audit: () => [],
    audit_location: () => ({ dir: "/Users/operator/.kriya/audit", files: [] }),
    onboarding_status: () => ({}),
    coverage_status: () => ({ lanes: [] }),
  };

  window.__TAURI_INTERNALS__ = {
    metadata: { currentWindow: { label: "main" }, currentWebview: { label: "main" } },
    plugins: {},
    transformCallback: (cb) => {
      const id = Math.floor(Math.random() * 1e9);
      window[`_${id}`] = cb;
      return id;
    },
    invoke: async (cmd, args) => {
      if (cmd.startsWith("plugin:event|")) return 1; // listen/unlisten no-ops
      const h = handlers[cmd];
      if (h) return h(args || {});
      return {}; // benign default for anything else the shell touches
    },
  };
}

let browser;
try {
  await waitReady();
  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 940 }, deviceScaleFactor: 2 });
  await page.addInitScript(tauriStub);
  await page.goto(`http://localhost:${PORT}/`, { waitUntil: "networkidle" });
  await sleep(800);

  // 1 — Fleet tab: drift summary + Policy column (incl. FIN-0027's loud mismatch badge).
  await page.locator(".nav-item", { hasText: "On-prem aggregator" }).first().click();
  await page.waitForSelector("table.cp-cover", { timeout: 20000 });
  await page.getByText("bundle v3 —").waitFor({ timeout: 20000 }); // drift re-verification settled
  await sleep(500);
  await page.screenshot({ path: `${SHOTS}/fleet-drift.png` });
  console.log("shot: fleet-drift");

  // 2 — Drill-in on the green device: verified envelope chain + policy history (v2 → v3 transition).
  await page.locator("table.cp-cover tbody tr", { hasText: "ENG-0142" }).click();
  await page.waitForSelector(".drawer", { timeout: 20000 });
  await page.getByText("Version history (this window)").waitFor({ timeout: 20000 });
  await page.locator(".drawer .cp-line.ok").first().waitFor({ timeout: 20000 });
  // Bring the policy-history section into the drawer's frame.
  await page.getByText("Version history (this window)").scrollIntoViewIfNeeded();
  await sleep(400);
  await page.screenshot({ path: `${SHOTS}/fleet-drillin-policy.png` });
  console.log("shot: fleet-drillin-policy");
  await page.keyboard.press("Escape");
  await sleep(300);

  // 3 — Policy tab: org key + author form (seeded from the published v3 bundle).
  await page.locator(".segmented button", { hasText: "Policy" }).click();
  await page.getByText("seeded from the latest published bundle (v3)").waitFor({ timeout: 20000 });
  await page.locator("button", { hasText: "Generate / show org signing key" }).click();
  await page.getByText("Org key already exists").waitFor({ timeout: 20000 });
  await sleep(300);
  await page.screenshot({ path: `${SHOTS}/fleet-policy-author.png` });
  console.log("shot: fleet-policy-author");

  // 4 — Evidence tab: org-wide export with the AU + CM control table.
  await page.locator(".segmented button", { hasText: "Evidence" }).click();
  await page.locator('input[placeholder="Your organization"]').fill("Acme Federal");
  await page.locator("button", { hasText: "Generate & save" }).click();
  await page.getByText("3.4.2 (CM)").waitFor({ timeout: 20000 });
  await sleep(400);
  await page.screenshot({ path: `${SHOTS}/fleet-org-evidence.png` });
  console.log("shot: fleet-org-evidence");
} finally {
  if (browser) await browser.close();
  server.kill("SIGTERM");
}
console.log("done →", SHOTS);
