# Capturing marketing screenshots

Populate the Console with a **real signed trail** on this machine, then capture. In the desktop app
the Monitor tails `~/.kriya/audit/` live; in the browser build (`npm run dev`) import a real
`kriya-audit.jsonl` via **Audit log → Open a file…**. These views are the sellable set.

## Setup

```bash
npm install
npm run dev            # → http://localhost:5173
```

Then **Audit log → Open a file…** and pick a real `kriya-audit.jsonl` (ideally one that includes a
*tampered* row, an on-device attestation, and two operators for the strongest scenes). Use a
**1280×800** viewport and the **light theme** (the first-class default). Save captures into this
folder as `monitor.png`, `audit.png`, `approvals.png`, `policy.png`, `connections.png`,
`evidence.png`, then reference them from `README.md`.

## The key views (how to get there, what it shows)

| View | How to get there | What sells |
|---|---|---|
| **Monitor** (home) | Opens here (tails `~/.kriya/audit`; in the browser build, import a trail first via Audit) | The live home: the signed-receipt tail, posture (receipts, **verified vs unverified**, signers, coverage), and the per-app **attestation continuity** ribbon. |
| **Audit log** | **Audit log → Open a file…** (a `kriya-audit.jsonl` trail) | The signed-receipt table — *"every receipt, verified locally against its embedded key."* Status / source / actor / action / params, with filters. |
| **Approvals** | **Approvals → Load queue(s)** (a real `pending-approvals.jsonl`) | The cross-app/agent approval queue — **high-risk first** (close_account, refund_payment, delete_transaction tamper-flagged), per-app + per-actor (`claude-desktop / alice`, `cursor / bob`), waiting time, Approve/Deny. The clearest enterprise screenshot. |
| **Policy** | **Policy** | The rule editor: ordered Allow / Require-approval / Deny (color-coded), one-click coverage suggestions for ungoverned actions, budget cap, lint, decision preview. *"Author the rules the runtime enforces."* |
| **Connections** | **Connections** | The governed-MCP manager: the connection-type catalog (kriya-native / proxy / desktop) + the slide-in add-connection flow. The "how it gets wired" shot. |
| **Evidence** | **Evidence** (uses the loaded trail; Pro) | The report builder — pick SOC 2 / ISO 42001 / EU AI Act, generate on-device; control mapping (EU AI Act Art. 12/13/14, SOC 2 CC7.2, ISO 42001 A.9) with satisfied/gap + **Markdown / JSON**. The willingness-to-pay shot. |

> Tip for the strongest **Audit** shot (a tamper-flagged row): use a trail that includes a
> deliberately tampered receipt — it surfaces flagged, proving verification actually catches forgery.

## Optional: scripted capture

If you want repeatable captures without an extra committed dependency, run Playwright on demand
(it downloads to a cache, nothing is added to `package.json`):

```bash
npm run dev &                                  # leave the dev server running
npx --yes playwright@latest install chromium
npx --yes playwright@latest screenshot --viewport-size=1280,800 \
  http://localhost:5173 docs/screenshots/monitor.png
# …then drive Audit → Open a file… to import a real trail, and nav the other views, via a short Playwright script.
```

For most needs the manual capture above is faster. Keep generated PNGs out of git history if they
get large — link them from the README, or host them where the marketing site can reach them.
