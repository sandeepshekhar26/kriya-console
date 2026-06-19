# Capturing marketing screenshots

The Console ships with real Rust-signed sample data, so you can produce clean product screenshots
in a couple of minutes with **no setup beyond `npm run dev`**. These five views are the sellable set
(verified live, 2026-06-19).

## Setup

```bash
npm install
npm run dev            # → http://localhost:5173
```

Use a **1280×800** (desktop) viewport and your OS dark theme. Save captures into this folder as
`overview.png`, `audit.png`, `approvals.png`, `policy.png`, `compliance.png`, then reference them
from `README.md`.

## The five views (what to load, what it shows)

| View | How to get there | What sells |
|---|---|---|
| **Overview** | Click **Overview** → **Load sample data** | The posture dashboard: receipts, **verified vs failed/tampered**, distinct signers, governance posture + policy coverage at a glance. |
| **Audit log** | **Audit log** (uses the loaded receipts) | The signed-receipt table — *"every receipt, verified locally against its embedded key."* Status / source / actor / action / params, with filters. |
| **Approvals** | **Approvals** → **Load sample** | The cross-app/agent approval queue — **high-risk first** (close_account, refund_payment, delete_transaction in red), per-app + per-actor (`claude-desktop / alice`, `cursor / bob`), waiting time, Approve/Deny. The clearest enterprise screenshot. |
| **Policy** | **Policy** | The rule editor: ordered Allow / Require-approval / Deny (color-coded), one-click coverage suggestions for ungoverned actions, budget cap, lint, decision preview. *"Author the rules the runtime enforces."* |
| **Compliance** | **Compliance** → **Load sample** | The control mapping (EU AI Act Art. 12/13/14, SOC 2 CC7.2, ISO 42001 A.9) with satisfied/gap status + **Export Markdown / JSON**. The willingness-to-pay shot. |

> Tip for the strongest **Audit** shot (a red tampered row): load the compliance sample, which
> includes a deliberately tampered receipt — it surfaces in red, proving verification actually
> catches forgery.

## Optional: scripted capture

If you want repeatable captures without an extra committed dependency, run Playwright on demand
(it downloads to a cache, nothing is added to `package.json`):

```bash
npm run dev &                                  # leave the dev server running
npx --yes playwright@latest install chromium
npx --yes playwright@latest screenshot --viewport-size=1280,800 \
  http://localhost:5173 docs/screenshots/overview.png
# …then drive the nav + "Load sample" buttons via a short Playwright script for the other four.
```

For most needs the manual capture above is faster. Keep generated PNGs out of git history if they
get large — link them from the README, or host them where the marketing site can reach them.
