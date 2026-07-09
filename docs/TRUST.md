# Trust & tamper-evidence — what kriya Console lets you prove

> For security, compliance, and procurement reviewers. This explains, in plain terms, **what an
> auditor can independently verify** about agent activity through kriya Console, how the
> tamper-evidence works, and — honestly — the boundaries of that guarantee. The underlying
> cryptography lives in the **open** kriya runtime (MIT) and is documented at
> [`docs/SECURITY.md`](https://github.com/sandeepshekhar26/kriya/blob/main/docs/SECURITY.md); this
> document is the buyer-facing companion and does not contradict it.

## The one-sentence claim

Every action an AI agent actually performed in a kriya-governed app is recorded as a
**cryptographically signed receipt**, and kriya Console lets you (and your auditor) **re-verify
every one of those signatures locally — on your own machine, with no network and no trust in the
vendor** — so altered or forged records are detected, not assumed.

## What you can prove

| Question a regulator / auditor asks | How the Console answers it |
|---|---|
| *"Show me everything the agent did."* | The audit view aggregates the signed receipts from every kriya app into one table — action, parameters, who, when, success — and verifies each signature on-device, inside the Console app. |
| *"How do I know this log wasn't edited?"* | Each receipt is Ed25519-signed by the host. The Console re-derives the signed bytes and checks the signature; **any edit to a retained receipt fails verification and is flagged in red.** |
| *"Who authorized the risky ones?"* | Guarded actions (e.g. `delete_transaction`, `close_account`) were held for a human; the approval — with the operator's identity and a recorded reason — is part of the trail (R8 `actor`). |
| *"What is the agent even allowed to do?"* | The policy view shows the exact allow / require-approval / deny rules the runtime enforces, and produces the `agent-policy.yaml` the host loads — so the control is provable, not aspirational. |
| *"Give me evidence for our EU AI Act / SOC 2 / ISO 42001 control."* | The compliance view maps the verified trail to specific controls (EU AI Act Art. 12 record-keeping, Art. 14 human oversight, SOC 2 CC7.2, ISO 42001 A.9) and exports a Markdown report + JSON bundle, with **gaps shown honestly**, not hidden. |

## How the tamper-evidence works (in brief)

1. **The host signs, the agent can't.** The kriya runtime holds an Ed25519 signing key in the host
   process; the agent never sees it. After an action clears the policy/approval/budget gates, the
   host signs a receipt over the action id, parameters, who did it, when, and the success flag.
2. **Receipts are append-only and self-describing.** Each is one line in a JSONL log carrying the
   signature and the signer's public key.
3. **Verification is independent and offline.** The Console re-computes the exact bytes that were
   signed and checks the signature on-device, inside the Console app's compiled backend. The
   verification is proven **byte-identical** to the host's signing in the test suite — if it
   drifted by a single byte, real receipts wouldn't verify. **Nothing is sent anywhere; you are
   not trusting kriya's word, you are checking the math.**

Because the signature covers *who/what/when*, you cannot quietly change the amount on a transaction,
flip a failure to a success, or reassign an action to a different operator without invalidating that
receipt's signature.

## Honest boundaries (read this)

A trustworthy vendor states the limits of its guarantee. Tamper-*evidence* is not the same as
tamper-*proofing*:

- **Pin your signer.** Verification proves a receipt wasn't altered *under the key that signed it*.
  A meaningful audit also confirms that key is **your** host's key. The Console surfaces every
  distinct signer across your logs precisely so an unexpected key stands out — make pinning the
  expected key part of your review.
- **Whole-record deletion is detected — receipts are hash-chained.** Each receipt carries a
  `prev_hash` (the SHA-256 of the previous log line) *inside the signed bytes*, so the log is a
  tamper-evident chain, not just a set of independent signatures. Removing, truncating, or
  reordering entire records breaks the chain: re-verification flags a `CHAIN-BREAK` at the gap.
  Signatures prove *no retained record was altered*; the chain extends that to a *completeness*
  guarantee against whole-receipt deletion. (Anchoring the chain head to an external timestamp is
  a further hardening option.)
- **A fully compromised host is out of scope.** The guarantee is against the *agent* and against
  *after-the-fact editing by anything without the key* — not against arbitrary code running inside
  the trusted host process.
- **Signing key lifecycle.** A persisted, stable signing identity has shipped (R20): the pinned
  public key stays the same run-to-run, so the audit trail is verifiable over months, not just within
  one session. A deployment only shows multiple signer keys if it runs with the ephemeral
  per-process key instead of a persisted one — the Console shows you exactly how many. Hardware-backed
  (Secure Enclave) anchoring of that identity is the remaining hardening.
- **Policy enforcement now actually reaches every install path (B0, fixed).** Until this fix, the
  Policy view authored a policy that was never written to any file the runtime could load, and
  every "Install hook" / "Govern everything" / manual-connection action installed `kriya-hook`,
  `kriya-hermes-hook`, and `kriya-gateway` with **no `--policy` flag at all** — every enforcement
  point silently ran the permissive built-in default, regardless of what the Policy view showed.
  A deny rule the operator saved was never actually enforced. Fixed: the authored policy now
  persists to `~/.kriya/agent-policy.yaml` on every edit, and every install path wires `--policy`
  at that file. Stated here retroactively, in the same spirit as the rest of this document — an
  honest account includes bugs that shipped, not just the ones caught before release.
- **The approval tier is a `tty`/GUI-dialog prompt, not a live Console popup.** `RequiresApproval`
  actions are decided by the hook/gateway process itself (a terminal prompt or a macOS dialog),
  self-bounded at 300s. We deliberately do **not** use Claude Code's native
  `permissionDecision:"ask"` — it has documented, reproducible reliability gaps (unreliable in
  headless `claude -p` mode, and has been observed silently overridden by a broad
  `permissions.allow` rule elsewhere in a user's settings, letting the tool run with no prompt at
  all). The **Approvals** view in this Console is a separate, manual/historical decision queue —
  load a JSONL file of pending requests, decide with a reason, and the decision is recorded in the
  local trail — it is not wired to unblock a paused hook process live. A true remote,
  Console-mediated approval flow is a possible future addition, not something this build claims.
- **A hook that times out, crashes, or emits malformed output on Claude Code's own side fails
  open — kriya cannot change that from this side of the seam.** Claude Code's hook timeout
  (600s default) is documented to let the tool proceed if a hook doesn't answer in time; the same
  is true of a hook that crashes or produces output Claude Code can't parse. `kriya-hook`
  mitigates this everywhere it can control the outcome — the approval gates self-bound well under
  that ceiling, and the hook's own internal errors (bad payload, unreadable policy) always fail
  closed — but a cooperative seam is still cooperative: whoever controls `settings.json`, or
  whatever kills the hook process externally, has the last word. See `kriya`'s
  [`docs/SECURITY.md`](https://github.com/sandeepshekhar26/kriya/blob/main/docs/SECURITY.md) for
  the full detail.

These boundaries are shared with the open runtime's threat model and are not unique to the paid
tier; we publish them rather than paper over them.

## Coverage — what is (and isn't) being recorded, as a signed metric

Signatures prove a *retained* receipt is authentic; they cannot prove an event **no source
observed** ever produced a receipt. The Console makes that boundary a first-class, verifiable
surface instead of a footnote — the **Coverage Map**:

- **Six lanes, three states.** Claude Code tools · remote/attached MCP · local stdio MCP ·
  desktop apps · raw file & exec · raw egress — each classified **GREEN** (configured, with
  receipts or a live watcher heartbeat inside the window), **AMBER** (configured but silent), or
  **GREY** (uncovered: events there leave *no* receipt). The window is stated on the map itself.
- **The map is itself evidence.** On every lane-state change (and at least daily) the Console
  signs a `kriya.coverage.snapshot` receipt into its own hash chain
  (`~/.kriya/audit/coverage.jsonl`), verifiable by the same offline verifiers as any receipt.
  So "we were covered all quarter" is a *checkable chain of signed statements*, and a silenced
  Console, a stopped watcher, or a deleted stretch of history is **visible by absence** — a gap in
  the heartbeat chain, not a quiet nothing.
- **What a GREEN lane does NOT claim.** GREEN means the configured source was alive and recording
  in the window — not that every event in that lane was captured (a watcher can be stopped *before*
  an action and restarted after; the heartbeat bounds the gap in time but cannot manufacture the
  missing event), and never that payload content was read (recording is metadata: action, actor,
  time, outcome — no TLS payloads). A GREY lane is the honest statement that nothing would have
  been recorded there at all.

## Why on-device matters here

For local and regulated apps, the audit cannot live in a cloud gateway — the data and the human are
on the device, and so the proof must be too. kriya Console verifies and aggregates **on your
machine**: the receipts, the policy, and the evidence export never leave it. That is the posture
EU AI Act record-keeping and SOC 2 monitoring expect when an agent touches real data, in exactly the
place a cloud MCP gateway structurally cannot reach.

*Questions for a security review:* **Sandeepshekhar26@gmail.com**.
