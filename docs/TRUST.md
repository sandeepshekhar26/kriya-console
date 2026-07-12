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

## The three-tier data-boundary promise

The Console now has three distinct postures — free single-machine use, an enrolled device
reporting into a fleet, and the fleet cockpit itself — and each carries a different, precisely
scoped promise about what ever leaves the machine. Stating them side by side, rather than letting
"nothing leaves the device" quietly become the answer for all three, is the same honesty discipline
as the Coverage Map above: say exactly what is and isn't true, per state, not a comforting average.

| Tier | Promise | What that means concretely |
|---|---|---|
| **Free / un-enrolled device** | **Machine-level: nothing leaves the device, full stop.** | No fleet connection is configured, so no socket to any server — kriyad or otherwise — is ever opened for audit/evidence purposes. This is unchanged, byte-for-byte, by anything below: the free tier's claim on this page has not been weakened or reinterpreted. |
| **Enrolled device** (paid `control-plane`) | **Boundary-level: minimized, signed envelopes and the device-info beacon go to the customer's own kriyad — never anywhere else.** | Once an operator points a device at a self-hosted `kriyad` (their box, their VM, their k8s, or an air-gapped enclave — see below), the device signs and sends redaction-minimized evidence envelopes plus the periodic `DeviceInfo` inventory beacon (§7 fields only, see below) to that one server, over mTLS. Raw receipts and raw payload values are never included — see "Honest boundaries" above for what recording even means. This traffic never reaches kriya's infrastructure or any third-party cloud; it terminates at infrastructure the customer alone controls. |
| **Operator** (paid `fleet-console`, the cockpit) | **Boundary-level: the cockpit pulls from, and publishes policy to, the customer's own kriyad — never kriya's or any vendor's cloud.** | The fleet cockpit view in this same Console app, run in "operator mode," talks only to the customer's self-hosted `kriyad` (the same server enrolled devices report to) to read coverage/evidence and publish org-key-signed policy bundles (shipped in P3; each device re-verifies the org signature before applying). It is the same on-device Console binary, not a hosted dashboard — there is no kriya-operated server in this path at any point. |

**The through-line, at every tier: kriya (the vendor) never receives your data.** The only thing
that changes tier-to-tier is whether anything leaves the *device* at all, and if it does, that it
goes exclusively to infrastructure the customer stands up and controls themselves. There is no
tier, free or paid, in which evidence or inventory data is sent to a server kriya operates.

**Why this doesn't undercut the ops story.** Raw receipts and raw payload values stay device-local
even for an enrolled device — not merely as a courtesy, but because it keeps the customer's own
`kriyad` store non-sensitive (a backup is one small SQLite file, not a honeypot of raw agent
payloads) and because it's the posture that survives an employee-privacy review: a regulated buyer
adopting fleet governance must be able to show they did *not* centralize keystroke-level employee
activity. Envelope verbosity beyond the minimized default is the customer's own policy dial to set
on their own server — not something this Console decides for them or defaults to.

### What the device-info beacon does — and does not — collect

The new `POST /v1/device-info` beacon (used by the enrolled-device tier above, and read back by
the cockpit's fleet table and per-device drill-in) is schema-constrained to an explicit allowlist
of device-scoped, technical fields, enforced in code, not just by convention:

| Collected (device-scoped, technical) | Excluded — never collected, never transmitted | Excluded — unavoidably seen in transport, never persisted |
|---|---|---|
| Console / runtime / verifier / agent / adapter versions | OS **username** | Source **IP** — any TCP connection reveals it to the server; kriyad must not write it to the store |
| Coarse OS platform, version, and architecture | **Hostname** — never auto-derived; the only device name shown is an optional, enterprise-assigned asset tag from the customer's own MDM, and the fleet cockpit falls back to a short public-key fragment (never a locally-known OS identity string) when that tag is absent | |
| Per-agent wired/unwired status, applied policy version | Timezone, locale, MAC address, hardware serial numbers | |
| Outbox depth (a health signal), enrollment time | | |

One scope sentence that must accompany this table wherever it is shown: **on a single-user device,
device-scoped records are still personal data under GDPR** — `device_pub` plus an MDM asset tag is
indirectly identifiable (pseudonymization is not anonymization). This table is *minimization within
scope*, not an exemption from it; the customer is the controller of what their kriyad receives.

This is the same field list documented as canonical in the runtime's `DeviceInfo` schema (see the
open kriya repo's `kriya-verify` crate), which ships with an adversarial test proving the exclusion
structurally: a probe that deliberately offers a username, a hostname, a source IP, a timezone, a
locale, a MAC address, and a serial number is fed through the real constructor, and none of those
seven values — or their field names — can appear anywhere in the signed bytes actually placed on
the wire. The guarantee here isn't "we chose not to send it today"; it's that the schema has no
field to put it in.

## Egress governance (E1) — honest limits

The Console can allowlist, budget, and receipt an agent's outbound calls through the governed
connector lanes (MCP-over-HTTP, gateway-proxied tool calls, and the hook-observed WebFetch/WebSearch
lane) — a standalone signed receipt in the `kriya.io.<direction>.<kind>.<decision>` vocabulary per
governed call, correlated to the underlying action receipt. Read this section before treating any of
it as a network boundary control, because it isn't one:

- **Governed lanes only, not the host.** *"When a stdio MCP server routed through kriya calls an
  external API, kriya sees — and signs — only the tool call and result that crossed its stdio pipe;
  the server's own outbound network traffic (which hosts it contacted, what it sent) is invisible to
  kriya and appears in no receipt. Host-level observation of that traffic is a separate, later
  capability."* A spawned subprocess or a stdio MCP server's own sockets bypass this lane entirely —
  the Coverage Map's grey **raw egress** lane names that gap on purpose; a green chip on a governed
  lane never colors it.
- **Two different byte-hash definitions, never conflated.** Every `kriya.io.*` receipt's `params`
  names `hash_scheme`: `"wire-bytes"` (the gateway/broker lane, where kriya is the TLS client and
  hashes the exact bytes on the wire) or `"canonical-json"` (the hook lane, which hashes the
  canonical key-sorted serialization of `tool_input`/`tool_response` — a different, less precise
  commitment). Byte counts are labeled *observed payload bytes*, never a wire/TLS-level accounting —
  connection reuse, headers, and keep-alive are invisible either way, and an SSE reply's `bytes_in`
  is flagged partial (a lower bound, not an exact count).
- **A denied call is receipted at the decision point.** A `kriya.io.*.deny` receipt is written
  before/instead of execution — the call never reaches the destination — so `deny` rows exist even
  though nothing crossed the wire. The one exception: fail-closed mode (below) can itself deny an
  egress because the receipt couldn't be written; that block carries no receipt by construction (the
  precondition failed), which is the whole point of the mode.
- **Fail-closed is opt-in, and inverts the honest default.** "No receipt, no egress" is a policy
  flag, off by default — the documented default is fail-**open** (a receipt-write failure doesn't
  block the call). Turning it on makes the signed receipt itself a precondition of the egress, which
  is unusually strong evidence, but it is not the out-of-the-box behavior.
- **The egress chip on the Coverage Map is a window observation, not a configuration attestation.**
  "ON" means at least one `kriya.io.egress.*` receipt was observed on that lane within the window;
  "OFF" means the lane is otherwise covered but none appeared. Neither state proves the egress tier
  was configured for the *entire* window — that requires a signed toggle/policy-version receipt this
  build does not yet emit. The compliance export's governed-surface posture statement says so
  explicitly (see "not monitored" vs "zero observed" below) rather than overclaiming a bound it can't
  prove.
- **What the chip, and the ledger, do NOT claim.** Not a firewall, not "DLP" (that word never appears
  in an E1-gated export), and never "every byte" — the honest label is "governed connector traffic."
  Enforcement rides a cooperative hook or gateway process that can be disabled at the host, same as
  every other governance seam in this document.

**The governed-surface posture statement** a compliance export prints is deliberately three-valued,
never a bare "zero egress":
- *"NOT MONITORED"* — zero governed-lane receipts of any kind were observed in the window, so no
  statement about egress can honestly be made either way (absent-by-configuration, not a finding).
- *"zero observed"* — the governed surface was active (other governed-lane receipts exist) and
  produced no egress, but this does **not** prove the ledger was continuously enabled for the full
  window (no toggle receipt bounds it yet).
- *"NOT zero"* — at least one `kriya.io.egress.*` receipt was observed and verified.

A physical air gap or network isolation, if one exists, is the organization's own attested posture —
kriya cannot verify it, and does not claim to.

## Employee privacy — E1

An identity-bound, timestamped record of which destinations an agent reached is employee-behavioral
data the moment it exists — this is architectural, not a policy choice, and it holds regardless of
how the feature is used:

- **What is recorded per user:** the destination host, observed payload byte counts, a content hash,
  the policy decision, and the acting agent + operator identity (the same `actor` field every kriya
  receipt already carries) — never the request/response content itself.
- **Purpose limitation, stated once, meant everywhere it's echoed:** compliance and security
  evidence — never individual performance evaluation, productivity scoring, or general monitoring of
  an operator's work. This sentence is the one to check any downstream export or fleet purpose-field
  against.
- **Who can read it:** whoever has filesystem access to the device (device-local, the default), or
  operator/console access to an enrolled fleet's customer-run `kriyad` — never a kriya-operated
  server, at any tier (see "The three-tier data-boundary promise" above).
- **Retention default:** unset (indefinite) until the operator configures one — see "Retention and
  the chain" below.
- **Per-device deny counts already reach an enrolled fleet's `kriyad`.** The minimized envelope's
  allowlisted action ids include the `kriya.io.*` facets, so an "attempted-policy-violation" tally
  per device is visible centrally even though the destination itself is not — disclosed here, not
  discovered later. Raw params (`dest_host`, `content_sha256`, byte counts) are structurally
  unreachable by the minimizer at any verbosity — see [redaction](#) below — so only the *count* of
  each `kriya.io.*` id travels, never what it names.
- **Ingress digests are OFF by default even when egress is ON**, and are keyed (HMAC under a
  device-local salt) rather than a plain hash when enabled — an unsalted hash of guessable content
  (a filename, a common phrase) is itself a content-disclosure risk ("did this agent read
  salary.xlsx?"), which a keyed hash forecloses for anyone without the salt.
- **The privacy artifact pack.** Deploying the egress/ingress ledger to employee devices is a real
  co-determination and data-protection question in many jurisdictions, not a formality — see
  [`docs/privacy/`](privacy/README.md) for a DPIA template (Art. 35), an employee-notice template
  (Arts. 13/14), and a model works-agreement clause for co-determination jurisdictions (DE/AT/NL/FR
  and similar). Treat the works-council step as a precondition to deployment there, not paperwork
  that follows it.

## Retention and the chain

Compliant deletion and tamper-evidence pull in opposite directions by default: pruning old receipts
to honor a retention limit (or a GDPR Art. 17 erasure request) normally looks exactly like an
attacker truncating the log. The design that resolves this:

- **A signed epoch-checkpoint receipt** (`kriya.retention.checkpoint`) seals a pruned prefix: its
  params attest *"receipts before T pruned per policy P; prior chain head was H"*, and its own
  `prev_hash` equals H — so it sits at the exact point the pruned lines used to be.
- **Every verifier accepts the checkpoint as a legitimate chain boundary**, not a break — the offline
  CLI, `kriya-verify`, and the TS verifier all recognize `kriya.retention.checkpoint` and treat the
  seal as sealed, the same way they already treat a genesis receipt's absent `prev_hash`.
- **Retained receipts re-chain onto the checkpoint**, re-signed by the same signing key (a prune can
  never re-attribute a receipt to a different key — that's a hard error, not a silent skip).
- **`kriya.io.*` gets a shorter default retention class than policy/approval receipts** — the
  egress/ingress ledger is the most granular, least evidence-durable data on the trail, so it is the
  first candidate for a shorter window when an operator sets one. Neither class has a retention limit
  by default; an unset `retention:` policy means indefinite retention, unchanged from before this
  feature existed.
- **The organization decides the actual retention period.** kriya provides the mechanism (the
  checkpoint design + the `retention:` policy field); it does not impose or default to a specific
  number of days. See [`docs/privacy/README.md`](privacy/README.md#retention-defaults) for suggested
  starting points tied to the compliance drivers this ledger supports.

## Why on-device matters here

For local and regulated apps, the audit cannot live in a cloud gateway — the data and the human are
on the device, and so the proof must be too. kriya Console verifies and aggregates **on your
machine**: the receipts, the policy, and the evidence export never leave it. That is the posture
EU AI Act record-keeping and SOC 2 monitoring expect when an agent touches real data, in exactly the
place a cloud MCP gateway structurally cannot reach.

*Questions for a security review:* **Sandeepshekhar26@gmail.com**.
