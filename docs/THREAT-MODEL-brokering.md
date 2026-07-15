# Threat model — credential brokering (doc 24 §11 B13 / EG-B)

Every other governed-lane control kriya ships is kriya acting as a **witness**: it observes an agent
action and signs a receipt about it, but it never itself becomes a place where sensitive data lives.
Credential brokering is different in kind. kriya becomes a **custodian** — it briefly holds a real
secret in its own process memory so it can inject it into an outbound call the agent never sees the
value of. That is a genuinely new attack surface, not a bigger version of an old one, and it gets its
own threat model rather than a paragraph in [`TRUST.md`](TRUST.md).

## The one-sentence claim

The agent composes tool calls with a placeholder — `{{kriya:<alias>}}` — never a real credential;
kriya substitutes the real value from OS Keychain at the moment a call actually leaves the machine, on
a governed lane, scoped to that ONE alias's own destination allowlist; the real value is never hashed,
logged, or written into a signed receipt.

## What you can prove

- **The agent's own context never contains the secret.** The model composes `{{kriya:github_pat}}`,
  not a token — so a prompt-injection attack, a careless `git log`/paste by the agent, or a leaked
  transcript exposes a meaningless placeholder string, not a working credential.
- **No receipt — action or io — ever carries the value.** Every `kriya.io.*` receipt's
  `content_sha256` is computed over the outbound body *before* substitution runs; the substitution
  itself happens in a separate buffer that the hashing code never sees. A cleared brokered call is
  additively flagged (`"b13-brokered:<alias>"`) — the alias name, never the value.
- **A misrouted call is denied, not brokered.** Each alias carries its OWN destination allowlist,
  independent of (and typically narrower than) the general egress tier. A placeholder bound for a host
  the alias doesn't list is refused before any Keychain read happens — see "Scope, not blanket trust"
  below.
- **An unconfigured or unparseable placeholder fails closed.** A `{{kriya:x}}` for an alias that was
  never configured, or a tool call with no resolvable destination at all (a raw shell command), is
  denied outright — doc 24 §11's "on any ambiguity, deny" rule, applied here specifically because
  ambiguity in a credential-handling path is the one place a soft failure is unacceptable.

## How it works — the two substitution points, and nowhere else

Substitution happens in exactly two places:

1. **The governed HTTP transport** (`mcp::client::HttpTransport`, in the open-source runtime) —
   right before the request body is handed to the TLS socket.
2. **The Claude Code hook lane** (`bin/kriya-hook`) — via Claude Code's own documented
   `hookSpecificOutput.updatedInput` mechanism: the `PreToolUse` hook returns the substituted
   arguments, and Claude Code executes the tool with them. The model never sees `updatedInput`; only
   the tool does.

It deliberately does **not** happen by mutating an action's params before the action receipt is
signed, or before the executor runs — both of those capture params verbatim, so substituting there
would put the real secret into the permanent signed record, which is the exact leak this feature
exists to prevent. Reading a secret's value happens exactly once per substitution, as late as
possible, at the point that is actually about to send it.

**Dual-layer enforcement**, the same shape as the SSRF/rebinding guard (B6): a governor-level
pre-check that only ever asks "is this alias configured and scoped to this destination" — it never
reads a value, so it can produce a clean, attributed deny receipt without touching Keychain — and a
transport-level check that is the actual, TOCTOU-relevant enforcement, reached only after the
pre-check already cleared. Either layer failing independently denies the call.

**Scope, not blanket trust.** An alias's `allowed_hosts` is deliberately its own field, separate from
the general egress destination tier. A host being on the broad egress allowlist says nothing about
whether *this specific credential* should ever be sent there — the two are checked independently, and
brokering only fires when both agree.

## An honest, undocumented-behavior problem — and how it's closed

Claude Code does not document whether a `PostToolUse` hook's `tool_input` reflects the original
(placeholder) form the model composed, or the mutated (real-secret) form a preceding `PreToolUse`
substituted via `updatedInput`. Rather than assume either answer, kriya-hook's `post` stage treats
this as adversarial: whenever `secrets:` is configured and a call's destination is knowable, it
actively scans the *observed* `tool_input` for each configured alias's real Keychain value and
redacts any match back to `{{kriya:<alias>}}` **before** anything — the action receipt, the io
receipt — hashes or records it. If the real value was never present, every redaction is a harmless
no-op; if it was, it is gone before it can leak. This holds regardless of which of the two
(undocumented) behaviors turns out to be true, and is exercised directly by an end-to-end test that
runs `post` with both forms and asserts neither produces a receipt containing the real value.

## Custody: OS Keychain, never a file

A `secrets:` policy entry is a **reference** — a Keychain service + account pair — never a value.
`agent-policy.yaml` is operator-authored and, per doc 24's own frozen-format discipline, round-trips
through the Console; a plaintext secret in that file would defeat the entire feature; the schema
structurally cannot express one.

The runtime reads a secret's real value via the macOS Keychain (`/usr/bin/security
find-generic-password`, invoked with the service/account as separate process arguments — never
shell-interpolated, so not susceptible to injection even though those two strings come from
operator-authored policy). This is standard macOS Keychain, not a Secure Enclave-gated item requiring
a fresh biometric/passcode prompt on every read: an agent's automated calls need to complete without
a human physically present at each one, so item-level biometric gating isn't compatible with the
brokering use case as built. What IS true: the macOS Keychain database itself is encrypted at rest
under a key hierarchy rooted in the device's Secure Enclave / hardware-backed data protection, and
access is gated behind the user's own login session — meaningfully more custody than a file kriya
itself writes, which is the comparison that actually matters here (see "why this is still better"
below). Once read, the value is wrapped in a zeroizing buffer (`zeroize`) from the moment it exists in
kriya's process memory, and the intermediate subprocess-output buffer is explicitly zeroed before the
final value is extracted from it — best-effort in-process hygiene, not a guarantee against a
sophisticated attacker with kernel-level memory-forensics capability. No implementation of in-process
secret hygiene in a garbage-collected-adjacent runtime (Rust's allocator can still leave copies in
freed-but-unzeroed heap pages the zeroizing wrapper never touched, registers, or swap) is airtight
against that threat class, and this doc will not claim otherwise.

A real, non-hypothetical correctness bug was caught and fixed while building this: naively splicing a
secret's raw bytes into an already-JSON-encoded body corrupts the JSON (or worse, lets a secret
containing `"`/`\` break out of its intended string field) if the value itself contains a JSON special
character. Every substitution path JSON-escapes the value before splicing it — proven by an end-to-end
test using a secret deliberately chosen to contain a quote and a backslash, round-tripped through a
real Keychain item.

## What a compromised host can do

Be precise about the blast radius, because "kriya holds secrets now" invites both over- and
under-stating it:

- **A compromised kriya process can read every alias it's configured for.** The governor/transport
  code runs with the same OS-level permissions as the rest of kriya; if an attacker achieves arbitrary
  code execution inside the kriya process itself, Keychain access control (gated behind the user's own
  login session, the same boundary any other app-level Keychain client gets) is the only remaining
  barrier — same as it would be for any macOS application that legitimately holds a Keychain
  reference. This is not a stronger guarantee than "the app has your login-session-scoped Keychain
  access," and doesn't claim to be.
- **A compromised or malicious MCP server the agent talks to gets nothing extra from brokering.** The
  substituted value only ever reaches the ONE destination the alias's `allowed_hosts` names, on the
  ONE governed lane the call is already going out; the whole design point is that a malicious or
  buggy server elsewhere on the same session can't cause your GitHub PAT to reach it, because
  brokering doesn't fire for a destination the alias doesn't list.
- **A compromised model (prompt injection, a malicious instruction hidden in fetched content) still
  cannot exfiltrate the credential.** It can at most cause kriya to construct a call TO an
  alias-allowed host WITH the placeholder — which either broker correctly (to a destination the
  operator already explicitly trusted with that exact credential) or gets denied. It cannot make the
  raw value appear anywhere the model can read, because the model is never shown it.
- **What brokering does NOT defend against:** a genuinely compromised, alias-allowed destination
  itself — if `api.github.com` is legitimately allowlisted for `github_pat` and GitHub's own
  infrastructure were compromised, that's the credential's owner being compromised, not a kriya
  failure; brokering was never a substitute for scoping *which* destinations get a credential at all
  (that's what `allowed_hosts` is for) or for the credential's own permissions (a PAT with
  delete-repo scope is still a PAT with delete-repo scope, brokered or not).

## Why this is still better than the agent holding the raw token

Without brokering, a real credential sits in the agent's own context: in the prompt, in tool-call
arguments the model composed and can therefore reproduce, in the transcript, in whatever logging the
agent host or the LLM provider does on its own inference path — none of which kriya has any control
or visibility over. Every one of those is a channel kriya cannot audit, redact from, or bound. Moving
the credential's real value out of that entire surface and into a single, narrow, auditable substitution
step — one kriya controls, receipts, and can scope per-destination — trades an unbounded exposure
surface for a bounded, governed one. It does not make the credential's value un-exfiltratable in
every conceivable scenario (see "what a compromised host can do" above); it removes the single most
common and highest-volume leak path, which is the agent's own context.

## Explicit non-goal

kriya is **not a secrets manager**. It does not generate, rotate, version, or audit-log secret
*lifecycle* events; it does not offer a UI for organizing secrets by team or environment; it has no
opinion on how the actual value got into Keychain in the first place. It is a narrow, governed
injection point that integrates with whatever the customer already uses to provision secrets onto the
device — 1Password, a corporate MDM profile, a manual `security add-generic-password`, or an
enterprise secrets manager's own CLI writing into Keychain. If the organization needs central
issuance, rotation policy, or a secrets-manager's own audit trail, that remains that system's job;
kriya's job starts at "the value already exists in Keychain" and ends at "the value reached exactly
the one destination it was scoped for, and nothing else ever saw it."

## Related

- [`TRUST.md`](TRUST.md) — the Console-wide trust and tamper-evidence claims this doc is a focused
  extension of.
