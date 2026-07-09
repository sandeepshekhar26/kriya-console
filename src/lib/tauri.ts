// Bridge to the compiled Rust backend (D-018). In the Tauri app these call the backend commands;
// in a plain browser (dev / the old web build) `isTauri()` is false and the UI falls back to the
// manual-import + sample paths. The backend is the authoritative verifier and the paid gate; the
// React views are the thin viewer.

import type { AuditRow } from "./types";

/** True when running inside the Tauri webview (v2 exposes `__TAURI_INTERNALS__`). */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// Lazy imports so the modules are only pulled when actually in Tauri (keeps the browser build clean).
async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

/** Subscribe to the backend's `audit-changed` event; returns an unlisten fn. */
export async function onAuditChanged(cb: () => void): Promise<() => void> {
  const { listen } = await import("@tauri-apps/api/event");
  return listen("audit-changed", () => cb());
}

// ── Audit (free: live monitor + verify) ──────────────────────────────────────
export interface AuditFileInfo {
  name: string;
  path: string;
  receipts: number;
  bytes: number;
}
export interface AuditLocation {
  dir: string;
  files: AuditFileInfo[];
}
export const auditLocation = () => invoke<AuditLocation>("audit_location");
export const readAudit = () => invoke<AuditRow[]>("read_audit");
export const readAuditFile = (path: string) => invoke<AuditRow[]>("read_audit_file", { path });

// ── Coverage Map (free, W1) ──────────────────────────────────────────────────
export type LaneState = "green" | "amber" | "grey";
export interface LaneInfo {
  state: LaneState;
  /** The seam providing this lane's evidence (e.g. "hook.claude-code", "gateway"). */
  source?: string | null;
  lastReceiptMs?: number | null;
  files: number;
}
/** One lane within an agent's coverage group (GA-2). Mirrors Rust `coverage::AgentLane`. */
export interface AgentLane {
  id: string;
  title: string;
  state: LaneState;
  source?: string | null;
  lastReceiptMs?: number | null;
  /** For an out-of-scope lane: why it can't produce an on-device receipt. */
  locus?: string | null;
}
/** One agent's coverage group. Mirrors Rust `coverage::AgentCoverage`. */
export interface AgentCoverage {
  agent: string;
  label: string;
  lanes: AgentLane[];
}
export interface CoverageStatus {
  windowH: number;
  lanes: Record<string, LaneInfo>;
  lastSnapshotMs?: number | null;
  snapshotChainOk: boolean;
  snapshots: number;
  /** Per-agent coverage groups (Claude Code, Hermes) — a view layer over the same audit dir. */
  agents: AgentCoverage[];
}
export const coverageStatus = () => invoke<CoverageStatus>("coverage_status");

// ── Onboarding (free) ────────────────────────────────────────────────────────
export interface OnboardingStatus {
  gatewayPresent: boolean;
  gatewayPath: string | null;
  gatewayBundled: boolean;
  accessibilityTrusted: boolean | null;
  claudeConfigPath: string;
  claudeConfigExists: boolean;
  wiredServers: string[];
  auditDir: string;
  auditLogs: number;
  /** An `agent-policy.yaml` exists where the runtime loads it (cwd or ~/.kriya/). */
  policyPresent: boolean;
}
export interface WireRequest {
  /** `kriya` = a kriya-instrumented server launched directly (bolt-on / serve). */
  front: "kriya" | "proxy" | "reach-in" | "computer-use" | "router";
  app?: string;
  approval?: string;
  downstream?: string[];
}
export interface WireResult {
  serverKey: string;
  configPath: string;
  snippet: string;
  merged: boolean;
}
export const onboardingStatus = () => invoke<OnboardingStatus>("onboarding_status");
export const openSettingsPane = (pane: string) => invoke<void>("open_settings_pane", { pane });
export const listCandidateApps = () => invoke<string[]>("list_candidate_apps");
export const wireClaudeConfig = (req: WireRequest) => invoke<WireResult>("wire_claude_config", { req });

// ── Govern-all (free, GA-0) ──────────────────────────────────────────────────
/** `governed` = wired through its seam; `ungoverned` = detected, wireable; `needs-permission` = a
 *  macOS grant is missing; `out-of-scope-cloud` = executes off-device, no on-device receipt possible. */
export type GovernState = "governed" | "ungoverned" | "needs-permission" | "out-of-scope-cloud";
/** One governable target in the detected surface. Mirrors Rust `govern::GovernTarget` (camelCase). */
export interface GovernTarget {
  /** Stable id (`<agent>:<kind>[:<key>]`) — the handle for per-item govern/ungovern + the toggle. */
  id: string;
  /** `claude-code` | `claude-desktop` | `hermes` | `desktop`. */
  agent: string;
  /** `hook` | `mcp-server` | `desktop-apps`. */
  kind: string;
  /** `hook` | `gateway` | `reach-in/computer-use`. */
  seam: string;
  state: GovernState;
  configPath?: string | null;
  label: string;
  detail: string;
}
/** The whole detected governable surface. Mirrors Rust `govern::GovernableSurface`. */
export interface GovernableSurface {
  targets: GovernTarget[];
  /** Is `kriya-hook` bundled/resolvable? (Govern-all can't install a hook it doesn't ship.) */
  hookAvailable: boolean;
  /** Is `kriya-gateway` bundled/resolvable? */
  gatewayAvailable: boolean;
  /** Is `kriya-hermes-hook` bundled/resolvable? A distinct binary/availability from
   *  `hookAvailable` — Claude Code and Hermes each have their own hook adapter. */
  hermesHookAvailable: boolean;
  /** macOS Accessibility trust for the desktop lane (`null`/absent off macOS). */
  axTrusted?: boolean | null;
  /** Running desktop-app names (reach-in/computer-use candidates) — for the Advanced drawer. */
  desktopCandidates: string[];
}
export interface HookResult {
  agent: string;
  configPath: string;
  hookPath: string;
  installed: boolean;
}
export const governableSurface = () => invoke<GovernableSurface>("governable_surface");
export const installHook = (agent: string) => invoke<HookResult>("install_hook", { agent });
export const uninstallHook = (agent: string) => invoke<HookResult>("uninstall_hook", { agent });

/** The Console-authored policy YAML, persisted to `~/.kriya/agent-policy.yaml` — the file every
 *  seam above wires via `--policy` (B0). Mirrors Rust `govern::PolicySaveResult`. */
export interface PolicySaveResult {
  path: string;
  bytes: number;
}
export const saveAgentPolicy = (yaml: string) => invoke<PolicySaveResult>("save_agent_policy", { yaml });
export const loadAgentPolicy = () => invoke<string | null>("load_agent_policy");

// ── Govern-all orchestrator (free, GA-1) ─────────────────────────────────────
/** One planned/performed change. Mirrors Rust `govern::GovernAction`. */
export interface GovernAction {
  targetId: string;
  agent: string;
  /** `hook` | `gateway`. */
  seam: string;
  /** `install-hook` | `wrap-mcp-server` (govern) · `uninstall-hook` | `unwrap-mcp-server` (revert). */
  action: string;
  serverKey?: string | null;
  configPath?: string | null;
  detail: string;
}
export interface GovernError {
  targetId: string;
  message: string;
}
/** The dry-run plan (`govern_preview`). Mirrors Rust `govern::GovernPlan`. */
export interface GovernPlan {
  wire: GovernAction[];
  needsPermission: GovernTarget[];
  outOfScopeCloud: GovernTarget[];
  alreadyGoverned: GovernTarget[];
  blocked: GovernTarget[];
  hookAvailable: boolean;
  gatewayAvailable: boolean;
  hermesHookAvailable: boolean;
}
/** The result of a `govern_all`. Mirrors Rust `govern::GovernAllReport`. */
export interface GovernAllReport {
  wired: GovernAction[];
  needsPermission: GovernTarget[];
  outOfScopeCloud: GovernTarget[];
  alreadyGoverned: GovernTarget[];
  errors: GovernError[];
}
/** The result of an `ungovern_all` / `ungovern`. Mirrors Rust `govern::RevertReport`. */
export interface RevertReport {
  reverted: GovernAction[];
  errors: GovernError[];
}
export interface GovernOpts {
  /** Restrict the run to these target ids (the per-item toggle). Omit to govern the whole surface. */
  only?: string[];
}
export const governPreview = () => invoke<GovernPlan>("govern_preview");
export const governAll = (opts?: GovernOpts) => invoke<GovernAllReport>("govern_all", { opts: opts ?? null });
export const ungovernAll = () => invoke<RevertReport>("ungovern_all");
export const ungovern = (target: string) => invoke<RevertReport>("ungovern", { target });

// ── License (R29) ────────────────────────────────────────────────────────────
export interface LicenseStatus {
  tier: "free" | "pro";
  valid: boolean;
  holder?: string | null;
  features: string[];
  expiresMs?: number | null;
  licenseId?: string | null;
  reason?: string | null;
}
export const licenseStatus = () => invoke<LicenseStatus>("license_status");
export const installLicense = (token: string) => invoke<LicenseStatus>("install_license", { token });
export const removeLicense = () => invoke<LicenseStatus>("remove_license");

// ── Paid (Rust, license-gated) ───────────────────────────────────────────────
export interface SignerGroup {
  fingerprint: string;
  receipts: number;
  verified: number;
  failed: number;
  apps: string[];
  agents: string[];
  operators: string[];
}
export interface AppRollup {
  app: string;
  receipts: number;
  verified: number;
  destructive: number;
  chainBreakLine: number | null;
}
export interface FleetReport {
  totalReceipts: number;
  verified: number;
  failed: number;
  failedActions: number;
  distinctSigners: number;
  distinctApps: number;
  distinctAgents: number;
  onDeviceAttestations: number;
  firstMs: number;
  lastMs: number;
  tamperSignals: string[];
  signers: SignerGroup[];
  apps: AppRollup[];
}
export interface ComplianceControl {
  id: string;
  name: string;
  status: "satisfied" | "partial" | "gap";
  evidence: string;
}
export interface ComplianceBundle {
  framework: string;
  generatedMs: number;
  totalReceipts: number;
  verified: number;
  failed: number;
  distinctApps: number;
  distinctAgents: number;
  distinctOperators: number;
  onDeviceAttestations: number;
  destructiveActions: number;
  integrityOk: boolean;
  controls: ComplianceControl[];
  markdown: string;
  json: string;
}
export const fleetCorrelation = () => invoke<FleetReport>("fleet_correlation");
export const exportCompliance = (framework: string) => invoke<ComplianceBundle>("export_compliance", { framework });

// ── Fleet cockpit (paid, P1: signed DeviceInfo beacon, doc 22 §7) ────────────
// kriyad's wire types (kriyad is a separate Rust binary the Console talks to over mTLS — not a Tauri
// `invoke` command — so these interfaces are hand-mirrored from `kriya-verify::DeviceInfo` /
// `kriya-aggregator::store::DeviceCoverage`, same "Mirrors Rust ..." convention as the sections above).
//
// BC-3/BC-4 (doc 22 §8): every field below that was introduced in P1 is OPTIONAL here, even fields
// that are always-present in a freshly-signed DeviceInfo — because a TS client built BEFORE this
// schema existed must still type-check and parse against a superset response (an old cockpit build
// talking to a new kriyad, or this new cockpit talking to an old kriyad that never sends these keys
// at all). Treat `?:` here as "the wire may omit this key", independent of whether the *producing*
// Rust struct happens to make the field non-optional once it exists.

/** One detected agent + its governance adapter. Mirrors Rust `kriya_verify::AgentInfo`. */
export interface DeviceAgentInfo {
  id?: string;
  version?: string;
  adapter?: string;
  adapter_version?: string;
  wired?: boolean;
}

/** Coarse, non-fingerprinting OS descriptor. Mirrors Rust `kriya_verify::OsInfo`. */
export interface DeviceOsInfo {
  platform?: string;
  version?: string;
  arch?: string;
}

/** Freshness echo of the applied policy bundle (doc 22 §5) — absent until P3 lands. Mirrors Rust
 *  `kriya_verify::PolicyEcho`. */
export interface DevicePolicyEcho {
  applied_version?: number;
  bundle_hash?: string;
}

/** The device inventory snapshot, doc 22 §7 schema — allowlist-only on the Rust side (no
 *  username/hostname/IP/locale/serial can ever appear here). Mirrors Rust `kriya_verify::DeviceInfo`.
 *  Every field optional per BC-3/BC-4 above. */
export interface DeviceInfo {
  console_version?: string;
  /** The governed gateway/runtime, e.g. `"kriya-host 0.4.2"`. */
  runtime_version?: string;
  verify_crate_version?: string;
  os?: DeviceOsInfo;
  /** Detected by the doc-21 govern-all engine. */
  agents?: DeviceAgentInfo[];
  /** `null`/absent until the P3 policy-push phase lands. */
  policy?: DevicePolicyEcho | null;
  /** Buffered envelopes — a health signal. */
  outbox_pending?: number;
  enrolled_ms?: number;
  /** ONLY the enterprise-assigned MDM asset tag — NEVER derived from the OS hostname. */
  device_label?: string | null;
}

/** The signed wire envelope `POST`ed to kriyad's `/v1/device-info`. Mirrors Rust
 *  `kriya_verify::SignedDeviceInfo`. */
export interface SignedDeviceInfo {
  device_pub?: string;
  collected_ms?: number;
  info?: DeviceInfo;
  signature?: string;
}

/** One device's `GET /v1/coverage` row from kriyad. The `device_pub`.. `status` fields are the
 *  original (pre-P1) shape; every field below that is new, additive, `skip_serializing_if`-absent
 *  (never `null`) on a device that hasn't posted a DeviceInfo beacon yet (BC-4) — hence optional here
 *  too. Mirrors Rust `kriya_aggregator::store::DeviceCoverage`. Snake_case (kriyad is a plain JSON
 *  HTTP API, not a `#[serde(rename_all = "camelCase")]` Tauri command — unlike every interface above). */
export interface DeviceCoverageRow {
  device_pub: string;
  org_id?: string | null;
  business_unit?: string | null;
  last_seq: number;
  max_seq_seen: number;
  last_seen_ms: number;
  /** `current` · `behind` · `silent`. */
  status: string;
  // --- doc 22 §7 device-inventory passthrough (P1), all additive/optional ---
  console_version?: string;
  runtime_version?: string;
  verify_crate_version?: string;
  os_platform?: string;
  os_version?: string;
  os_arch?: string;
  policy_applied_version?: number;
  policy_bundle_hash?: string;
  outbox_pending?: number;
  enrolled_ms?: number;
  device_label?: string;
  agents?: DeviceAgentInfo[];
  info_collected_ms?: number;
  // --- P4 (doc 22 §9-CM) drift-view passthrough, additive/optional. Still just the SERVED HINT — the
  // cockpit re-verifies a device's actual applied version against its own signed envelopes locally
  // (`lib/policyDrift.ts`) before rendering a drift verdict; never trust these two fields alone. ---
  applied_policy_version?: number;
  applied_bundle_hash?: string;
  /** The highest bundle version this kriyad has ever accepted — the SAME value on every row (no
   *  genuine "top-level" slot in a bare JSON array without breaking every existing parser, BC-4). */
  latest_bundle_version?: number;
}

// ── Fleet cockpit — the Tauri commands themselves (paid, P2, doc 22 §6/§8) ──
// The P0 Rust commands (`src-tauri/src/control_plane/fleet.rs`) predate this file having any wrapper
// for them; P1 added the DeviceInfo/DeviceCoverageRow types above but not these. Tauri v2 auto-converts
// each Rust snake_case param to a camelCase JS object key — these mirror `fleet.rs`'s exact signatures.

/** One re-verified envelope: the raw signed line as returned by kriyad, plus whether it verifies
 *  locally against kriya-verify right now (BC-5). `verified: false` is returned, not thrown — a
 *  forged/tampered row is itself the finding, not a reason to hide the rest of the window. Mirrors
 *  Rust `control_plane::fleet::VerifiedEnvelope` (`#[serde(rename_all = "camelCase")]`). */
export interface VerifiedEnvelope {
  raw: string;
  verified: boolean;
  /** Set only when verification failed — the reason, for the operator's investigation. */
  error?: string | null;
}

/** Mirrors Rust `control_plane::fleet::DeviceEvidence`. */
export interface DeviceEvidence {
  envelopes: VerifiedEnvelope[];
  /** The device's most-recent signed heartbeat line, re-verified the same way — `null` if the
   *  device has never heartbeat. */
  heartbeat?: VerifiedEnvelope | null;
}

/** Probe `url`'s `/healthz` over mTLS with the given CA + client cert/key, and ONLY on success persist
 *  the connection to `~/.kriya/console/fleet.json`. Requires the `fleet-console` license flag (checked
 *  Rust-side, first, before any network I/O). */
export const fleetConnect = (url: string, caPemPath: string, certPath: string, keyPath: string) =>
  invoke<void>("fleet_connect", { url, caPemPath, certPath, keyPath });

/** `GET /v1/coverage` — the per-device liveness/completeness dashboard. */
export const fleetCoverage = () => invoke<DeviceCoverageRow[]>("fleet_coverage");

/** `GET /v1/verify?device_pub=&from_seq=&to_seq=` — the trustless read-back, re-verified LOCALLY over
 *  the raw returned bytes before this ever reaches the UI (BC-5: never trust the wire, never re-verify
 *  a re-serialization). */
export const fleetDeviceEvidence = (devicePub: string, fromSeq: number, toSeq: number) =>
  invoke<DeviceEvidence>("fleet_device_evidence", { devicePub, fromSeq, toSeq });

// ── Org policy key (paid, P3, doc 22 §3/§5) ──────────────────────────────────
/** Mirrors Rust `control_plane::org_key::OrgKeyInfo`. */
export interface OrgKeyInfo {
  orgPolicyPub: string;
  pubPath: string;
  /** `false` when an existing key was found and returned unchanged (never silently rotated). */
  generated: boolean;
}
/** Generate (once) the org policy key that signs `PolicyBundle`s — private half in the OS keychain,
 *  public half exported to `org-policy.pub` for MDM/enrollment. Idempotent-but-honest: calling this
 *  again after a key exists returns it unchanged (`generated: false`), never rotates it silently. */
export const orgPolicyKeygen = () => invoke<OrgKeyInfo>("org_policy_keygen");

// ── Policy authoring / publish (paid, P3, doc 22 §5) ─────────────────────────
/** `GET /v1/policy` preview — the latest bundle this cockpit can see (may miss a narrowly
 *  device/BU-scoped bundle; see Rust `fleet::fleet_policy_preview`'s doc comment). `null` when nothing
 *  is published yet. Shaped as the raw `{bundle: PolicyBundle, signature}` wire object. */
export const fleetPolicyPreview = () => invoke<{ bundle: PolicyBundleDraft; signature: string } | null>(
  "fleet_policy_preview",
);

/** Mirrors Rust `kriya_verify::PolicyBundle`'s editable fields (snake_case — the wire shape). */
export interface PolicyBundleDraft {
  org_id: string;
  version: number;
  issued_ms: number;
  expires_ms?: number | null;
  scope: { business_unit?: string | null; device_pubs?: string[] | null };
  policy: Record<string, unknown>;
  budgets: Record<string, unknown>;
  govern: { target: string; action: string }[];
  envelope_verbosity: string;
}

/** Mirrors Rust `control_plane::fleet::PublishResult`. */
export interface PublishResult {
  version: number;
  duplicate: boolean;
}

/** Author → sign (OS-keychain org key) → publish. `version` is computed server-side (never trust a
 *  client-supplied version — anti-rollback). Requires `fleet-console` AND a generated org key
 *  (`orgPolicyKeygen`). */
export const fleetPublishPolicy = (args: {
  orgId: string;
  businessUnit?: string | null;
  devicePubs?: string[] | null;
  expiresMs?: number | null;
  policy: Record<string, unknown>;
  budgets: Record<string, unknown>;
  govern: { target: string; action: string }[];
  envelopeVerbosity: string;
}) => invoke<PublishResult>("fleet_publish_policy", args);

// ── Org-wide evidence export (paid, P5, doc 22 §9) ───────────────────────────
// The per-device engine (`exportCompliance`/`ComplianceBundle` above) is untouched by this — kriyad
// only ever stores signed envelope rollups, never raw receipts (doc 22 §11-B1), so this is a wholly
// separate, envelope-native module (`fleet_evidence.rs`). Mirrors its Rust shape field-for-field.

/** `"satisfied" | "partial" | "gap"` — mirrors Rust `fleet_evidence::ControlStatus` (serde `lowercase`). */
export type OrgControlStatus = "satisfied" | "partial" | "gap";

/** Mirrors Rust `control_plane::fleet_evidence::OrgControl`. */
export interface OrgControl {
  framework: string;
  control: string;
  requirement: string;
  evidence: string;
  status: OrgControlStatus;
}

/** One device's row in the fleet coverage-completeness table — mirrors Rust
 *  `control_plane::fleet_evidence::DeviceCompleteness`. */
export interface DeviceCompleteness {
  devicePub: string;
  deviceLabel?: string | null;
  /** kriyad's own liveness hint (`current`/`behind`/`silent`) — the fields below are the LOCALLY
   *  re-verified proof layer, not a second hint. */
  liveness: string;
  envelopesInWindow: number;
  /** Human-readable seq-continuity gap citations, e.g. `"seq 12 -> 15 (2 missing)"`. Empty = no gaps. */
  seqGaps: string[];
  chainIntact: boolean;
  chainBreakAt?: number | null;
  /** From the LATEST in-window envelope's `policy_state`, locally re-verified — absent if this
   *  device's window carries no envelope with one (never applied within the window, or pre-P3). */
  appliedPolicyVersion?: number | null;
  appliedBundleHash?: string | null;
  consoleVersion?: string | null;
  runtimeVersion?: string | null;
}

/** The full org-wide evidence bundle — mirrors Rust `control_plane::fleet_evidence::OrgEvidence`.
 *  `markdown`/`json` are the ready-to-save report text, generated in Rust (same pattern as
 *  `ComplianceBundle` above: the Console never re-derives report text client-side). */
export interface OrgEvidence {
  generatedMs: number;
  organization: string;
  windowFromMs: number;
  windowToMs: number;
  devicesTotal: number;
  devicesCurrent: number;
  devicesBehind: number;
  devicesSilent: number;
  deviceCompleteness: DeviceCompleteness[];
  /** The highest version among the currently-published, in-scope-visible bundle(s) — absent when
   *  nothing has ever been published. */
  latestBundleVersion?: number | null;
  /** Named exceptions: devices whose locally-verified applied version is behind `latestBundleVersion`,
   *  or that have never applied any bundle at all. */
  drift: string[];
  controls: OrgControl[];
  markdown: string;
  json: string;
}

/** The org-wide, envelope-native evidence export (P5, doc 22 §9). Requires `fleet-console`.
 *  `windowMs` defaults to 90 days (Rust `fleet_evidence::DEFAULT_WINDOW_MS`) when omitted. */
export const fleetOrgEvidence = (organization: string, windowMs?: number | null) =>
  invoke<OrgEvidence>("fleet_org_evidence", { organization, windowMs: windowMs ?? null });
