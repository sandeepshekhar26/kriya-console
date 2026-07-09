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
