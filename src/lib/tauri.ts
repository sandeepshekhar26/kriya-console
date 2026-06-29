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
