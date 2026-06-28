// Demo seed — real signed data for the pitch walkthrough. The receipts and the device envelopes are
// genuinely signed (the same fixtures the Rust e2e uses); the Control Plane view re-verifies them with
// the real in-browser Ed25519 verifier. The peer fleet rows are illustrative (clearly marked) so the
// coverage table looks like a real deployment; the cryptographic proof runs on the real focus device.

import outboxRaw from "./fixtures/pilot-outbox.ndjson?raw";
import heartbeatRaw from "./fixtures/pilot-heartbeat.json?raw";
import devicePubRaw from "./fixtures/pilot-device-pub.txt?raw";
import sampleAudit from "../sample/sample-audit.jsonl?raw";
import sampleApprovals from "../sample/sample-approvals.jsonl?raw";
import type { SignedEnvelope } from "../lib/envelope";

export const DEVICE_PUB = devicePubRaw.trim();

/** The real device's signed AttestationEnvelope chain (seq 1 → seq 2). */
export const ENVELOPES: SignedEnvelope[] = outboxRaw
  .trim()
  .split("\n")
  .filter(Boolean)
  .map((l) => JSON.parse(l) as SignedEnvelope);

/** The device's signed heartbeat (the tail-truncation anchor): `seq_seen` = highest seq it emitted. */
export const HEARTBEAT = JSON.parse(heartbeatRaw) as {
  heartbeat: { device_pub: string; seq_seen: number; ts_ms: number };
  public_key: string;
  signature: string;
};

export const SAMPLE_AUDIT = sampleAudit;
export const SAMPLE_APPROVALS = sampleApprovals;

export type Coverage = "current" | "behind" | "silent";

export interface FleetDevice {
  id: string;
  pub: string;
  bu: string;
  status: Coverage;
  lastSeq: number;
  maxSeqSeen: number;
  lastSeen: string;
  real?: boolean; // the cryptographically re-provable focus device
}

const short = (p: string) => `${p.slice(0, 8)}…${p.slice(-4)}`;

/**
 * The fleet reporting into the on-prem aggregator. `build-host-07` is the REAL device whose signed
 * envelopes the verify panel re-proves; the peers are illustrative so the coverage view reads like a
 * real deployment (current / behind / silent are the three states kriyad derives).
 */
export const FLEET: FleetDevice[] = [
  { id: "build-host-07", pub: short(DEVICE_PUB), bu: "Platform Eng", status: "current", lastSeq: 2, maxSeqSeen: 2, lastSeen: "just now", real: true },
  { id: "fin-analyst-12", pub: "7b9c4af1…a1e0", bu: "Finance", status: "current", lastSeq: 184, maxSeqSeen: 184, lastSeen: "40s ago" },
  { id: "ci-runner-02", pub: "3f10d8c2…9d7b", bu: "Platform Eng", status: "behind", lastSeq: 88, maxSeqSeen: 91, lastSeen: "2m ago" },
  { id: "risk-desk-03", pub: "c4d2e6a9…7e3c", bu: "Risk & Controls", status: "silent", lastSeq: 51, maxSeqSeen: 51, lastSeen: "4h 12m ago" },
];

export const FLEET_STATS = {
  devices: FLEET.length,
  current: FLEET.filter((d) => d.status === "current").length,
  behind: FLEET.filter((d) => d.status === "behind").length,
  silent: FLEET.filter((d) => d.status === "silent").length,
  envelopes: 1247, // illustrative cumulative ingest count for the deployment
  rejected: 3, // forged/malformed envelopes the aggregator refused at ingest
};
