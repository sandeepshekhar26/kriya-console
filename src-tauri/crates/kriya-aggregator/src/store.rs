//! The append-only SQLite store (2.3) — kriyad's entire state in one file. Stores ONLY signed metadata
//! (the minimized envelope bytes + extracted rollup columns), NEVER raw payloads — the envelopes are
//! redacted by construction. Backup = copy the file. Inserts/queries land with the endpoints (2.5–2.9).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use kriya_verify::{PolicyScope, SignedDeviceInfo, SignedEnvelope, SignedHeartbeat, SignedPolicyBundle};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub struct Store {
    conn: Mutex<Connection>,
}

/// The row cap for `read_back` (doc 22 §11 DoS hardening): the store layer NEVER materializes more
/// than this many envelope rows into memory for a single read-back, regardless of how wide a window
/// was requested. This is the defense-in-depth backstop — it's what keeps a legacy client that sends
/// no `from_seq`/`to_seq` at all (defaults to `0..=u64::MAX`) working (capped, not rejected), even
/// though the HTTP layer separately rejects an explicitly oversized window with a 400.
pub const READ_BACK_ROW_CAP: i64 = 10_000;

/// The outcome of ingesting one envelope (idempotent on `(device_pub, seq)`).
#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    Accepted,
    Duplicate,
}

/// The outcome of ingesting one policy bundle (P3). Unlike envelope ingest (many devices, gap-tolerant
/// by construction), a bundle publish is a single authored, monotonic sequence from one operator, so a
/// version COLLISION with DIFFERENT content is a loud, distinct error (see [`Store::insert_policy_bundle`])
/// rather than a silently-ignored duplicate — an operator retry with the SAME bytes is still a safe
/// idempotent no-op.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyIngest {
    Accepted,
    DuplicateSameContent,
}

/// One device's coverage row (the derived liveness/completeness view).
///
/// Derives `Deserialize` too (not just `Serialize`) so BC-5 cross-version fixture tests can parse a
/// COMMITTED pre-P1 `/v1/coverage` JSON sample straight into this (new, superset) shape and assert
/// every P1 field lands as `None` — see
/// `main::tests::old_shape_coverage_fixture_parses_as_new_device_coverage_shape`. Production code
/// only ever serializes this type; deserialization is a test-only convenience of the same derive.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceCoverage {
    pub device_pub: String,
    pub org_id: Option<String>,
    pub business_unit: Option<String>,
    pub last_seq: i64,
    pub max_seq_seen: i64,
    pub last_seen_ms: i64,
    /// `current` · `behind` (a heartbeat claims a higher seq than is stored) · `silent` (stale).
    pub status: String,

    // --- doc 22 §7 device-inventory passthrough (P1) — ADDITIVE, optional, ABSENT (not null) when a
    // device has never posted a DeviceInfo beacon (pre-P1 devices, or ones that simply haven't beaconed
    // yet). Old cockpit clients parsing this JSON ignore unknown fields (BC-4); new clients get `null`/
    // absent as the honest "inventory: n/a" signal, never an error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_crate_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_applied_version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_pending: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrolled_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    /// The full `agents[]` array (doc 22 §7), stored/returned as opaque JSON — not worth its own table
    /// for a fleet-table passthrough; the cockpit already has `kriya_verify::AgentInfo` to parse it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agents: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info_collected_ms: Option<i64>,
}

/// A trustless read-back: the EXACT stored signed bytes + the device's most-recent signed heartbeat
/// (the tail-truncation anchor the auditor compares `returned_top_seq >= seq_seen` against).
#[derive(Debug, Serialize)]
pub struct Readback {
    pub envelopes: Vec<String>,
    pub heartbeat: Option<String>,
}

const MIGRATIONS: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Every accepted envelope: the EXACT signed bytes (for trustless read-back) + extracted rollup columns.
CREATE TABLE IF NOT EXISTS envelopes (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  device_pub    TEXT    NOT NULL,
  seq           INTEGER NOT NULL,
  prev_hash     TEXT,
  org_id        TEXT    NOT NULL,
  business_unit TEXT,
  window_from   INTEGER NOT NULL,
  window_to     INTEGER NOT NULL,
  merkle_root   TEXT    NOT NULL,
  receipts      INTEGER NOT NULL,
  verified      INTEGER NOT NULL,
  failed        INTEGER NOT NULL,
  destructive   INTEGER NOT NULL,
  non_egress    INTEGER NOT NULL,
  non_egress_proof TEXT,
  signed_bytes  BLOB    NOT NULL,
  signature     TEXT    NOT NULL,
  received_ms   INTEGER NOT NULL,
  -- Envelope v1.1 (P3, doc 22 §5) — the policy freshness echo, ALL NULLABLE so a pre-P3 envelope (or
  -- one from a device that has never applied a policy bundle) upserts/serves exactly as before (BC-4).
  -- Read-only observability columns for a future drift view (P4) — `GET /v1/verify` keeps serving
  -- `signed_bytes` verbatim regardless; these are never re-derived FROM the stored columns.
  policy_state_version     INTEGER,
  policy_state_bundle_hash TEXT,
  policy_state_applied_ms  INTEGER,
  UNIQUE(device_pub, seq)            -- idempotency key (the roadmap's "(signer, chain_index)")
);

-- Minimized per-action rollup (one row per envelope action line). NO decision column (policy stays
-- on-device).
CREATE TABLE IF NOT EXISTS actions (
  envelope_id INTEGER NOT NULL REFERENCES envelopes(id),
  action      TEXT    NOT NULL,
  count       INTEGER NOT NULL,
  failures    INTEGER NOT NULL,
  destructive INTEGER NOT NULL
);

-- Pseudonymous operators only — NO names, ever.
CREATE TABLE IF NOT EXISTS operators (
  envelope_id INTEGER NOT NULL REFERENCES envelopes(id),
  op_ref      TEXT    NOT NULL,
  actions     INTEGER NOT NULL
);

-- Append-only liveness log: the device-signed claim + server-observed time (the timestamp anchor).
CREATE TABLE IF NOT EXISTS heartbeats (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  device_pub   TEXT    NOT NULL,
  seq_seen     INTEGER NOT NULL,
  ts_ms        INTEGER NOT NULL,
  received_ms  INTEGER NOT NULL,
  signed_bytes BLOB    NOT NULL,
  signature    TEXT    NOT NULL
);

-- Derived coverage view (upserted on ingest + heartbeat).
CREATE TABLE IF NOT EXISTS devices (
  device_pub    TEXT PRIMARY KEY,
  org_id        TEXT,
  business_unit TEXT,
  last_seq      INTEGER,
  max_seq_seen  INTEGER,
  last_seen_ms  INTEGER,

  -- doc 22 §7 device-inventory beacon (P1) — ALL NULLABLE so old rows (pre-P1 devices, or ones that
  -- haven't beaconed yet) keep upserting/serving exactly as before (BC-4). `info_signed_bytes` is the
  -- RAW bytes verbatim (BC-5: re-verification must run on received bytes, never a reconstruction);
  -- everything else is a parsed convenience column for querying/filtering. NEVER a source-IP column —
  -- doc 22 §7's GDPR exclusion table forbids persisting it (kriyad sees it at the transport layer only).
  info_signed_bytes        BLOB,
  info_signature            TEXT,
  info_collected_ms         INTEGER,
  console_version           TEXT,
  runtime_version            TEXT,
  verify_crate_version       TEXT,
  os_platform                TEXT,
  os_version                 TEXT,
  os_arch                    TEXT,
  policy_applied_version     INTEGER,
  policy_bundle_hash         TEXT,
  outbox_pending             INTEGER,
  enrolled_ms                INTEGER,
  device_label               TEXT,
  agents_json                TEXT
);

CREATE INDEX IF NOT EXISTS idx_env_device_seq ON envelopes(device_pub, seq);
CREATE INDEX IF NOT EXISTS idx_env_org        ON envelopes(org_id);

-- P3 (doc 22 §5): the org-policy-key-signed bundles an operator publishes. Append-only; `version` is
-- UNIQUE (the monotonic anti-rollback key devices independently enforce again on their own side).
-- `signed_bytes` is the EXACT bytes kriyad verified on ingest, stored verbatim for trustless read-back
-- (GET /v1/policy serves this raw, never a re-render) — kriyad authors nothing (doc 22 §3): it verifies
-- against the pinned org-policy.pub and stores/serves, it never constructs or modifies a bundle.
CREATE TABLE IF NOT EXISTS policy_bundles (
  version            INTEGER NOT NULL UNIQUE,
  org_id             TEXT    NOT NULL,
  issued_ms          INTEGER NOT NULL,
  expires_ms         INTEGER,
  scope_json         TEXT    NOT NULL,
  envelope_verbosity TEXT    NOT NULL,
  signed_bytes       BLOB    NOT NULL,
  signature          TEXT    NOT NULL,
  received_ms        INTEGER NOT NULL
);
"#;

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        conn.execute_batch(MIGRATIONS)
            .map_err(|e| format!("migrate: {e}"))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        conn.execute_batch(MIGRATIONS)
            .map_err(|e| format!("migrate: {e}"))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The single-tenant box serializes DB access behind one mutex (verification, not the DB, is the
    /// bottleneck). Poisoning is recovered — a panic mid-statement shouldn't wedge the server.
    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert one ALREADY-VERIFIED signed envelope. Gap-tolerant + idempotent on `(device_pub, seq)`
    /// (`INSERT OR IGNORE` → a duplicate is a no-op, never an error); out-of-order/missing seqs are a
    /// coverage gap, not a rejection. Extracts the `actions` + `operators` rollups and upserts the
    /// device coverage row, all in one transaction. `raw_line` is stored verbatim for trustless
    /// read-back (the exact bytes the device signed).
    pub fn insert_envelope(
        &self,
        signed: &SignedEnvelope,
        raw_line: &[u8],
        received_ms: u64,
    ) -> Result<Ingest, String> {
        let e = &signed.envelope;
        let (policy_version, policy_bundle_hash, policy_applied_ms) = match &e.policy_state {
            Some(p) => (Some(p.version as i64), Some(p.bundle_hash.clone()), Some(p.applied_ms as i64)),
            None => (None, None, None),
        };
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|x| x.to_string())?;

        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO envelopes \
                 (device_pub,seq,prev_hash,org_id,business_unit,window_from,window_to,merkle_root,\
                  receipts,verified,failed,destructive,non_egress,non_egress_proof,signed_bytes,\
                  signature,received_ms,policy_state_version,policy_state_bundle_hash,\
                  policy_state_applied_ms) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                params![
                    e.device_pub,
                    e.seq,
                    e.prev_envelope_hash,
                    e.org_id,
                    e.business_unit,
                    e.window.from_ms,
                    e.window.to_ms,
                    e.integrity.merkle_root,
                    e.counts.receipts,
                    e.counts.verified,
                    e.counts.failed,
                    e.counts.destructive,
                    e.non_egress.attested as i64,
                    e.non_egress.proof_digest,
                    raw_line,
                    signed.signature,
                    received_ms,
                    policy_version,
                    policy_bundle_hash,
                    policy_applied_ms,
                ],
            )
            .map_err(|x| x.to_string())?;
        if changed == 0 {
            return Ok(Ingest::Duplicate);
        }
        let envelope_id = tx.last_insert_rowid();
        for a in &e.actions {
            tx.execute(
                "INSERT INTO actions (envelope_id,action,count,failures,destructive) \
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    envelope_id,
                    a.action,
                    a.count,
                    a.failures,
                    a.destructive as i64
                ],
            )
            .map_err(|x| x.to_string())?;
        }
        for o in &e.operators {
            tx.execute(
                "INSERT INTO operators (envelope_id,op_ref,actions) VALUES (?1,?2,?3)",
                params![envelope_id, o.op_ref, o.actions],
            )
            .map_err(|x| x.to_string())?;
        }
        tx.execute(
            "INSERT INTO devices (device_pub,org_id,business_unit,last_seq,max_seq_seen,last_seen_ms) \
             VALUES (?1,?2,?3,?4,COALESCE((SELECT max_seq_seen FROM devices WHERE device_pub=?1),0),?5) \
             ON CONFLICT(device_pub) DO UPDATE SET \
               org_id=excluded.org_id, business_unit=excluded.business_unit, \
               last_seq=MAX(COALESCE(last_seq,0), excluded.last_seq), \
               last_seen_ms=excluded.last_seen_ms",
            params![e.device_pub, e.org_id, e.business_unit, e.seq, received_ms],
        )
        .map_err(|x| x.to_string())?;

        tx.commit().map_err(|x| x.to_string())?;
        Ok(Ingest::Accepted)
    }

    /// Upsert one ALREADY-VERIFIED signed DeviceInfo beacon (doc 22 §7, P1) into the `devices` row —
    /// creating the row if this is the FIRST beacon kriyad has ever seen from this `device_pub` (mirrors
    /// `insert_envelope`/`insert_heartbeat`'s own upsert convention: a never-before-seen device gets a
    /// row created, never rejected). `raw_line` is the EXACT bytes the device signed, stored verbatim in
    /// `info_signed_bytes` for future re-verification/read-back (BC-5) — everything else here is a
    /// parsed convenience column threaded onto the SAME row `insert_envelope`/`insert_heartbeat` already
    /// maintain, never persisting a source/peer IP (doc 22 §7's GDPR exclusion table).
    pub fn insert_device_info(
        &self,
        signed: &SignedDeviceInfo,
        raw_line: &[u8],
        received_ms: u64,
    ) -> Result<(), String> {
        let info = &signed.info;
        let (policy_applied_version, policy_bundle_hash) = match &info.policy {
            Some(p) => (Some(p.applied_version as i64), Some(p.bundle_hash.clone())),
            None => (None, None),
        };
        let agents_json = serde_json::to_string(&info.agents).map_err(|e| e.to_string())?;
        let conn = self.lock();
        conn.execute(
            "INSERT INTO devices \
             (device_pub,last_seq,max_seq_seen,last_seen_ms,info_signed_bytes,info_signature,\
              info_collected_ms,console_version,runtime_version,verify_crate_version,os_platform,\
              os_version,os_arch,policy_applied_version,policy_bundle_hash,outbox_pending,enrolled_ms,\
              device_label,agents_json) \
             VALUES (?1,COALESCE((SELECT last_seq FROM devices WHERE device_pub=?1),0),\
                     COALESCE((SELECT max_seq_seen FROM devices WHERE device_pub=?1),0),?2,\
                     ?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17) \
             ON CONFLICT(device_pub) DO UPDATE SET \
               last_seen_ms=MAX(COALESCE(last_seen_ms,0), excluded.last_seen_ms), \
               info_signed_bytes=excluded.info_signed_bytes, \
               info_signature=excluded.info_signature, \
               info_collected_ms=excluded.info_collected_ms, \
               console_version=excluded.console_version, \
               runtime_version=excluded.runtime_version, \
               verify_crate_version=excluded.verify_crate_version, \
               os_platform=excluded.os_platform, \
               os_version=excluded.os_version, \
               os_arch=excluded.os_arch, \
               policy_applied_version=excluded.policy_applied_version, \
               policy_bundle_hash=excluded.policy_bundle_hash, \
               outbox_pending=excluded.outbox_pending, \
               enrolled_ms=excluded.enrolled_ms, \
               device_label=excluded.device_label, \
               agents_json=excluded.agents_json",
            params![
                signed.device_pub,
                received_ms,
                raw_line,
                signed.signature,
                signed.collected_ms,
                info.console_version,
                info.runtime_version,
                info.verify_crate_version,
                info.os.platform,
                info.os.version,
                info.os.arch,
                policy_applied_version,
                policy_bundle_hash,
                info.outbox_pending as i64,
                info.enrolled_ms as i64,
                info.device_label,
                agents_json,
            ],
        )
        .map_err(|x| x.to_string())?;
        Ok(())
    }

    /// Insert one ALREADY-VERIFIED signed `PolicyBundle` (P3, doc 22 §5). `version` is UNIQUE:
    /// - a version never seen before → inserted, `Accepted`.
    /// - a version already stored with the IDENTICAL raw bytes (an operator's retried publish, e.g.
    ///   after a network blip) → a safe no-op, `DuplicateSameContent`.
    /// - a version already stored with DIFFERENT bytes → a loud `Err` (never a silent overwrite and
    ///   never conflated with the duplicate case — the operator must bump the version, matching the
    ///   anti-rollback contract devices enforce independently on their own side).
    ///
    /// `raw_line` is the EXACT bytes kriyad verified on ingest, stored verbatim so `GET /v1/policy` can
    /// serve trustless read-back — kriyad authors nothing (doc 22 §3): it never constructs/reformats a
    /// bundle, only verifies, stores, and serves the bytes as received.
    pub fn insert_policy_bundle(
        &self,
        signed: &SignedPolicyBundle,
        raw_line: &[u8],
        received_ms: u64,
    ) -> Result<PolicyIngest, String> {
        let b = &signed.bundle;
        let scope_json = serde_json::to_string(&b.scope).map_err(|e| e.to_string())?;
        let conn = self.lock();

        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT signed_bytes FROM policy_bundles WHERE version=?1",
                params![b.version as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(existing_bytes) = existing {
            return if existing_bytes == raw_line {
                Ok(PolicyIngest::DuplicateSameContent)
            } else {
                Err(format!(
                    "version {} was already published with DIFFERENT content — versions must be \
                     strictly increasing; bump the version to publish a change",
                    b.version
                ))
            };
        }

        conn.execute(
            "INSERT INTO policy_bundles \
             (version,org_id,issued_ms,expires_ms,scope_json,envelope_verbosity,signed_bytes,\
              signature,received_ms) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                b.version as i64,
                b.org_id,
                b.issued_ms as i64,
                b.expires_ms.map(|v| v as i64),
                scope_json,
                b.envelope_verbosity,
                raw_line,
                signed.signature,
                received_ms as i64,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(PolicyIngest::Accepted)
    }

    /// Serve the LATEST version in scope for a device (P3) — the exact stored signed bytes, verbatim
    /// (trustless: the device re-verifies the signature itself; this is serving, never deciding).
    /// Scans versions newest-first and returns the first whose `scope` covers this
    /// `(device_pub, business_unit)` pair; `None` when no published bundle covers this device (the
    /// route layer turns that into a 404, indistinguishable from — and handled identically to — an
    /// old kriyad that lacks the route at all: either way there is nothing to apply this cycle).
    pub fn latest_policy_bundle(&self, device_pub: &str, business_unit: Option<&str>) -> Option<String> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT scope_json, signed_bytes FROM policy_bundles ORDER BY version DESC")
            .ok()?;
        let mut rows = stmt.query([]).ok()?;
        while let Ok(Some(row)) = rows.next() {
            let scope_json: String = row.get(0).ok()?;
            let bytes: Vec<u8> = row.get(1).ok()?;
            let scope: PolicyScope = match serde_json::from_str(&scope_json) {
                Ok(s) => s,
                Err(_) => continue, // a corrupt scope row is skipped, never a 500
            };
            if scope.covers(device_pub, business_unit) {
                return Some(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
        None
    }

    /// Append one ALREADY-VERIFIED signed heartbeat (liveness log) and update the device's
    /// `max_seq_seen` + `last_seen_ms` (the coverage anchor).
    pub fn insert_heartbeat(
        &self,
        signed: &SignedHeartbeat,
        raw_line: &[u8],
        received_ms: u64,
    ) -> Result<(), String> {
        let h = &signed.heartbeat;
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|x| x.to_string())?;
        tx.execute(
            "INSERT INTO heartbeats (device_pub,seq_seen,ts_ms,received_ms,signed_bytes,signature) \
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![h.device_pub, h.seq_seen, h.ts_ms, received_ms, raw_line, signed.signature],
        )
        .map_err(|x| x.to_string())?;
        tx.execute(
            "INSERT INTO devices (device_pub,last_seq,max_seq_seen,last_seen_ms) \
             VALUES (?1,COALESCE((SELECT last_seq FROM devices WHERE device_pub=?1),0),?2,?3) \
             ON CONFLICT(device_pub) DO UPDATE SET \
               max_seq_seen=MAX(COALESCE(max_seq_seen,0), excluded.max_seq_seen), \
               last_seen_ms=excluded.last_seen_ms",
            params![h.device_pub, h.seq_seen, received_ms],
        )
        .map_err(|x| x.to_string())?;
        tx.commit().map_err(|x| x.to_string())?;
        Ok(())
    }

    /// Per-device coverage (2.8). `status` = `silent` if `now − last_seen_ms > silent_after_ms`,
    /// `behind` if a heartbeat claims a higher seq than is stored, else `current`. A gap is always a
    /// visible cell, never a silent hole (subject to invariant 6b: a never-covered source is invisible).
    pub fn coverage(
        &self,
        now_ms: u64,
        silent_after_ms: u64,
        org_filter: Option<&str>,
    ) -> Vec<DeviceCoverage> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT device_pub, org_id, business_unit, COALESCE(last_seq,0), \
                 COALESCE(max_seq_seen,0), COALESCE(last_seen_ms,0), \
                 console_version, runtime_version, verify_crate_version, os_platform, os_version, \
                 os_arch, policy_applied_version, policy_bundle_hash, outbox_pending, enrolled_ms, \
                 device_label, agents_json, info_collected_ms \
                 FROM devices ORDER BY device_pub",
            )
            .expect("prepare coverage");
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Option<String>>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    r.get::<_, Option<i64>>(12)?,
                    r.get::<_, Option<String>>(13)?,
                    r.get::<_, Option<i64>>(14)?,
                    r.get::<_, Option<i64>>(15)?,
                    r.get::<_, Option<String>>(16)?,
                    r.get::<_, Option<String>>(17)?,
                    r.get::<_, Option<i64>>(18)?,
                ))
            })
            .expect("query coverage");
        rows.filter_map(Result::ok)
            .filter(|(_, org, ..)| org_filter.map_or(true, |o| org.as_deref() == Some(o)))
            .map(
                |(
                    device_pub,
                    org_id,
                    business_unit,
                    last_seq,
                    max_seq_seen,
                    last_seen_ms,
                    console_version,
                    runtime_version,
                    verify_crate_version,
                    os_platform,
                    os_version,
                    os_arch,
                    policy_applied_version,
                    policy_bundle_hash,
                    outbox_pending,
                    enrolled_ms,
                    device_label,
                    agents_json,
                    info_collected_ms,
                )| {
                    let status = if now_ms.saturating_sub(last_seen_ms as u64) > silent_after_ms {
                        "silent"
                    } else if max_seq_seen > last_seq {
                        "behind"
                    } else {
                        "current"
                    };
                    let agents = agents_json
                        .as_deref()
                        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
                    DeviceCoverage {
                        device_pub,
                        org_id,
                        business_unit,
                        last_seq,
                        max_seq_seen,
                        last_seen_ms,
                        status: status.into(),
                        console_version,
                        runtime_version,
                        verify_crate_version,
                        os_platform,
                        os_version,
                        os_arch,
                        policy_applied_version,
                        policy_bundle_hash,
                        outbox_pending,
                        enrolled_ms,
                        device_label,
                        agents,
                        info_collected_ms,
                    }
                },
            )
            .collect()
    }

    /// Trustless read-back (2.9): the EXACT stored signed bytes for a contiguous `from_seq..=to_seq`
    /// slice (no re-render) + the device's most-recent signed heartbeat (the tail anchor). The caller
    /// re-runs the offline verifier on these bytes and asserts `returned_top_seq >= heartbeat.seq_seen`.
    ///
    /// DoS hardening (doc 22 §11): capped at `READ_BACK_ROW_CAP` rows regardless of the requested
    /// window width — this is the data-layer backstop (defense in depth) behind the route-layer 400
    /// in `get_verify`. A caller asking for a window wider than the cap (including a legacy caller
    /// that sent no range at all, i.e. `0..=u64::MAX`) gets the first `READ_BACK_ROW_CAP` envelopes
    /// in the window, not an error — additive/backward-compatible (BC-4).
    pub fn read_back(&self, device_pub: &str, from_seq: u64, to_seq: u64) -> Readback {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT signed_bytes FROM envelopes WHERE device_pub=?1 AND seq>=?2 AND seq<=?3 \
                 ORDER BY seq LIMIT ?4",
            )
            .expect("prepare read_back");
        let clamp = |s: u64| s.min(i64::MAX as u64) as i64;
        let envelopes = stmt
            .query_map(
                params![device_pub, clamp(from_seq), clamp(to_seq), READ_BACK_ROW_CAP],
                |r| {
                    let b: Vec<u8> = r.get(0)?;
                    Ok(String::from_utf8_lossy(&b).into_owned())
                },
            )
            .expect("query read_back")
            .filter_map(Result::ok)
            .collect();
        let heartbeat = conn
            .query_row(
                "SELECT signed_bytes FROM heartbeats WHERE device_pub=?1 ORDER BY id DESC LIMIT 1",
                params![device_pub],
                |r| {
                    let b: Vec<u8> = r.get(0)?;
                    Ok(String::from_utf8_lossy(&b).into_owned())
                },
            )
            .optional()
            .unwrap_or(None);
        Readback {
            envelopes,
            heartbeat,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_creates_the_five_tables() {
        let store = Store::open_in_memory().unwrap();
        let conn = store.lock();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for t in ["actions", "devices", "envelopes", "heartbeats", "operators"] {
            assert!(
                tables.contains(&t.to_string()),
                "missing table {t}: {tables:?}"
            );
        }
    }

    #[test]
    fn unique_device_seq_is_enforced() {
        let store = Store::open_in_memory().unwrap();
        let conn = store.lock();
        let insert = "INSERT INTO envelopes \
            (device_pub,seq,org_id,window_from,window_to,merkle_root,receipts,verified,failed,\
             destructive,non_egress,signed_bytes,signature,received_ms) \
            VALUES ('ab',1,'o',0,1,'r',0,0,0,0,0,x'00','s',0)";
        conn.execute(insert, []).unwrap();
        assert!(
            conn.execute(insert, []).is_err(),
            "UNIQUE(device_pub, seq) must reject a duplicate"
        );
    }

    #[test]
    fn ingest_is_idempotent_and_extracts_rollups() {
        let store = Store::open_in_memory().unwrap();
        // A real Rust-signed envelope (the parity fixture); ingest trusts the caller already verified.
        let fixture = include_str!("../../../../src/sample/sample-envelope.json");
        let signed: SignedEnvelope =
            serde_json::from_value(serde_json::from_str(fixture).unwrap()).unwrap();
        let line = serde_json::to_string(&signed).unwrap();

        assert_eq!(
            store
                .insert_envelope(&signed, line.as_bytes(), 1000)
                .unwrap(),
            Ingest::Accepted
        );
        // Idempotent on (device_pub, seq) — a re-post is a no-op, not an error or a second row.
        assert_eq!(
            store
                .insert_envelope(&signed, line.as_bytes(), 1001)
                .unwrap(),
            Ingest::Duplicate
        );

        let conn = store.lock();
        let count = |t: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count("envelopes"), 1, "duplicate inserted no second row");
        assert_eq!(count("actions") as usize, signed.envelope.actions.len());
        assert_eq!(count("operators") as usize, signed.envelope.operators.len());
        let last_seq: i64 = conn
            .query_row(
                "SELECT last_seq FROM devices WHERE device_pub=?1",
                [&signed.envelope.device_pub],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last_seq as u64, signed.envelope.seq, "coverage upserted");
    }

    /// Envelope v1.1 (P3, doc 22 §5): a pre-P3 envelope (no `policy_state`) stores NULL in the new
    /// columns (BC-4 — additive, never a fabricated value); a v1.1 envelope WITH `policy_state`
    /// populates them. Two separate stores (the two fixtures share the same fixed signing key/seq, so
    /// inserting both into one store would collide on `UNIQUE(device_pub, seq)` — irrelevant to what
    /// this test actually checks: what each shape stores).
    #[test]
    fn policy_state_columns_are_null_for_v1_0_and_populated_for_v1_1() {
        let v1_0_store = Store::open_in_memory().unwrap();
        let v1_0_fixture = include_str!("../../../../src/sample/sample-envelope.json");
        let v1_0: SignedEnvelope =
            serde_json::from_value(serde_json::from_str(v1_0_fixture).unwrap()).unwrap();
        assert!(v1_0.envelope.policy_state.is_none(), "the v1.0 fixture must genuinely lack it");
        v1_0_store
            .insert_envelope(&v1_0, v1_0_fixture.as_bytes(), 1000)
            .unwrap();
        let (v1_0_version, v1_0_hash): (Option<i64>, Option<String>) = v1_0_store
            .lock()
            .query_row(
                "SELECT policy_state_version, policy_state_bundle_hash FROM envelopes WHERE device_pub=?1",
                [&v1_0.envelope.device_pub],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(v1_0_version, None, "pre-P3 envelope must store NULL, never a fabricated value");
        assert_eq!(v1_0_hash, None);

        let v1_1_store = Store::open_in_memory().unwrap();
        let v1_1_fixture = include_str!("../../../../src/sample/sample-envelope-v1.1.json");
        let v1_1: SignedEnvelope =
            serde_json::from_value(serde_json::from_str(v1_1_fixture).unwrap()).unwrap();
        assert!(v1_1.envelope.policy_state.is_some(), "the v1.1 fixture must genuinely carry it");
        v1_1_store
            .insert_envelope(&v1_1, v1_1_fixture.as_bytes(), 2000)
            .unwrap();
        let (v1_1_version, v1_1_hash, v1_1_applied_ms): (Option<i64>, Option<String>, Option<i64>) =
            v1_1_store
                .lock()
                .query_row(
                    "SELECT policy_state_version, policy_state_bundle_hash, policy_state_applied_ms \
                     FROM envelopes WHERE device_pub=?1",
                    [&v1_1.envelope.device_pub],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
        assert_eq!(v1_1_version, Some(13));
        assert_eq!(v1_1_hash, Some("deadbeefcafef00d".to_string()));
        assert_eq!(v1_1_applied_ms, Some(1_783_500_000_000));
    }

    #[test]
    fn heartbeat_updates_coverage() {
        use kriya_verify::{Heartbeat, SignedHeartbeat};
        let store = Store::open_in_memory().unwrap();
        let hb = SignedHeartbeat {
            heartbeat: Heartbeat {
                device_pub: "ab12".into(),
                seq_seen: 7,
                ts_ms: 1,
            },
            public_key: "ab12".into(),
            signature: "00".into(),
        };
        store.insert_heartbeat(&hb, b"raw", 5000).unwrap();
        let conn = store.lock();
        let (max_seq, last_seen): (i64, i64) = conn
            .query_row(
                "SELECT max_seq_seen, last_seen_ms FROM devices WHERE device_pub='ab12'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(max_seq, 7, "heartbeat anchors max_seq_seen");
        assert_eq!(last_seen, 5000);
    }

    fn sample() -> SignedEnvelope {
        serde_json::from_value(
            serde_json::from_str(include_str!("../../../../src/sample/sample-envelope.json"))
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn coverage_status_transitions() {
        use kriya_verify::{Heartbeat, SignedHeartbeat};
        let store = Store::open_in_memory().unwrap();
        let signed = sample();
        let dev = signed.envelope.device_pub.clone();
        let line = serde_json::to_string(&signed).unwrap();
        store
            .insert_envelope(&signed, line.as_bytes(), 100_000)
            .unwrap();

        let cov = store.coverage(100_000, 10_800_000, None);
        assert_eq!(cov.len(), 1);
        assert_eq!(cov[0].status, "current", "fresh + caught up");

        // A heartbeat claims a higher seq than is stored → behind.
        let hb = SignedHeartbeat {
            heartbeat: Heartbeat {
                device_pub: dev.clone(),
                seq_seen: 5,
                ts_ms: 1,
            },
            public_key: dev.clone(),
            signature: "0".into(),
        };
        store.insert_heartbeat(&hb, b"hb", 100_000).unwrap();
        let cov = store.coverage(100_000, 10_800_000, None);
        assert_eq!(cov[0].status, "behind");
        assert_eq!(cov[0].max_seq_seen, 5);

        // Far past the silence window → silent.
        let cov = store.coverage(100_000 + 20_000_000, 10_800_000, None);
        assert_eq!(cov[0].status, "silent");

        // org filter excludes other orgs.
        assert!(store
            .coverage(100_000, 10_800_000, Some("other-org"))
            .is_empty());
    }

    #[test]
    fn read_back_returns_exact_bytes_and_heartbeat() {
        use kriya_verify::{Heartbeat, SignedHeartbeat};
        let store = Store::open_in_memory().unwrap();
        let signed = sample();
        let dev = signed.envelope.device_pub.clone();
        let line = serde_json::to_string(&signed).unwrap();
        store.insert_envelope(&signed, line.as_bytes(), 1).unwrap();
        store
            .insert_heartbeat(
                &SignedHeartbeat {
                    heartbeat: Heartbeat {
                        device_pub: dev.clone(),
                        seq_seen: 1,
                        ts_ms: 1,
                    },
                    public_key: dev.clone(),
                    signature: "0".into(),
                },
                b"hbline",
                1,
            )
            .unwrap();

        let rb = store.read_back(&dev, 0, u64::MAX);
        assert_eq!(rb.envelopes.len(), 1);
        // The returned bytes are EXACTLY what was stored, and re-verify offline (trustless).
        assert_eq!(rb.envelopes[0], line);
        let v: serde_json::Value = serde_json::from_str(&rb.envelopes[0]).unwrap();
        assert!(
            kriya_verify::verify_envelope(&v).is_ok(),
            "read-back bytes must re-verify"
        );
        assert_eq!(rb.heartbeat.as_deref(), Some("hbline"));
    }

    // ── P3: policy_bundles (doc 22 §5) ─────────────────────────────────────────────────────────────

    fn signed_bundle(version: u64, scope: PolicyScope) -> SignedPolicyBundle {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[31u8; 32]);
        kriya_verify::sign_policy_bundle(
            &key,
            kriya_verify::PolicyBundle {
                org_id: "acme".into(),
                version,
                issued_ms: 1000 + version,
                expires_ms: None,
                scope,
                policy: serde_json::json!({ "rules": [] }),
                budgets: serde_json::json!({}),
                govern: vec![],
                envelope_verbosity: "standard".into(),
            },
        )
    }

    #[test]
    fn insert_policy_bundle_accepts_dedups_and_rejects_version_collisions() {
        let store = Store::open_in_memory().unwrap();
        let v1 = signed_bundle(1, PolicyScope::all());
        let line = serde_json::to_string(&v1).unwrap();

        assert_eq!(
            store.insert_policy_bundle(&v1, line.as_bytes(), 100).unwrap(),
            PolicyIngest::Accepted
        );
        // A retried publish of the IDENTICAL bytes is a safe no-op, not an error.
        assert_eq!(
            store.insert_policy_bundle(&v1, line.as_bytes(), 200).unwrap(),
            PolicyIngest::DuplicateSameContent
        );

        // A DIFFERENT bundle claiming the SAME version is a loud error — never a silent overwrite.
        let v1_different = signed_bundle(1, PolicyScope { business_unit: Some("bu-2".into()), device_pubs: None });
        let different_line = serde_json::to_string(&v1_different).unwrap();
        let err = store
            .insert_policy_bundle(&v1_different, different_line.as_bytes(), 300)
            .unwrap_err();
        assert!(err.contains("already published"), "{err}");

        let conn = store.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM policy_bundles", [], |r| r.get(0))
            .unwrap();
        drop(conn);
        assert_eq!(count, 1, "the rejected collision must not create a second row");
    }

    #[test]
    fn latest_policy_bundle_serves_newest_in_scope_version() {
        let store = Store::open_in_memory().unwrap();
        let v1 = signed_bundle(1, PolicyScope::all());
        let v2 = signed_bundle(2, PolicyScope::all());
        store
            .insert_policy_bundle(&v1, serde_json::to_string(&v1).unwrap().as_bytes(), 100)
            .unwrap();
        store
            .insert_policy_bundle(&v2, serde_json::to_string(&v2).unwrap().as_bytes(), 200)
            .unwrap();

        let served = store.latest_policy_bundle("any-device", None).expect("a bundle in scope");
        let parsed: serde_json::Value = serde_json::from_str(&served).unwrap();
        assert_eq!(parsed["bundle"]["version"], 2, "the newest version wins");
    }

    #[test]
    fn latest_policy_bundle_scope_filters_by_business_unit_and_device_pub() {
        let store = Store::open_in_memory().unwrap();
        let bu_scoped = signed_bundle(
            1,
            PolicyScope { business_unit: Some("enclave-7".into()), device_pubs: None },
        );
        store
            .insert_policy_bundle(&bu_scoped, serde_json::to_string(&bu_scoped).unwrap().as_bytes(), 100)
            .unwrap();

        assert!(
            store.latest_policy_bundle("devA", Some("enclave-7")).is_some(),
            "a device in the scoped BU is served"
        );
        assert!(
            store.latest_policy_bundle("devA", Some("other-bu")).is_none(),
            "a device in a different BU is NOT served — scope filtering is serving, not deciding, but \
             still narrows what's handed out"
        );
        assert!(
            store.latest_policy_bundle("devA", None).is_none(),
            "a device with no configured BU doesn't match a BU-scoped bundle"
        );

        // A device-list-scoped bundle at a higher version, restricted to one device.
        let device_scoped = signed_bundle(
            2,
            PolicyScope { business_unit: None, device_pubs: Some(vec!["devB".into()]) },
        );
        store
            .insert_policy_bundle(&device_scoped, serde_json::to_string(&device_scoped).unwrap().as_bytes(), 200)
            .unwrap();

        // devB is covered by v2 (device-scoped) — the newest version in ITS scope.
        let served = store.latest_policy_bundle("devB", None).expect("devB is explicitly scoped");
        let parsed: serde_json::Value = serde_json::from_str(&served).unwrap();
        assert_eq!(parsed["bundle"]["version"], 2);

        // devA is still only covered by the BU-scoped v1 (v2 doesn't cover it) — falls through to v1.
        let served = store.latest_policy_bundle("devA", Some("enclave-7")).expect("devA covered by v1");
        let parsed: serde_json::Value = serde_json::from_str(&served).unwrap();
        assert_eq!(parsed["bundle"]["version"], 1);
    }

    #[test]
    fn latest_policy_bundle_is_none_when_nothing_published() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.latest_policy_bundle("devA", None).is_none());
    }
}
