//! The append-only SQLite store (2.3) — kriyad's entire state in one file. Stores ONLY signed metadata
//! (the minimized envelope bytes + extracted rollup columns), NEVER raw payloads — the envelopes are
//! redacted by construction. Backup = copy the file. Inserts/queries land with the endpoints (2.5–2.9).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use kriya_verify::{SignedEnvelope, SignedHeartbeat};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

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

/// One device's coverage row (the derived liveness/completeness view).
#[derive(Debug, Serialize)]
pub struct DeviceCoverage {
    pub device_pub: String,
    pub org_id: Option<String>,
    pub business_unit: Option<String>,
    pub last_seq: i64,
    pub max_seq_seen: i64,
    pub last_seen_ms: i64,
    /// `current` · `behind` (a heartbeat claims a higher seq than is stored) · `silent` (stale).
    pub status: String,
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
  last_seen_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_env_device_seq ON envelopes(device_pub, seq);
CREATE INDEX IF NOT EXISTS idx_env_org        ON envelopes(org_id);
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
        let mut conn = self.lock();
        let tx = conn.transaction().map_err(|x| x.to_string())?;

        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO envelopes \
                 (device_pub,seq,prev_hash,org_id,business_unit,window_from,window_to,merkle_root,\
                  receipts,verified,failed,destructive,non_egress,non_egress_proof,signed_bytes,\
                  signature,received_ms) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
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
                 COALESCE(max_seq_seen,0), COALESCE(last_seen_ms,0) FROM devices ORDER BY device_pub",
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
                ))
            })
            .expect("query coverage");
        rows.filter_map(Result::ok)
            .filter(|(_, org, ..)| org_filter.map_or(true, |o| org.as_deref() == Some(o)))
            .map(
                |(device_pub, org_id, business_unit, last_seq, max_seq_seen, last_seen_ms)| {
                    let status = if now_ms.saturating_sub(last_seen_ms as u64) > silent_after_ms {
                        "silent"
                    } else if max_seq_seen > last_seq {
                        "behind"
                    } else {
                        "current"
                    };
                    DeviceCoverage {
                        device_pub,
                        org_id,
                        business_unit,
                        last_seq,
                        max_seq_seen,
                        last_seen_ms,
                        status: status.into(),
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
}
