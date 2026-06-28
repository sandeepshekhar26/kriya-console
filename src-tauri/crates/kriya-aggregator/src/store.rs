//! The append-only SQLite store (2.3) — kriyad's entire state in one file. Stores ONLY signed metadata
//! (the minimized envelope bytes + extracted rollup columns), NEVER raw payloads — the envelopes are
//! redacted by construction. Backup = copy the file. Inserts/queries land with the endpoints (2.5–2.9).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use kriya_verify::{SignedEnvelope, SignedHeartbeat};
use rusqlite::{params, Connection};

pub struct Store {
    conn: Mutex<Connection>,
}

/// The outcome of ingesting one envelope (idempotent on `(device_pub, seq)`).
#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    Accepted,
    Duplicate,
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
}
