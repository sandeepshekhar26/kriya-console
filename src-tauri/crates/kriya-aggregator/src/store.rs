//! The append-only SQLite store (2.3) — kriyad's entire state in one file. Stores ONLY signed metadata
//! (the minimized envelope bytes + extracted rollup columns), NEVER raw payloads — the envelopes are
//! redacted by construction. Backup = copy the file. Inserts/queries land with the endpoints (2.5–2.9).

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

pub struct Store {
    conn: Mutex<Connection>,
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
}
