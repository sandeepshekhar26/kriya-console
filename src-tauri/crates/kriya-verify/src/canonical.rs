//! Canonical-JSON (R21) + the SHA-256 hashing primitive — shared by receipt, license, envelope, and
//! Merkle verification so every signed artifact is canonicalized the one same way.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Recursively sort object keys so serialization is deterministic regardless of any build's
/// serde_json `preserve_order` flag (R21). Arrays keep order (semantic); their object elements are
/// sorted; scalars pass through. Applied to receipt `params` before signing/verifying, so the
/// canonical bytes are reproducible by any verifier without depending on a build flag.
pub fn canonical_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical_value(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}

/// Lowercase-hex SHA-256 of `bytes` — the hash-chain link primitive (R20). Each receipt's `prev_hash`
/// equals the SHA-256 of the previous **line** on disk.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
