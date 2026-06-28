//! The signed liveness heartbeat (1.17) — `{device_pub, seq_seen, ts_ms}` signed by the device
//! evidence key. The device posts one on a fixed interval regardless of activity, so a silent device
//! shows up as a stale `last_seen` (a visible coverage gap, not a hole) and `seq_seen` is the
//! tail-truncation anchor for the trustless read-back (`/v1/verify`, 2.9/2.10). Verified by the server
//! (2.6) and the auditor with the SAME shared code that verifies envelopes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::canonical_json_bytes;
use crate::sig::verify_detached;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// The device evidence key (== signing `public_key`).
    pub device_pub: String,
    /// The highest envelope `seq` the device has produced — the tail-truncation anchor.
    pub seq_seen: u64,
    /// Device-claimed wall-clock (ms since epoch).
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeartbeat {
    pub heartbeat: Heartbeat,
    pub public_key: String,
    pub signature: String,
}

/// Canonical signed bytes of a heartbeat = compact JSON of its recursively key-sorted value.
pub fn heartbeat_canonical_bytes(h: &Heartbeat) -> Vec<u8> {
    canonical_json_bytes(&serde_json::to_value(h).unwrap_or(Value::Null))
}

/// Verify a parsed `SignedHeartbeat`: `device_pub == public_key` and the Ed25519 signature over the
/// canonical heartbeat bytes. Used as the tail anchor the auditor compares against the read-back set.
pub fn verify_heartbeat(v: &Value) -> Result<(), String> {
    let s: SignedHeartbeat =
        serde_json::from_value(v.clone()).map_err(|e| format!("not a signed heartbeat: {e}"))?;
    if s.heartbeat.device_pub != s.public_key {
        return Err("device_pub does not match the signing public_key".into());
    }
    verify_detached(
        &s.public_key,
        &s.signature,
        &heartbeat_canonical_bytes(&s.heartbeat),
    )
    .map_err(|_| "heartbeat signature does not match".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signed_heartbeat_verifies_and_tamper_fails() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let hb = Heartbeat {
            device_pub: pk.clone(),
            seq_seen: 42,
            ts_ms: 1000,
        };
        let sig = hex::encode(key.sign(&heartbeat_canonical_bytes(&hb)).to_bytes());
        let signed = serde_json::to_value(SignedHeartbeat {
            heartbeat: hb,
            public_key: pk,
            signature: sig,
        })
        .unwrap();
        assert!(
            verify_heartbeat(&signed).is_ok(),
            "honest heartbeat verifies"
        );

        let mut tampered = signed.clone();
        tampered["heartbeat"]["seq_seen"] = serde_json::json!(99); // forge a higher anchor
        assert!(
            verify_heartbeat(&tampered).is_err(),
            "tampering seq_seen must fail"
        );
    }
}
