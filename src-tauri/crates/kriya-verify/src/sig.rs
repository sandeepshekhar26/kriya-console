//! The raw Ed25519 signature check, factored out of receipt/license/envelope verification (0.3).
//!
//! `verify_detached` abstracts ONLY the key/sig decode + `vk.verify(msg, sig)` step. The canonical
//! **message** construction stays at each call site — receipts sign `CanonicalReceipt` bytes, licenses
//! sign `canonical_license_bytes`, envelopes sign their own canonical bytes; those are deliberately
//! different and must NOT be unified here.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify a detached Ed25519 signature: decode the lowercase-hex public key (32 bytes) and signature
/// (64 bytes) and check `sig` over `msg`. `Ok(())` ⇒ authentic; `Err(reason)` ⇒ malformed inputs or a
/// signature that does not match. The caller supplies the already-canonicalized `msg`.
pub fn verify_detached(pubkey_hex: &str, sig_hex: &str, msg: &[u8]) -> Result<(), String> {
    let pub_bytes = decode_fixed::<32>(pubkey_hex).ok_or("public_key must be 32 bytes of hex")?;
    let sig_bytes = decode_fixed::<64>(sig_hex).ok_or("signature must be 64 bytes of hex")?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| format!("bad public key: {e}"))?;
    vk.verify(msg, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| "signature does not match".to_string())
}

/// Decode lowercase hex into a fixed-size byte array, or `None` on bad hex / wrong length.
pub(crate) fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex::decode(s).ok()?.try_into().ok()
}
