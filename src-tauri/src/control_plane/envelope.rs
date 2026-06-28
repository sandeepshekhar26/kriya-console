//! Device control-plane secrets (1.8) + the envelope BUILDER (1.10).
//!
//! The **evidence key** (a stable Ed25519 identity, the device's fleet identity) SIGNS attestation
//! envelopes; its public half is `device_pub`. The **pepper** keys the operator-pseudonym HMAC, so the
//! server can dedup an operator WITHOUT ever seeing a plaintext name. Both live `0600` under
//! `~/.kriya/console/` and NEVER leave the device. (1.8 is the keys; the builder lands in 1.10.)

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

/// The device evidence signing key, persisted at `~/.kriya/console/evidence.key` (32-byte hex seed,
/// `0600`). Stable across runs — the `device_pub` an auditor pins stays the same deployment-to-deployment.
pub fn evidence_signing_key() -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&load_or_create_seed(
        &evidence_key_path(),
    )?))
}

/// The device's stable public identity (lowercase hex of the evidence verifying key) = `device_pub`.
pub fn evidence_public_hex() -> Result<String, String> {
    Ok(hex::encode(
        evidence_signing_key()?.verifying_key().to_bytes(),
    ))
}

/// The operator-pseudonym pepper (32 bytes), persisted `0600` at `~/.kriya/console/pepper`. Device-local
/// and never transmitted — so the server can dedup an operator via the HMAC pseudonym but can never
/// recover the plaintext name (the pseudonym map stays OFF the aggregator).
pub fn pepper() -> Result<Vec<u8>, String> {
    Ok(load_or_create_seed(&pepper_path())?.to_vec())
}

fn evidence_key_path() -> PathBuf {
    crate::audit::console_dir().join("evidence.key")
}
fn pepper_path() -> PathBuf {
    crate::audit::console_dir().join("pepper")
}

/// Load a 32-byte seed from `path` (lowercase hex), or generate one with the OS CSPRNG and persist it
/// (`0600` on unix; parents created). Mirrors the runtime host's durable-identity pattern. An
/// existing-but-invalid file is an ERROR, never overwritten — losing a device identity must be a
/// deliberate act, not a side effect of a typo'd path.
fn load_or_create_seed(path: &Path) -> Result<[u8; 32], String> {
    if path.exists() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let bytes = hex::decode(text.trim())
            .map_err(|e| format!("{} is not valid hex: {e}", path.display()))?;
        return bytes
            .try_into()
            .map_err(|_| format!("{} must be 32 bytes (64 hex chars)", path.display()));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("OS CSPRNG failed: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(path, hex::encode(seed))
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    restrict_perms(path);
    Ok(seed)
}

#[cfg(unix)]
fn restrict_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// `load_or_create_seed` is stable across reloads, `0600`, and refuses to overwrite a corrupt file.
    /// Tests the core directly with a temp path (no `$HOME` override → no cross-test races).
    #[test]
    fn seed_is_stable_persisted_0600_and_corrupt_is_an_error() {
        let dir = std::env::temp_dir().join(format!("kriya-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("evidence.key");

        let s1 = load_or_create_seed(&path).expect("mint seed");
        let s2 = load_or_create_seed(&path).expect("reload seed");
        assert_eq!(s1, s2, "seed must be stable across reloads");
        assert_eq!(s1.len(), 32);
        // The evidence key derived from a stable seed is a stable device_pub.
        assert_eq!(
            hex::encode(SigningKey::from_bytes(&s1).verifying_key().to_bytes()),
            hex::encode(SigningKey::from_bytes(&s2).verifying_key().to_bytes()),
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the seed file must be 0600");
        }

        std::fs::write(&path, "not-valid-hex").unwrap();
        assert!(
            load_or_create_seed(&path).is_err(),
            "a corrupt seed file must error, never be silently regenerated"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
