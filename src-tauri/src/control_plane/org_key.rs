//! The org policy key (P3, doc 22 §3/§5) — the customer-held Ed25519 keypair that signs `PolicyBundle`s.
//! **kriyad never holds it** — only the pinned public half ever leaves this machine (exported to
//! `org-policy.pub` for MDM/enrollment). Unlike the device evidence key (`envelope.rs`'s
//! `~/.kriya/console/evidence.key`, a plaintext 0600 file — a low-value, per-device identity), the org
//! key signs policy for the WHOLE fleet, so it gets the OS's real secret store (macOS Keychain /
//! Windows Credential Manager / Linux Secret Service) via the `keyring` crate, never a file on disk.
//!
//! This module is operator-side (`fleet-console`-gated), not device-side — it lives under
//! `control_plane` because it is still control-plane-only (build-time dormancy applies identically).

use ed25519_dalek::SigningKey;

const SERVICE: &str = "kriya-console-org-policy-key";
/// A fixed keyring "account" — one org key per operator machine, so there is exactly one credential to
/// find/rotate.
const ACCOUNT: &str = "org-policy-key";

/// Where the exported PUBLIC half lives for MDM/enrollment distribution.
pub fn org_policy_pub_path() -> std::path::PathBuf {
    crate::audit::console_dir().join("org-policy.pub")
}

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("opening OS keychain: {e}"))
}

/// Load the org policy signing key from the OS keychain, if one has been generated on this machine.
/// The secret is stored as lowercase hex of the 32-byte Ed25519 seed (`keyring`'s stable
/// `get_password`/`set_password` string API, rather than gambling on a binary-secret API that varies
/// across keyring backends/versions).
pub fn load_org_signing_key() -> Result<Option<SigningKey>, String> {
    let e = entry()?;
    match e.get_password() {
        Ok(hex_seed) => {
            let bytes = hex::decode(hex_seed.trim())
                .map_err(|e| format!("stored org key is not valid hex: {e}"))?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "stored org key must be 32 bytes".to_string())?;
            Ok(Some(SigningKey::from_bytes(&seed)))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("reading OS keychain: {e}")),
    }
}

#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OrgKeyInfo {
    pub org_policy_pub: String,
    pub pub_path: String,
    /// Whether this call minted a NEW key (`false` = an existing key was found and is being reported
    /// unchanged).
    pub generated: bool,
}

/// Generate the org policy key ONCE, persist its private half in the OS keychain, and export the
/// public half to `org-policy.pub` (for MDM/enrollment). Requires `fleet-console` — checked first.
///
/// **Idempotent-but-honest**: if a key already exists, this returns it UNCHANGED (`generated: false`)
/// rather than silently rotating — rotating would orphan every device already pinned to the old public
/// key. An operator who wants to rotate must remove the OS keychain entry first (an explicit,
/// out-of-band act), then call this again.
#[tauri::command]
pub fn org_policy_keygen() -> Result<OrgKeyInfo, String> {
    crate::license::require_fleet_console()?;

    if let Some(existing) = load_org_signing_key()? {
        let pub_hex = hex::encode(existing.verifying_key().to_bytes());
        write_pub_file(&pub_hex)?;
        return Ok(OrgKeyInfo {
            org_policy_pub: pub_hex,
            pub_path: org_policy_pub_path().to_string_lossy().into_owned(),
            generated: false,
        });
    }

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("OS CSPRNG failed: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    let pub_hex = hex::encode(key.verifying_key().to_bytes());

    entry()?
        .set_password(&hex::encode(seed))
        .map_err(|e| format!("writing OS keychain: {e}"))?;
    write_pub_file(&pub_hex)?;

    Ok(OrgKeyInfo {
        org_policy_pub: pub_hex,
        pub_path: org_policy_pub_path().to_string_lossy().into_owned(),
        generated: true,
    })
}

fn write_pub_file(pub_hex: &str) -> Result<(), String> {
    write_pub_file_to(&org_policy_pub_path(), pub_hex)
}

/// Path-injected core so this is testable without touching the process-global `$HOME` env var (which
/// every other `$HOME`-mutating test in this crate also races against) — mirrors `outbox.rs`'s
/// `append`/`append_to` split.
fn write_pub_file_to(path: &std::path::Path, pub_hex: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(path, format!("{pub_hex}\n"))
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Sign a `PolicyBundle` with the org key held in the OS keychain. `Err` if no key has been generated
/// yet (the cockpit's authoring flow calls [`org_policy_keygen`] first, or on first Sign & Publish).
pub fn sign_with_org_key(
    bundle: kriya_verify::PolicyBundle,
) -> Result<kriya_verify::SignedPolicyBundle, String> {
    let key = load_org_signing_key()?
        .ok_or("no org policy key has been generated yet — run org_policy_keygen first")?;
    Ok(kriya_verify::sign_policy_bundle(&key, bundle))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the OS-keychain-touching tests from racing each other AND from any real keychain entry a
    /// developer might have on their own machine — each test uses a distinct service name derived from
    /// the process/thread id, never the production [`SERVICE`] constant.
    fn scoped_entry(tag: &str) -> keyring::Entry {
        let service = format!(
            "kriya-console-org-policy-key-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        keyring::Entry::new(&service, ACCOUNT).expect("open a scoped keychain entry")
    }

    #[test]
    fn write_pub_file_round_trips() {
        // Path-injected — never touches the process-global `$HOME` env var, so this can't race any
        // other `$HOME`-mutating test in this crate (a real, previously-latent flakiness class: each
        // module's own `ENV_LOCK` only guards within that module, not across modules).
        let dir = std::env::temp_dir().join(format!(
            "kriya-orgkey-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("org-policy.pub");
        let key = SigningKey::from_bytes(&[77u8; 32]);
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        write_pub_file_to(&path, &pub_hex).unwrap();
        let read = std::fs::read_to_string(&path).unwrap();
        assert_eq!(read.trim(), pub_hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Exercises the actual OS keychain round-trip (skips gracefully in a sandboxed CI runner with no
    /// keychain/secret-service backend, rather than failing the whole suite on an environment gap).
    #[test]
    fn keychain_round_trips_a_seed() {
        let e = scoped_entry("roundtrip");
        let seed = [3u8; 32];
        if e.set_password(&hex::encode(seed)).is_err() {
            eprintln!("skip: no OS keychain/secret-service backend available in this environment");
            return;
        }
        let read = e.get_password().expect("read back the just-written secret");
        assert_eq!(hex::decode(read).unwrap(), seed.to_vec());
        let _ = e.delete_credential();
    }

    #[test]
    fn missing_entry_is_none_not_an_error() {
        let e = scoped_entry("missing");
        match e.get_password() {
            Err(keyring::Error::NoEntry) => {} // expected
            Ok(_) => panic!("a never-written scoped entry must not already exist"),
            Err(_) => {
                eprintln!("skip: no OS keychain/secret-service backend available in this environment");
            }
        }
    }
}
