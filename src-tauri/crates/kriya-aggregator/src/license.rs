//! Offline `control-plane` license gate (2.2) — kriyad refuses to start ingest without a valid license
//! that grants the `control-plane` feature. Verified entirely offline against the pinned issuer key
//! (`kriya_verify::verify_token`), exactly like the device: no checkout call, no phone-home. Reuses the
//! SAME verifier the Console + device link.

use std::path::Path;

use kriya_verify::{verify_token, LicenseToken};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `Ok(())` only when `license_path` holds a valid, unexpired license granting the `control-plane`
/// feature. `Err(reason)` otherwise — kriyad logs it and refuses to serve ingest.
pub fn gate(license_path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(license_path)
        .map_err(|e| format!("no license at {}: {e}", license_path.display()))?;
    let token: LicenseToken =
        serde_json::from_str(&text).map_err(|e| format!("malformed license: {e}"))?;
    let payload = verify_token(&token, now_ms())?;
    if !payload.features.iter().any(|f| f == "control-plane") {
        return Err("license does not grant the `control-plane` feature".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("kriyad-lic-{}-{name}", std::process::id()));
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }

    #[test]
    fn accepts_control_plane_rejects_missing_and_wrong_feature() {
        // A real control-plane license verifies against the pinned issuer key (seed-independent).
        let cp = include_str!("../fixtures/dev-control-plane-license.json");
        let cp_path = write_tmp("cp.json", cp.as_bytes());
        assert!(
            gate(&cp_path).is_ok(),
            "a control-plane license is accepted"
        );

        // The receipt-side fixture is a valid license WITHOUT the control-plane feature → rejected.
        let plain = include_str!("../../kriya-verify/fixtures/dev-license.json");
        let plain_path = write_tmp("plain.json", plain.as_bytes());
        let err = gate(&plain_path).unwrap_err();
        assert!(
            err.contains("control-plane"),
            "wrong-feature license rejected: {err}"
        );

        // No file → refused.
        assert!(gate(std::path::Path::new("/nonexistent/kriyad-license.json")).is_err());

        let _ = std::fs::remove_file(&cp_path);
        let _ = std::fs::remove_file(&plain_path);
    }
}
