//! `issue-license` — DEV/DEMO license minter (R29). **Not a shipped product surface.** It signs a
//! `pro` license with the dev issuer seed (the gitignored `dev-keys/issuer-dev-seed.hex`) so the
//! offline verify path can be exercised end-to-end on a dev machine and the demo can show paid
//! features unlocking. Production issuance is the deferred checkout → offline-signer path (D-018);
//! this stub exists only because the verify half is real and needs something to verify.
//!
//! Gated behind the `dev-issuer` feature so it is never built into a shipped `.app`.
//!
//! Usage:
//!   cargo run --features dev-issuer --bin issue-license -- --holder "Acme Regulated Co" [--days 365]
//! Prints the license token JSON to stdout; paste it into the Console's Activate field.

use kriya_console_lib::license::{dev_issue, LicensePayload};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn main() {
    let mut holder = "Demo Holder".to_string();
    let mut days: Option<u64> = None;
    let mut control_plane = false;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--holder" => holder = it.next().unwrap_or(holder),
            "--control-plane" => control_plane = true, // also grant the on-prem control-plane feature
            "--days" => {
                days = it.next().and_then(|d| d.parse().ok()).or_else(|| {
                    eprintln!("--days needs a number");
                    std::process::exit(2)
                })
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: issue-license --holder \"<name>\" [--control-plane] [--days <n>]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let issued = now_ms();
    let mut features = vec!["compliance-export".into(), "fleet-correlation".into()];
    if control_plane {
        features.push("control-plane".into());
    }
    let payload = LicensePayload {
        holder,
        tier: "pro".into(),
        features,
        issued_ms: issued,
        expires_ms: days.map(|d| issued + d * 24 * 60 * 60 * 1000),
        license_id: format!("dev-{issued}"),
    };

    match dev_issue(payload) {
        Ok(token) => {
            println!("{}", serde_json::to_string_pretty(&token).unwrap());
        }
        Err(e) => {
            eprintln!("issue-license: {e}");
            std::process::exit(1);
        }
    }
}
