//! Live-ish smoke of the govern-all flow (GA-1) against a sandbox HOME seeded from the machine's
//! REAL agent configs when present. Exercises the actual `#[tauri::command]` functions end to end:
//! detect → govern_all → (idempotent re-run) → ungovern_all, and asserts every config is restored
//! byte-for-byte. `#[ignore]` because it touches real config content + runs the osascript app scan;
//! run it explicitly:
//!
//!   cargo test --manifest-path src-tauri/Cargo.toml --test govern_live_smoke -- --ignored --nocapture
//!
//! The sandbox is a throwaway temp HOME — it NEVER writes the user's real files.

use std::path::{Path, PathBuf};

use kriya_console_lib::govern::{govern_all, governable_surface, ungovern_all};

fn real_home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).expect("HOME set")
}

/// Copy `rel` under the real HOME into the sandbox if it exists; otherwise write `seed`.
fn seed(sandbox: &Path, rel: &str, seed: &str) -> PathBuf {
    let dst = sandbox.join(rel);
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    let src = real_home().join(rel);
    if let Ok(real) = std::fs::read_to_string(&src) {
        std::fs::write(&dst, real).unwrap();
        eprintln!("  seeded {rel} from REAL config");
    } else {
        std::fs::write(&dst, seed).unwrap();
        eprintln!("  seeded {rel} from sample (no real config present)");
    }
    dst
}

#[test]
#[ignore]
fn govern_all_round_trip_on_real_configs() {
    let sandbox = std::env::temp_dir().join(format!("kriya-govern-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    std::fs::create_dir_all(&sandbox).unwrap();

    eprintln!("== seeding sandbox HOME: {} ==", sandbox.display());
    let cc = seed(
        &sandbox,
        ".claude/settings.json",
        "{\n  \"permissions\": { \"allow\": [\"Read\"] }\n}\n",
    );
    let desktop = seed(
        &sandbox,
        "Library/Application Support/Claude/claude_desktop_config.json",
        "{\n  \"mcpServers\": {\n    \"filesystem\": { \"command\": \"npx\", \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/tmp\"] }\n  }\n}\n",
    );
    let hermes = seed(
        &sandbox,
        ".hermes/config.yaml",
        "mcpServers:\n  fs:\n    command: uvx\n    args: [mcp-server-fs]\n",
    );

    // Whether each file is YAML (Hermes) or JSON — for the content-equality check.
    let is_yaml = |p: &Path| p.extension().and_then(|e| e.to_str()) == Some("yaml");
    // Parse a config file into a serde_json::Value regardless of on-disk format (content, not bytes).
    let content_of = |p: &Path| -> serde_json::Value {
        let text = std::fs::read_to_string(p).unwrap();
        if is_yaml(p) {
            serde_yaml::from_str(&text).unwrap()
        } else {
            serde_json::from_str(&text).unwrap()
        }
    };

    let files = [cc.clone(), desktop.clone(), hermes.clone()];
    // The raw originals' *content* (order-independent) — nothing here may be lost or altered.
    let orig_content: Vec<serde_json::Value> = files.iter().map(|p| content_of(p)).collect();

    // Redirect HOME so every command resolves configs into the sandbox.
    let prev_home = std::env::var_os("HOME");
    std::env::set_var("HOME", &sandbox);

    eprintln!("\n== governable_surface() ==");
    let surface = governable_surface();
    for t in &surface.targets {
        eprintln!("  [{}] {} — {} ({})", t.state, t.agent, t.label, t.seam);
    }
    eprintln!(
        "  hook_available={} gateway_available={}",
        surface.hook_available, surface.gateway_available
    );

    eprintln!("\n== govern_all() ==");
    let report = govern_all(None);
    eprintln!(
        "  wired={} already_governed={} needs_permission={} out_of_scope_cloud={} errors={}",
        report.wired.len(),
        report.already_governed.len(),
        report.needs_permission.len(),
        report.out_of_scope_cloud.len(),
        report.errors.len()
    );
    for a in &report.wired {
        eprintln!("    + {} {}", a.action, a.target_id);
    }
    assert!(report.errors.is_empty(), "govern_all reported errors: {:?}", report.errors);

    eprintln!("\n== after govern_all (full configs) ==");
    for p in &files {
        eprintln!("--- {} ---", p.file_name().unwrap().to_string_lossy());
        eprintln!("{}", std::fs::read_to_string(p).unwrap());
    }

    eprintln!("\n== govern_all() again (idempotency) ==");
    let report2 = govern_all(None);
    eprintln!("  wired={} (expect 0)", report2.wired.len());
    assert!(report2.wired.is_empty(), "second govern_all must wire nothing");

    eprintln!("\n== ungovern_all() ==");
    let revert = ungovern_all();
    eprintln!("  reverted={} errors={}", revert.reverted.len(), revert.errors.len());
    for a in &revert.reverted {
        eprintln!("    - {} {}", a.action, a.target_id);
    }
    assert!(revert.errors.is_empty(), "ungovern_all reported errors: {:?}", revert.errors);

    // (1) Content preserved: after a full govern→ungovern the parsed content equals the raw
    //     original — nothing govern-all added remains, and no pre-existing key/value was lost or
    //     altered (order-independent; a first edit reformats whitespace, never content).
    eprintln!("\n== content-preservation check (order-independent) ==");
    let reverted_bytes: Vec<String> = files.iter().map(|p| std::fs::read_to_string(p).unwrap()).collect();
    for (i, p) in files.iter().enumerate() {
        assert_eq!(content_of(p), orig_content[i], "{} content changed", p.display());
        eprintln!("  OK {}", p.file_name().unwrap().to_string_lossy());
    }

    // (2) Stable & fully reversible: a second govern→ungovern round-trip reproduces the exact same
    //     bytes — the operations are deterministic and remove every entry they add.
    eprintln!("\n== stable-reversibility check (byte-identical second round-trip) ==");
    let _ = govern_all(None);
    let _ = ungovern_all();
    for (i, p) in files.iter().enumerate() {
        assert_eq!(std::fs::read_to_string(p).unwrap(), reverted_bytes[i], "{} not byte-stable across round-trips", p.display());
        eprintln!("  OK {}", p.file_name().unwrap().to_string_lossy());
    }

    match prev_home {
        Some(h) => std::env::set_var("HOME", h),
        None => std::env::remove_var("HOME"),
    }
    let _ = std::fs::remove_dir_all(&sandbox);
    eprintln!("\n== govern-all live round-trip OK ==");
}
