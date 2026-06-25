//! First-run onboarding — the GUI that turns "download" into "governing in minutes" (D-018). It
//! resolves the **bundled gateway** (shipped as a Tauri sidecar inside the app), opens the macOS
//! privacy panes the gateway needs (Accessibility for reach-in, Screen Recording for computer-use),
//! and **wires the MCP client config** so the chosen front is launched under governance — the exact
//! TCC + config-edit pain we hit live, done for the user. Reuses the `kriya-gateway doctor` logic.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingStatus {
    /// Whether the bundled gateway binary was found, and where.
    pub gateway_present: bool,
    pub gateway_path: Option<String>,
    /// Whether the gateway ships inside this app's bundle (the TCC-grantable, stable-identity case)
    /// versus a loose dev binary.
    pub gateway_bundled: bool,
    /// Is THIS app trusted for Accessibility (macOS TCC)? The bundled gateway shares the app's
    /// signing identity, so granting "Kriya Console.app" is what makes reach-in work. `None` off macOS.
    pub accessibility_trusted: Option<bool>,
    /// Path to the MCP client (Claude Desktop) config, and the kriya servers already wired into it.
    pub claude_config_path: String,
    pub claude_config_exists: bool,
    pub wired_servers: Vec<String>,
    /// The standard audit dir + whether it already holds any logs (governance is already flowing).
    pub audit_dir: String,
    pub audit_logs: usize,
}

/// Resolve the bundled `kriya-gateway` sidecar. In a packaged `.app` Tauri places external binaries
/// next to the main executable (`Contents/MacOS/kriya-gateway`); in `tauri dev` we fall back to the
/// `src-tauri/binaries/` staging dir. Returns `(path, bundled)`.
pub fn resolve_gateway() -> Option<(PathBuf, bool)> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // Packaged sidecar: same dir as the Console binary, name without the target-triple suffix.
            let bundled = dir.join("kriya-gateway");
            if bundled.is_file() {
                let in_app = bundled.to_string_lossy().contains(".app/Contents/MacOS/");
                return Some((bundled, in_app));
            }
            // Some layouts keep the triple suffix next to the exe.
            if let Some(p) = first_gateway_in(dir) {
                let in_app = p.to_string_lossy().contains(".app/Contents/MacOS/");
                return Some((p, in_app));
            }
        }
    }
    // Dev: the staged sidecar under src-tauri/binaries/kriya-gateway-<triple>.
    let dev_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries");
    if let Some(p) = first_gateway_in(&dev_dir) {
        return Some((p, false));
    }
    // Installed app, when the Console binary itself is elsewhere.
    let installed = PathBuf::from("/Applications/Kriya Console.app/Contents/MacOS/kriya-gateway");
    if installed.is_file() {
        return Some((installed, true));
    }
    None
}

/// First executable in `dir` whose name starts with `kriya-gateway` (matches both the bare name and
/// the `kriya-gateway-<triple>` staged sidecar).
fn first_gateway_in(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut hits: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("kriya-gateway"))
                .unwrap_or(false)
                && p.is_file()
        })
        .collect();
    hits.sort();
    hits.into_iter().next()
}

/// macOS Accessibility (TCC) trust for THIS process. The bundled gateway runs under the same app
/// signature, so this is the signal the onboarding step guides the user to flip. `None` off macOS.
#[cfg(target_os = "macos")]
pub fn accessibility_trusted() -> Option<bool> {
    // ApplicationServices' `AXIsProcessTrusted()` — takes no args, returns a bool, pure read of the
    // current process's TCC grant. Linked directly so the Console needs no extra crate.
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrusted() -> bool;
    }
    // SAFETY: argument-free, side-effect-free system call.
    Some(unsafe { AXIsProcessTrusted() })
}

#[cfg(not(target_os = "macos"))]
pub fn accessibility_trusted() -> Option<bool> {
    None
}

/// Standard Claude Desktop config path. macOS: `~/Library/Application Support/Claude/`.
pub fn claude_config_path() -> PathBuf {
    let home = crate::audit::home_dir().unwrap_or_else(|| PathBuf::from("."));
    #[cfg(target_os = "macos")]
    {
        home.join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
    #[cfg(target_os = "windows")]
    {
        // %APPDATA%\Claude\claude_desktop_config.json
        let appdata = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Roaming"));
        appdata.join("Claude").join("claude_desktop_config.json")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        home.join(".config")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
}

/// Names of the `mcpServers` entries that launch our gateway (any command basename `kriya-gateway`).
fn wired_kriya_servers(config: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(map) = config.get("mcpServers").and_then(|m| m.as_object()) {
        for (key, entry) in map {
            let cmd = entry.get("command").and_then(|c| c.as_str()).unwrap_or("");
            if Path::new(cmd)
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("kriya-gateway"))
                .unwrap_or(false)
            {
                out.push(key.clone());
            }
        }
    }
    out.sort();
    out
}

#[tauri::command]
pub fn onboarding_status() -> OnboardingStatus {
    let gateway = resolve_gateway();
    let cfg_path = claude_config_path();
    let cfg_exists = cfg_path.is_file();
    let config: serde_json::Value = std::fs::read_to_string(&cfg_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(serde_json::Value::Null);
    let audit_dir = crate::audit::default_audit_dir();
    let audit_logs = std::fs::read_dir(&audit_dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jsonl"))
                .count()
        })
        .unwrap_or(0);

    OnboardingStatus {
        gateway_present: gateway.is_some(),
        gateway_path: gateway
            .as_ref()
            .map(|(p, _)| p.to_string_lossy().into_owned()),
        gateway_bundled: gateway.as_ref().map(|(_, b)| *b).unwrap_or(false),
        accessibility_trusted: accessibility_trusted(),
        claude_config_path: cfg_path.to_string_lossy().into_owned(),
        claude_config_exists: cfg_exists,
        wired_servers: wired_kriya_servers(&config),
        audit_dir: audit_dir.to_string_lossy().into_owned(),
        audit_logs,
    }
}

/// Open a macOS privacy pane so the user can grant the gateway what a front needs. `pane` is
/// `accessibility` (reach-in), `screen-recording` (computer-use), or `automation` (app discovery).
#[tauri::command]
pub fn open_settings_pane(pane: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let anchor = match pane.as_str() {
            "accessibility" => "Privacy_Accessibility",
            "screen-recording" => "Privacy_ScreenCapture",
            "automation" => "Privacy_Automation",
            other => return Err(format!("unknown settings pane: {other}")),
        };
        let url = format!("x-apple.systempreferences:com.apple.preference.security?{anchor}");
        std::process::Command::new("open")
            .arg(url)
            .status()
            .map_err(|e| format!("could not open settings: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pane;
        Err("privacy panes are macOS-only".into())
    }
}

/// Best-effort list of running user-facing apps (reach-in candidates), via System Events — the same
/// discovery `kriya-gateway doctor` does. Needs Automation permission for System Events; returns an
/// empty list (not an error) when denied so the picker degrades to free-text.
#[tauri::command]
pub fn list_candidate_apps() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("osascript")
            .args([
                "-e",
                "tell application \"System Events\" to get name of (processes where background only is false)",
            ])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                let raw = String::from_utf8_lossy(&out.stdout);
                let mut apps: Vec<String> = raw
                    .trim()
                    .split(", ")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                apps.sort();
                apps.dedup();
                return apps;
            }
        }
        Vec::new()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireRequest {
    /// `proxy` | `reach-in` | `computer-use` | `router`.
    pub front: String,
    /// Target app for `reach-in` (and the single `--reach-in` app for `router`).
    pub app: Option<String>,
    /// Approval mode written into the args (default `gui` — the native modal).
    pub approval: Option<String>,
    /// Downstream command + args for `proxy` (everything after `--`).
    pub downstream: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireResult {
    pub server_key: String,
    pub config_path: String,
    pub snippet: String,
    pub merged: bool,
}

/// Write/merge a governed-front entry into the MCP client config (`claude_desktop_config.json`),
/// pointing `command` at the resolved bundled gateway. Idempotent on the server key; never touches
/// other servers. Returns the snippet (also useful for manual paste) and whether the merge landed.
#[tauri::command]
pub fn wire_claude_config(req: WireRequest) -> Result<WireResult, String> {
    let (gateway, _bundled) =
        resolve_gateway().ok_or("the bundled gateway binary could not be located")?;
    let command = gateway.to_string_lossy().into_owned();
    let approval = req.approval.clone().unwrap_or_else(|| "gui".to_string());

    let (server_key, args) = build_args(&req, &approval)?;

    let entry = serde_json::json!({ "command": command, "args": args });

    let path = claude_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating config dir {}: {e}", parent.display()))?;
    }
    // Load the existing config (or start a fresh object); never clobber unrelated servers.
    let mut config: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !config.is_object() {
        config = serde_json::json!({});
    }
    let obj = config.as_object_mut().unwrap();
    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    if !servers.is_object() {
        *servers = serde_json::json!({});
    }
    servers
        .as_object_mut()
        .unwrap()
        .insert(server_key.clone(), entry.clone());

    let pretty = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(&path, pretty).map_err(|e| format!("writing {}: {e}", path.display()))?;

    // The single-server snippet (handy for a manual paste / copy button in the UI).
    let snippet = serde_json::to_string_pretty(&serde_json::json!({
        "mcpServers": { server_key.clone(): entry }
    }))
    .map_err(|e| e.to_string())?;

    Ok(WireResult {
        server_key,
        config_path: path.to_string_lossy().into_owned(),
        snippet,
        merged: true,
    })
}

/// Build the `(server_key, args)` for the chosen front. Mirrors the gateway's subcommand contract.
fn build_args(req: &WireRequest, approval: &str) -> Result<(String, Vec<String>), String> {
    let slug = |s: &str| -> String {
        let mut out = String::new();
        let mut prev = true;
        for c in s.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_lowercase());
                prev = false;
            } else if !prev {
                out.push('-');
                prev = true;
            }
        }
        while out.ends_with('-') {
            out.pop();
        }
        if out.is_empty() {
            "app".into()
        } else {
            out
        }
    };

    match req.front.as_str() {
        "reach-in" => {
            let app = req
                .app
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .ok_or("reach-in needs a target app")?;
            Ok((
                format!("kriya-{}", slug(app)),
                vec![
                    "reach-in".into(),
                    "--app".into(),
                    app.to_string(),
                    "--approval".into(),
                    approval.to_string(),
                ],
            ))
        }
        "computer-use" => Ok((
            "kriya-computer-use".into(),
            vec![
                "computer-use".into(),
                "--approval".into(),
                approval.to_string(),
            ],
        )),
        "router" => {
            let mut args = vec!["router".into()];
            if let Some(app) = req.app.as_deref().filter(|s| !s.trim().is_empty()) {
                args.push("--reach-in".into());
                args.push(app.to_string());
            }
            args.push("--approval".into());
            args.push(approval.to_string());
            Ok(("kriya-router".into(), args))
        }
        "proxy" => {
            let downstream = req
                .downstream
                .clone()
                .filter(|d| !d.is_empty())
                .ok_or("proxy needs a downstream command (everything after `--`)")?;
            let mut args = vec![
                "proxy".into(),
                "--approval".into(),
                approval.to_string(),
                "--".into(),
            ];
            args.extend(downstream);
            Ok(("kriya-proxy".into(), args))
        }
        other => Err(format!("unknown front: {other}")),
    }
}
