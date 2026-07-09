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
    /// Whether an `agent-policy.yaml` exists where the runtime would load it (the working dir, or
    /// `~/.kriya/agent-policy.yaml`) — the onboarding "author your first rule" step ticks on this.
    ///
    /// Note: Screen Recording TCC state is deliberately NOT exposed. Unlike Accessibility
    /// (`AXIsProcessTrusted`, a no-arg read), macOS has no equivalent argument-free check, so the
    /// onboarding wizard treats Screen Recording as "grant, then re-check" rather than auto-detected.
    pub policy_present: bool,
}

/// Resolve the bundled `kriya-gateway` sidecar. In a packaged `.app` Tauri places external binaries
/// next to the main executable (`Contents/MacOS/kriya-gateway`); in `tauri dev` we fall back to the
/// `src-tauri/binaries/` staging dir. Returns `(path, bundled)`.
pub fn resolve_gateway() -> Option<(PathBuf, bool)> {
    resolve_sidecar("kriya-gateway")
}

/// Resolve the bundled `kriya-hook` sidecar (GA-0) — the Claude Code hooks adapter that govern-all
/// installs into `~/.claude/settings.json`. Same resolution order as [`resolve_gateway`].
pub fn resolve_hook() -> Option<(PathBuf, bool)> {
    resolve_sidecar("kriya-hook")
}

/// Resolve the bundled `kriya-hermes-hook` sidecar — the Hermes hooks adapter govern-all installs
/// into `~/.hermes/config.yaml`. Same resolution order as [`resolve_gateway`]/[`resolve_hook`].
pub fn resolve_hermes_hook() -> Option<(PathBuf, bool)> {
    resolve_sidecar("kriya-hermes-hook")
}

/// Resolve a bundled Tauri sidecar by binary name. In a packaged `.app` Tauri places external
/// binaries next to the main executable (`Contents/MacOS/<name>`); in `tauri dev` we fall back to the
/// `src-tauri/binaries/<name>-<triple>` staging dir, then the installed-app location. Returns
/// `(path, bundled)` where `bundled` means it lives inside a signed `.app` (the TCC-grantable case).
pub fn resolve_sidecar(name: &str) -> Option<(PathBuf, bool)> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // Packaged sidecar: same dir as the Console binary, name without the target-triple suffix.
            let bundled = dir.join(name);
            if bundled.is_file() {
                let in_app = bundled.to_string_lossy().contains(".app/Contents/MacOS/");
                return Some((bundled, in_app));
            }
            // Some layouts keep the triple suffix next to the exe.
            if let Some(p) = first_sidecar_in(dir, name) {
                let in_app = p.to_string_lossy().contains(".app/Contents/MacOS/");
                return Some((p, in_app));
            }
        }
    }
    // Dev: the staged sidecar under src-tauri/binaries/<name>-<triple>.
    let dev_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("binaries");
    if let Some(p) = first_sidecar_in(&dev_dir, name) {
        return Some((p, false));
    }
    // Installed app, when the Console binary itself is elsewhere.
    let installed =
        PathBuf::from(format!("/Applications/Kriya Console.app/Contents/MacOS/{name}"));
    if installed.is_file() {
        return Some((installed, true));
    }
    None
}

/// First executable in `dir` whose name starts with `name` (matches both the bare name and the
/// `<name>-<triple>` staged sidecar). Must not match a longer sibling by prefix
/// (`kriya-gateway` must never pick up `kriya-gateway-broker`); we anchor on the bare name or a
/// `<name>-` prefix.
fn first_sidecar_in(dir: &Path, name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let with_dash = format!("{name}-");
    let mut hits: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == name || n.starts_with(&with_dash))
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

/// Whether an `agent-policy.yaml` exists where the runtime would pick it up: the current working dir
/// (the `--policy agent-policy.yaml` convention) or the standard `~/.kriya/agent-policy.yaml` location.
fn policy_present() -> bool {
    if Path::new("agent-policy.yaml").is_file() {
        return true;
    }
    crate::audit::home_dir()
        .map(|home| home.join(".kriya").join("agent-policy.yaml").is_file())
        .unwrap_or(false)
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
        policy_present: policy_present(),
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
    // Was unconditionally "gui" — silently wrong off macOS (GuiApproval doesn't exist there; any
    // RequiresApproval action would hard-error at the binary). Same B0 bug class as govern.rs's
    // hook-install default; same fix (crate::govern::default_approval_mode).
    let approval = req.approval.clone().unwrap_or_else(|| crate::govern::default_approval_mode().to_string());

    // The `kriya` (bolt-on / serve) front is special: a kriya-instrumented MCP server governs and
    // signs its own named actions in-process, so the MCP client launches it DIRECTLY — no gateway
    // wrapper. Every other front routes through the bundled gateway.
    let (server_key, command, args) = if req.front == "kriya" {
        let downstream = req
            .downstream
            .clone()
            .filter(|d| !d.is_empty())
            .ok_or("a kriya-native connection needs a server command")?;
        let mut it = downstream.into_iter();
        let cmd = it.next().expect("downstream is non-empty (checked above)");
        let rest: Vec<String> = it.collect();
        let name = req
            .app
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("server");
        (format!("kriya-native-{}", slug(name)), cmd, rest)
    } else {
        let (gateway, _bundled) =
            resolve_gateway().ok_or("the bundled gateway binary could not be located")?;
        // B0: every gateway-routed front now wires --policy at the same Console-authored file
        // install_hook/govern_all point at (crate::govern::ensure_policy_file) — previously this
        // path, like the hook installers, never passed --policy at all.
        let policy_path = crate::govern::ensure_policy_file()?;
        let (key, args) = build_args(&req, &approval, &policy_path.to_string_lossy())?;
        (key, gateway.to_string_lossy().into_owned(), args)
    };

    let entry = serde_json::json!({ "command": command, "args": args });

    // The merge-safe write is the shared multi-client primitive (GA-0): read → ensure mcpServers →
    // insert this one key → write, never clobbering other servers or top-level keys. Claude Desktop
    // is the JSON `claude_desktop_config.json` target.
    let path = crate::govern::upsert_server(
        crate::govern::Client::ClaudeDesktop,
        &server_key,
        entry.clone(),
    )?;

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

/// Slugify a human name into an MCP server-key suffix (`Numbers` → `numbers`).
fn slug(s: &str) -> String {
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
}

/// Build the `(server_key, args)` for the chosen front. Mirrors the gateway's subcommand contract.
/// `policy` (B0) is inserted alongside `--approval` in every branch — previously omitted
/// entirely, so a wrapped server always ran the permissive built-in default regardless of what
/// the operator authored in the Policy view.
fn build_args(req: &WireRequest, approval: &str, policy: &str) -> Result<(String, Vec<String>), String> {
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
                    "--policy".into(),
                    policy.to_string(),
                    "--approval".into(),
                    approval.to_string(),
                ],
            ))
        }
        "computer-use" => Ok((
            "kriya-computer-use".into(),
            vec![
                "computer-use".into(),
                "--policy".into(),
                policy.to_string(),
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
            args.push("--policy".into());
            args.push(policy.to_string());
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
                "--policy".into(),
                policy.to_string(),
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
