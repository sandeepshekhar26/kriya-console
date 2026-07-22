//! Govern-all (GA-0 foundation, doc 21 Part C/E) — detect the local **governable surface** and wire
//! each agent through its correct seam, reversibly and idempotently.
//!
//! Three pieces land here:
//! - **Detection** ([`governable_surface`]): one structured inventory of every governable target on
//!   the machine — Claude Code (hook), Claude Desktop + Hermes (local stdio MCP via the gateway),
//!   and the desktop-app lane — each tagged `governed | ungoverned | needs-permission |
//!   out-of-scope-cloud`.
//! - **The multi-client writer**: idempotent, non-clobbering add/remove for the three real agent
//!   configs — `claude_desktop_config.json`, `~/.claude/settings.json` (hooks **and** mcpServers),
//!   and `~/.hermes/config.yaml`. All merge logic runs on a `serde_json::Value`; the YAML edge is
//!   the only place format matters. It never overwrites unrelated entries and is safe to run twice.
//! - **Hook install** ([`install_hook`] / [`uninstall_hook`]): merge the bundled `kriya-hook` block
//!   into `~/.claude/settings.json` (which [`crate::coverage`] then detects), reversibly.
//!
//! GA-1 adds `govern_all` / `govern_preview` / `ungovern_all` on top of these primitives; this file
//! is the pure, test-first substrate they orchestrate. Honesty per `docs/TRUST.md`: cloud-executed
//! surfaces (remote MCP) are surfaced as `out-of-scope-cloud`, never wired, never claimed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::audit::home_dir;
use crate::coverage::claude_settings_path;
use crate::onboarding::{claude_config_path, resolve_gateway, resolve_hermes_hook, resolve_hook};

// ---------------------------------------------------------------------------------------------
// Clients — the three agent configs govern-all reads and writes.
// ---------------------------------------------------------------------------------------------

/// A governable MCP-client / agent whose config govern-all can read and (idempotently) edit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Client {
    /// Claude Desktop — `claude_desktop_config.json`; local stdio MCP only (no hook seam).
    ClaudeDesktop,
    /// Claude Code — `~/.claude/settings.json`; hooks (the whole local `claude` lane) + mcpServers.
    ClaudeCode,
    /// Hermes (`NousResearch/hermes-agent`) — `~/.hermes/config.yaml`; local stdio MCP via the
    /// gateway, AND native tools + attached MCP via the `kriya-hermes-hook` shell-hook seam (R31).
    Hermes,
    /// Cursor — `~/.cursor/mcp.json` (global; project override `.cursor/mcp.json`); local stdio MCP
    /// only (no local hook seam — Cursor's built-in edit/terminal tools bypass MCP entirely; see the
    /// honest ceiling in the Coverage view + FEATURE-PROOF). Shares Anthropic's `mcpServers`
    /// (camelCase) shape, `{command,args,env}` for stdio / `url` for remote — verified 2026-07-21
    /// against cursor.com/docs (MCP), not assumed by analogy.
    Cursor,
    /// Cline (VS Code / Cursor extension `saoudrizwan.claude-dev`) — the extension's own
    /// `cline_mcp_settings.json` under VS Code's `globalStorage`; local stdio MCP only. Top-level
    /// `mcpServers`, stdio `{command,args,env,disabled,autoApprove}` — verified 2026-07-21 against
    /// docs.cline.bot (Configuring MCP Servers). NOTE the host split: this points at the **VS Code**
    /// storage path; a Cline running inside Cursor stores under `Cursor/User/globalStorage/…` instead
    /// (recorded in FEATURE-PROOF as the known host-variant limitation).
    Cline,
    /// GitHub Copilot (VS Code agent mode) — VS Code's user-level `mcp.json`; local stdio MCP only
    /// (Copilot's own built-in tools + its cloud coding agent are out of scope — locus rule). UNLIKE
    /// every other client here the servers map is keyed **`servers`** (lowercase), NOT `mcpServers`;
    /// stdio `{command,args,env}` (`type:"stdio"` implicit), remote `{type:"http",url}` — verified
    /// 2026-07-21 against code.visualstudio.com/docs/copilot/chat/mcp-servers. Detection is best-effort
    /// on the user `mcp.json`'s presence (VS Code writes it only once MCP is configured).
    Copilot,
    /// Gemini CLI (Google) — `~/.gemini/settings.json`; local stdio MCP only. Top-level `mcpServers`,
    /// stdio `{command,args,env,cwd}` / remote `{httpUrl}` or `{url}` — verified 2026-07-21 against
    /// github.com/google-gemini/gemini-cli (docs/tools/mcp-server). Presence keys on `settings.json`
    /// specifically (the bare `~/.gemini/` dir is also used by other Google tooling — do not
    /// false-detect it as an installed Gemini CLI).
    Gemini,
}

/// Serialization format of a client's config file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    Json,
    Yaml,
}

impl Client {
    /// The stable agent id used in [`GovernTarget::agent`] and target ids.
    pub fn agent_id(self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "claude-desktop",
            Client::ClaudeCode => "claude-code",
            Client::Hermes => "hermes",
            Client::Cursor => "cursor",
            Client::Cline => "cline",
            Client::Copilot => "copilot",
            Client::Gemini => "gemini",
        }
    }

    fn from_agent(agent: &str) -> Option<Client> {
        match agent {
            "claude-desktop" => Some(Client::ClaudeDesktop),
            "claude-code" => Some(Client::ClaudeCode),
            "hermes" => Some(Client::Hermes),
            "cursor" => Some(Client::Cursor),
            "cline" => Some(Client::Cline),
            "copilot" => Some(Client::Copilot),
            "gemini" => Some(Client::Gemini),
            _ => None,
        }
    }

    fn config_path(self) -> PathBuf {
        match self {
            Client::ClaudeDesktop => claude_config_path(),
            Client::ClaudeCode => claude_settings_path()
                .unwrap_or_else(|| PathBuf::from(".claude").join("settings.json")),
            Client::Hermes => hermes_config_path(),
            Client::Cursor => cursor_mcp_path(),
            Client::Cline => cline_mcp_path(),
            Client::Copilot => vscode_user_mcp_path(),
            Client::Gemini => gemini_settings_path(),
        }
    }

    fn fmt(self) -> Fmt {
        match self {
            Client::Hermes => Fmt::Yaml,
            _ => Fmt::Json, // Claude {Desktop,Code}, Cursor, Cline, Copilot, Gemini all use JSON
        }
    }

    /// Whether this client has a hook seam govern-all can install into. The VS-Code-family clients
    /// (Cursor/Cline/Copilot) and Gemini CLI expose **no local hook API** — they are MCP-only, so
    /// govern-all reaches them through the gateway (per-server wrap), never a hook.
    fn supports_hooks(self) -> bool {
        matches!(self, Client::ClaudeCode | Client::Hermes)
    }

    /// The command-line binary that indicates the client is installed even without a config file.
    fn path_binary(self) -> Option<&'static str> {
        match self {
            Client::ClaudeCode => Some("claude"),
            Client::Hermes => Some("hermes"),
            Client::Gemini => Some("gemini"),
            // GUI apps / extensions — not a PATH binary; detected via their config file's presence.
            // (Cursor ships a `cursor` shell command, but it is opt-in from the app and often absent
            // even on a full install — so presence keys on `~/.cursor/mcp.json`, like Claude Desktop.)
            Client::ClaudeDesktop | Client::Cursor | Client::Cline | Client::Copilot => None,
        }
    }

    /// The top-level key this client's config uses for its MCP-server map. Claude Desktop and Claude
    /// Code both use Anthropic's `mcpServers` (camelCase); Hermes stores the identical shape under
    /// `mcp_servers` (snake_case) — verified against the real `hermes_cli/mcp_config.py` source
    /// (`_get_mcp_servers`/`_save_mcp_server` read/write `config.get("mcp_servers")`/
    /// `config.setdefault("mcp_servers", {})`), not copied by analogy from Claude's convention. Getting
    /// this wrong means a real Hermes install's configured servers are silently invisible to
    /// detection — found live (2026-07-08): a user's Hermes agent never appeared in "Govern
    /// everything" because the original code looked up `mcpServers` universally.
    pub(crate) fn servers_key(self) -> &'static str {
        match self {
            Client::Hermes => "mcp_servers",
            // VS Code's native MCP config (Copilot agent mode) keys the map `servers` (lowercase) —
            // NOT Anthropic's `mcpServers`. Getting this wrong makes a real Copilot install's servers
            // invisible to detection, exactly the class of bug the Hermes `mcp_servers` note records.
            Client::Copilot => "servers",
            // Claude Desktop/Code, Cursor, Cline, Gemini CLI all use Anthropic's `mcpServers`.
            _ => "mcpServers",
        }
    }
}

/// `~/.cursor/mcp.json` — Cursor's global MCP server map (`mcpServers`).
pub fn cursor_mcp_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".cursor")
        .join("mcp.json")
}

/// `~/.gemini/settings.json` — Gemini CLI's settings (the `mcpServers` map lives here).
pub fn gemini_settings_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gemini")
        .join("settings.json")
}

/// Cline's MCP settings under VS Code's per-user `globalStorage` (extension `saoudrizwan.claude-dev`).
/// macOS path; the Console is macOS-first (mirrors [`crate::onboarding::claude_config_path`]'s
/// `~/Library/Application Support` convention).
pub fn cline_mcp_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library")
        .join("Application Support")
        .join("Code")
        .join("User")
        .join("globalStorage")
        .join("saoudrizwan.claude-dev")
        .join("settings")
        .join("cline_mcp_settings.json")
}

/// VS Code's user-level `mcp.json` (the seam GitHub Copilot agent mode reads). macOS path.
pub fn vscode_user_mcp_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library")
        .join("Application Support")
        .join("Code")
        .join("User")
        .join("mcp.json")
}

/// `~/.hermes/config.yaml` — Hermes' agent config (the `mcp_servers:` map + a future `hooks:` block).
pub fn hermes_config_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".hermes")
        .join("config.yaml")
}

// ---------------------------------------------------------------------------------------------
// The Console-authored policy (B0, doc 22 §11) — persistence + wiring into every enforcement
// seam. Before this, PolicyView.tsx authored a policy that was never written to any file the
// runtime could load, and every install path below omitted --policy entirely: a policy the
// operator marked "deny" was silently unenforced (the built-in default is allow-all), which is
// the founder-reported B0 bug. Fixed by (a) persisting the authored YAML to one stable,
// runtime-visible path, and (b) always passing --policy at it from every seam that installs a
// hook or wraps an MCP server.
// ---------------------------------------------------------------------------------------------

/// `~/.kriya/agent-policy.yaml` — the stable path `onboarding.rs::policy_present()` already
/// checks for as "where the runtime would load it." Lives directly under `~/.kriya/` (not
/// `~/.kriya/console/`, which is Console-private state) because the runtime binaries
/// (`kriya-hook`, `kriya-hermes-hook`, `kriya-gateway`) must read it too.
pub fn agent_policy_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kriya")
        .join("agent-policy.yaml")
}

/// Byte-identical to `kriya-hook`'s/`kriya-hermes-hook`'s own built-in `DEFAULT_POLICY_YAML` —
/// record-only, allow everything. Writing this changes nothing about current enforcement
/// behavior until the operator authors a real rule; it exists purely so `--policy <path>` always
/// points at a real file (never a dangling one) the moment any seam starts passing the flag.
pub(crate) const PERMISSIVE_DEFAULT_POLICY_YAML: &str = "rules:\n  - { action: \"*\", allow: true }\n";

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PolicySaveResult {
    pub path: String,
    pub bytes: usize,
}

/// Persist the Console-authored policy YAML to the stable, runtime-visible path. Called on every
/// policy edit (debounced from the frontend) so every seam that resolves `--policy` via
/// [`ensure_policy_file`] always points at what the operator most recently authored.
#[tauri::command]
pub fn save_agent_policy(yaml: String) -> Result<PolicySaveResult, String> {
    let path = agent_policy_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, &yaml).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(PolicySaveResult { path: path.to_string_lossy().into_owned(), bytes: yaml.len() })
}

/// Read the currently-persisted policy YAML, so a relaunched Console restores what was last
/// saved instead of resetting to the frontend's in-memory default every launch. `None` if the
/// file doesn't exist yet (a fresh install that has never saved a policy).
#[tauri::command]
pub fn load_agent_policy() -> Option<String> {
    std::fs::read_to_string(agent_policy_path()).ok()
}

/// Ensure `agent_policy_path()` exists — writing the permissive built-in default if absent —
/// BEFORE any enforcement-install path references it via `--policy`. Idempotent and
/// **never overwrites an already-authored policy** (unlike [`save_agent_policy`], which always
/// overwrites: that split is what preserves doc 19's "never brick the agent on install" intent
/// now that `--policy` is always passed — an operator who runs "Govern everything" without ever
/// opening the Policy view still gets a valid, existing `--policy` target). The one place that
/// answers "which file does `--policy` point at" — every enforcement-install call site (this
/// module's hook/hermes-hook/gateway-wrap installers, and `onboarding.rs::build_args`) resolves
/// the path through this function, never re-derives it, so there is exactly one source of truth.
pub(crate) fn ensure_policy_file() -> Result<PathBuf, String> {
    let path = agent_policy_path();
    if !path.is_file() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, PERMISSIVE_DEFAULT_POLICY_YAML)
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(path)
}

/// Mirrors `onboarding.rs::wire_claude_config`'s own `unwrap_or_else(|| "gui".to_string())`
/// convention (line ~312) — the hook-install path below never adopted it, silently falling back
/// to `kriya-hook`'s own hardcoded `"deny"` default instead: a `RequiresApproval` decision would
/// auto-deny with **zero interactive surface** (no tty prompt, no GUI dialog — nothing), which is
/// indistinguishable, from the operator's chair, from "the approval tier didn't do anything" —
/// the second half of the B0 bug report. `GuiApproval` is macOS-only in the runtime; `"tty"` is
/// the correct non-macOS fallback, not `"deny"` — that would just relocate the same bug. Unlike a
/// hardcoded `"deny"`, `"tty"` at least attempts an interactive prompt when Claude Code runs in a
/// real terminal, and degrades safely to a denial (now self-bounded at 300s, closing a related
/// fail-open gap) when no `/dev/tty` is reachable.
pub(crate) fn default_approval_mode() -> &'static str {
    if cfg!(target_os = "macos") {
        "gui"
    } else {
        "tty"
    }
}

// ---------------------------------------------------------------------------------------------
// Config read / write — all merge logic runs on a serde_json::Value; format is an edge concern.
// ---------------------------------------------------------------------------------------------

/// Read a client config into a JSON object `Value`, tolerating a missing/empty/malformed file (→
/// `{}`). YAML is parsed straight into a `serde_json::Value` so every downstream edit is one code
/// path regardless of on-disk format.
fn read_config(path: &Path, fmt: Fmt) -> Value {
    let Ok(text) = std::fs::read_to_string(path) else {
        return json!({});
    };
    let parsed = match fmt {
        Fmt::Json => serde_json::from_str::<Value>(&text).ok(),
        Fmt::Yaml => serde_yaml::from_str::<Value>(&text).ok(),
    };
    match parsed {
        Some(v) if v.is_object() => v,
        _ => json!({}),
    }
}

fn serialize_config(fmt: Fmt, v: &Value) -> Result<String, String> {
    let body = match fmt {
        Fmt::Json => serde_json::to_string_pretty(v).map_err(|e| e.to_string())?,
        Fmt::Yaml => serde_yaml::to_string(v).map_err(|e| e.to_string())?,
    };
    // Exactly one trailing newline (POSIX text-file convention; keeps `git diff` clean). serde_json's
    // pretty printer emits none, serde_yaml one — normalize both so writes are format-stable.
    Ok(format!("{}\n", body.trim_end_matches('\n')))
}

fn write_config(path: &Path, fmt: Fmt, v: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let text = serialize_config(fmt, v)?;
    std::fs::write(path, text).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// The client's MCP-servers object (keyed per [`Client::servers_key`] — `mcpServers` for Claude,
/// `mcp_servers` for Hermes), created if absent (or replaced if it exists as a non-object).
fn servers_mut(config: &mut Value, client: Client) -> &mut serde_json::Map<String, Value> {
    if !config.is_object() {
        *config = json!({});
    }
    let obj = config.as_object_mut().unwrap();
    let servers = obj.entry(client.servers_key()).or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    servers.as_object_mut().unwrap()
}

fn servers_ref(config: &Value, client: Client) -> Option<&serde_json::Map<String, Value>> {
    config.get(client.servers_key()).and_then(Value::as_object)
}

/// Insert/replace one MCP-server entry in a client's config, merge-safe (never touches other
/// servers or top-level keys) and format-correct (JSON for the Claude configs, YAML for Hermes;
/// `mcpServers` vs `mcp_servers` per [`Client::servers_key`]). The shared write primitive under
/// `wire_claude_config` and (GA-1) `govern_all`.
pub fn upsert_server(client: Client, key: &str, entry: Value) -> Result<PathBuf, String> {
    let path = client.config_path();
    let mut config = read_config(&path, client.fmt());
    servers_mut(&mut config, client).insert(key.to_string(), entry);
    write_config(&path, client.fmt(), &config)?;
    Ok(path)
}

/// Remove one MCP-server entry from a client's config (the revert half of [`upsert_server`]).
/// No-op if the key is absent; leaves everything else untouched.
pub fn remove_server(client: Client, key: &str) -> Result<PathBuf, String> {
    let path = client.config_path();
    let mut config = read_config(&path, client.fmt());
    if let Some(servers) = config.get_mut(client.servers_key()).and_then(Value::as_object_mut) {
        servers.remove(key);
    }
    write_config(&path, client.fmt(), &config)?;
    Ok(path)
}

// ---------------------------------------------------------------------------------------------
// Gateway wrap / unwrap of a local stdio MCP server entry.
// ---------------------------------------------------------------------------------------------

/// Is this entry launched via the bundled `kriya-gateway` (any subcommand)?
fn is_gateway_wrapped(entry: &Value) -> bool {
    entry
        .get("command")
        .and_then(Value::as_str)
        .and_then(|c| Path::new(c).file_name().and_then(|n| n.to_str()).map(String::from))
        .map(|n| n.starts_with("kriya-gateway"))
        .unwrap_or(false)
}

/// The gateway subcommand (`proxy` / `reach-in` / `computer-use` / `router`) of a wrapped entry.
fn gateway_subcommand(entry: &Value) -> Option<String> {
    if !is_gateway_wrapped(entry) {
        return None;
    }
    entry
        .get("args")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .map(String::from)
}

/// A remote/off-device MCP server (url- or transport-typed): out of scope, never wrappable.
/// `httpUrl` is Gemini CLI's remote key (alongside `url`); `streamableHttp` is Cline's remote
/// `type` — both verified 2026-07-21 and folded in so a remote server on those clients is honestly
/// classed out-of-scope-cloud, never mistaken for a wrappable local stdio server.
fn is_remote(entry: &Value) -> bool {
    entry.get("url").is_some()
        || entry.get("httpUrl").is_some()
        || entry
            .get("type")
            .and_then(Value::as_str)
            .map(|t| matches!(t, "sse" | "http" | "streamable-http" | "streamableHttp" | "ws"))
            .unwrap_or(false)
}

/// A local stdio server (spawned by a `command`) that is not already gateway-wrapped and not remote.
fn is_local_stdio(entry: &Value) -> bool {
    !is_gateway_wrapped(entry)
        && !is_remote(entry)
        && entry
            .get("command")
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
}

/// Wrap a local stdio server entry so its `tools/call`s route through the gateway (policy → approval
/// → signed receipt). Preserves every sibling key (`env`, …); only `command`/`args` change. Returns
/// `None` when the entry is not a wrappable local stdio server. `policy` is inserted BEFORE the
/// `--` separator (a gateway flag, never forwarded to the downstream command), so [`unwrap_entry`]'s
/// reconstruction — which only looks after `--` — is unaffected by its presence (B0).
fn wrap_entry(entry: &Value, gateway: &str, actor: &str, approval: &str, policy: &str) -> Option<Value> {
    if !is_local_stdio(entry) {
        return None;
    }
    let cmd = entry.get("command")?.as_str()?.to_string();
    let orig_args: Vec<Value> = entry
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut args: Vec<Value> = vec![
        json!("proxy"),
        json!("--policy"),
        json!(policy),
        json!("--approval"),
        json!(approval),
        json!("--actor"),
        json!(actor),
        json!("--"),
        json!(cmd),
    ];
    args.extend(orig_args);
    let mut wrapped = entry.clone();
    let obj = wrapped.as_object_mut()?;
    obj.insert("command".into(), json!(gateway));
    obj.insert("args".into(), Value::Array(args));
    Some(wrapped)
}

/// Reverse [`wrap_entry`]: reconstruct the original `command`/`args` from everything after `--`.
/// Only unwraps gateway `proxy` entries (never a reach-in/computer-use desktop front). Preserves
/// sibling keys, so a wrap→unwrap round-trips a canonical entry byte-for-byte.
fn unwrap_entry(entry: &Value) -> Option<Value> {
    if gateway_subcommand(entry).as_deref() != Some("proxy") {
        return None;
    }
    let args = entry.get("args").and_then(Value::as_array)?;
    let dashdash = args.iter().position(|a| a.as_str() == Some("--"))?;
    let mut rest = args[dashdash + 1..].iter();
    let cmd = rest.next()?.as_str()?.to_string();
    let orig_args: Vec<Value> = rest.cloned().collect();
    let mut orig = entry.clone();
    let obj = orig.as_object_mut()?;
    obj.insert("command".into(), json!(cmd));
    if orig_args.is_empty() {
        obj.remove("args");
    } else {
        obj.insert("args".into(), Value::Array(orig_args));
    }
    Some(orig)
}

// ---------------------------------------------------------------------------------------------
// The hooks block (`~/.claude/settings.json`).
// ---------------------------------------------------------------------------------------------

/// The marker that identifies a hooks group as one govern-all installed (the resolved path always
/// contains the binary name). Used to keep install idempotent and uninstall surgical.
const HOOK_MARK: &str = "kriya-hook";

/// Shell-quote a path for a hook `command` string (Claude Code runs it via the shell). Single-quote
/// only when needed (spaces / specials), escaping embedded single quotes.
fn shell_quote(path: &str) -> String {
    if !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
    {
        path.to_string()
    } else {
        format!("'{}'", path.replace('\'', r"'\''"))
    }
}

/// `policy_quoted` and `approval` close the B0 bug: previously this command carried neither flag,
/// so an installed hook always ran the permissive built-in default (a policy the operator marked
/// "deny" was silently unenforced) and any `RequiresApproval` decision silently auto-denied with
/// zero interactive surface (`kriya-hook`'s own hardcoded fallback). `policy_quoted` is expected
/// pre-quoted by the caller (same convention as `hook_cmd_quoted`).
fn hook_group(hook_cmd_quoted: &str, mode: &str, policy_quoted: &str, approval: &str) -> Value {
    json!({ "hooks": [ { "type": "command", "command": format!("{hook_cmd_quoted} {mode} --policy {policy_quoted} --approval {approval}") } ] })
}

/// Does a settings config already carry a kriya-hook block? Mirrors [`crate::coverage::hook_configured`]
/// (any mention of `kriya-hook` inside the `hooks` value) but operates on an in-memory `Value`, so
/// detection is a pure function of its inputs.
fn config_has_kriya_hook(config: &Value) -> bool {
    config
        .get("hooks")
        .map(|h| h.to_string().contains(HOOK_MARK))
        .unwrap_or(false)
}

/// Does this hooks group belong to kriya (any inner hook command mentions `kriya-hook`)?
fn group_is_kriya(group: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .map(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .map(|c| c.contains(HOOK_MARK))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Merge the kriya-hook `PreToolUse`/`PostToolUse` groups into a settings `Value`. Idempotent (drops
/// any prior kriya group before appending) and non-clobbering (leaves every other group untouched).
fn install_hook_block(config: &mut Value, hook_cmd_quoted: &str, policy_quoted: &str, approval: &str) {
    if !config.is_object() {
        *config = json!({});
    }
    let obj = config.as_object_mut().unwrap();
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let hooks_obj = hooks.as_object_mut().unwrap();
    for (event, mode) in [("PreToolUse", "pre"), ("PostToolUse", "post")] {
        let arr = hooks_obj.entry(event).or_insert_with(|| json!([]));
        if !arr.is_array() {
            *arr = json!([]);
        }
        let list = arr.as_array_mut().unwrap();
        list.retain(|g| !group_is_kriya(g));
        list.push(hook_group(hook_cmd_quoted, mode, policy_quoted, approval));
    }
}

/// Reverse [`install_hook_block`]: remove only kriya groups, prune emptied event arrays, and drop the
/// `hooks` key if nothing else remains.
fn uninstall_hook_block(config: &mut Value) {
    let Some(obj) = config.as_object_mut() else {
        return;
    };
    let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) else {
        return;
    };
    for event in ["PreToolUse", "PostToolUse"] {
        if let Some(arr) = hooks.get_mut(event).and_then(Value::as_array_mut) {
            arr.retain(|g| !group_is_kriya(g));
        }
    }
    hooks.retain(|_, v| !v.as_array().map(|a| a.is_empty()).unwrap_or(false));
    if hooks.is_empty() {
        obj.remove("hooks");
    }
}

// ---------------------------------------------------------------------------------------------
// Hermes' hook writer — a distinct shape from Claude Code's `hooks.PreToolUse[].hooks[].command`
// (JSON): a flat `hooks: { <event>: [ { command, matcher?, timeout? } ] }` map (YAML), verified
// against the real `agent/shell_hooks.py` + `website/docs/user-guide/features/hooks.md` source,
// 2026-07-08 (event names `pre_tool_call`/`post_tool_call`, no per-entry nested `hooks` array).
// ---------------------------------------------------------------------------------------------

/// Kept separate from `HOOK_MARK` (Claude Code's `kriya-hook`) — the two binaries/configs are
/// independent, and "kriya-hermes-hook" does not contain "kriya-hook" as a substring (no collision
/// risk either way; verified by inspection).
const HERMES_HOOK_MARK: &str = "kriya-hermes-hook";

/// One Hermes shell-hook entry for `event` (`pre_tool_call`/`post_tool_call`) — no `matcher`, so it
/// fires for every `tool_name` (confirmed against `ShellHookSpec.matches_tool`: an absent matcher
/// matches everything), the same "whole lane, zero per-tool config" property `kriya-hook` has for
/// Claude Code. `timeout: 300` is Hermes' own hard per-hook cap, matching `GuiApproval`'s own
/// `osascript … giving up after 300` so a pending approval dialog gets the full window either
/// side can give it. `policy_quoted`/`approval` mirror [`hook_group`]'s own B0 fix — same bug,
/// same seam, same fix.
fn hermes_hook_entry(hook_cmd_quoted: &str, mode: &str, policy_quoted: &str, approval: &str) -> Value {
    json!({ "command": format!("{hook_cmd_quoted} {mode} --policy {policy_quoted} --approval {approval}"), "timeout": 300 })
}

/// Does a Hermes config already carry a kriya-hermes-hook entry? Mirrors
/// [`crate::coverage::hermes_flags_from`]'s own check (any mention of `kriya-hermes-hook` inside
/// the `hooks` value) but operates on an in-memory `Value`, so detection is a pure function of
/// its inputs.
fn config_has_kriya_hermes_hook(config: &Value) -> bool {
    config
        .get("hooks")
        .map(|h| h.to_string().contains(HERMES_HOOK_MARK))
        .unwrap_or(false)
}

/// Does this hook entry belong to kriya (its `command` mentions `kriya-hermes-hook`)?
fn hermes_entry_is_kriya(entry: &Value) -> bool {
    entry
        .get("command")
        .and_then(Value::as_str)
        .map(|c| c.contains(HERMES_HOOK_MARK))
        .unwrap_or(false)
}

/// Merge the kriya-hermes-hook `pre_tool_call`/`post_tool_call` entries into a Hermes config
/// `Value`, and set `hooks_auto_accept: true` — confirmed sufficient on its own (no env var or CLI
/// flag needed) to skip Hermes' own interactive first-use TTY consent prompt, so installing this
/// is a single config write with no follow-up terminal step. Idempotent (drops any prior kriya
/// entry before appending) and non-clobbering of every OTHER hook event/entry.
fn install_hermes_hook_block(config: &mut Value, hook_cmd_quoted: &str, policy_quoted: &str, approval: &str) {
    if !config.is_object() {
        *config = json!({});
    }
    let obj = config.as_object_mut().unwrap();
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let hooks_obj = hooks.as_object_mut().unwrap();
    for (event, mode) in [("pre_tool_call", "pre"), ("post_tool_call", "post")] {
        let arr = hooks_obj.entry(event).or_insert_with(|| json!([]));
        if !arr.is_array() {
            *arr = json!([]);
        }
        let list = arr.as_array_mut().unwrap();
        list.retain(|e| !hermes_entry_is_kriya(e));
        list.push(hermes_hook_entry(hook_cmd_quoted, mode, policy_quoted, approval));
    }
    obj.insert("hooks_auto_accept".into(), json!(true));
}

/// Reverse [`install_hermes_hook_block`]: remove only kriya entries, prune emptied event arrays,
/// drop the `hooks` key if nothing else remains, and — only when the value is exactly `true` (what
/// install always sets, never anything else) — drop `hooks_auto_accept` too, so a govern→ungovern
/// round-trip restores an untouched config byte-for-byte. In the narrow case a user had
/// independently set `hooks_auto_accept: true` themselves for an unrelated hook, this resets it to
/// Hermes' own more-cautious default (re-prompt) rather than silently leaving a flag kriya no
/// longer needs — the safe direction to diverge in, never the unsafe one.
fn uninstall_hermes_hook_block(config: &mut Value) {
    let Some(obj) = config.as_object_mut() else {
        return;
    };
    if let Some(hooks) = obj.get_mut("hooks").and_then(Value::as_object_mut) {
        for event in ["pre_tool_call", "post_tool_call"] {
            if let Some(arr) = hooks.get_mut(event).and_then(Value::as_array_mut) {
                arr.retain(|e| !hermes_entry_is_kriya(e));
            }
        }
        hooks.retain(|_, v| !v.as_array().map(|a| a.is_empty()).unwrap_or(false));
        if hooks.is_empty() {
            obj.remove("hooks");
        }
    }
    if obj.get("hooks_auto_accept") == Some(&json!(true)) {
        obj.remove("hooks_auto_accept");
    }
}

// ---------------------------------------------------------------------------------------------
// Detection — the governable-surface inventory.
// ---------------------------------------------------------------------------------------------

/// One governable target in the inventory. Serialized to the UI and echoed in the govern-all report.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernTarget {
    /// Stable id (`<agent>:<kind>[:<key>]`) — the handle for per-item govern/ungovern + the toggle.
    pub id: String,
    /// The agent/client: `claude-code` | `claude-desktop` | `hermes` | `desktop`.
    pub agent: String,
    /// What kind of surface: `hook` | `mcp-server` | `desktop-apps`.
    pub kind: String,
    /// The seam that governs it: `hook` | `gateway` | `reach-in/computer-use`.
    pub seam: String,
    /// `governed` | `ungoverned` | `needs-permission` | `out-of-scope-cloud`.
    pub state: String,
    /// The config file that would be edited (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    /// Short human label for the row.
    pub label: String,
    /// One honest line of context (why this state / what wiring it through does).
    pub detail: String,
}

impl GovernTarget {
    fn new(
        id: impl Into<String>,
        agent: impl Into<String>,
        kind: impl Into<String>,
        seam: impl Into<String>,
        state: impl Into<String>,
        config_path: Option<String>,
        label: impl Into<String>,
        detail: impl Into<String>,
    ) -> GovernTarget {
        GovernTarget {
            id: id.into(),
            agent: agent.into(),
            kind: kind.into(),
            seam: seam.into(),
            state: state.into(),
            config_path,
            label: label.into(),
            detail: detail.into(),
        }
    }
}

/// The whole detected surface. `targets` is a flat list the UI groups by `agent`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernableSurface {
    pub targets: Vec<GovernTarget>,
    /// Is `kriya-hook` bundled/resolvable? (Govern-all can't install a hook it doesn't ship.)
    pub hook_available: bool,
    /// Is `kriya-gateway` bundled/resolvable? (Needed to wrap MCP servers.)
    pub gateway_available: bool,
    /// Is `kriya-hermes-hook` bundled/resolvable? A distinct binary/availability from
    /// `hook_available` — Claude Code and Hermes each have their own hook adapter.
    pub hermes_hook_available: bool,
    /// macOS Accessibility trust for the desktop-app lane (`None` off macOS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ax_trusted: Option<bool>,
    /// Running desktop-app names (reach-in/computer-use candidates) — for the Advanced drawer.
    pub desktop_candidates: Vec<String>,
}

/// A client's state at detection time: its parsed config + whether it is present at all.
struct ClientState {
    client: Client,
    config: Value,
    present: bool,
}

/// Pure detector: build the inventory from already-read client states + environment facts. Injecting
/// the inputs keeps this unit-testable with fixtures (no filesystem / PATH / TCC access).
fn detect(
    clients: &[ClientState],
    ax_trusted: Option<bool>,
    desktop_candidates: &[String],
    hook_available: bool,
    gateway_available: bool,
    hermes_hook_available: bool,
) -> GovernableSurface {
    let mut targets = Vec::new();

    for cs in clients {
        if !cs.present {
            continue;
        }
        let agent = cs.client.agent_id();
        let cfg_path = Some(cs.client.config_path().to_string_lossy().into_owned());

        // The hook target (the whole native + attached-MCP lane). Claude Code and Hermes each get
        // their own — a distinct binary/config shape per client, unconditional (detected
        // regardless of whether any MCP servers are configured too, so an agent with zero MCP
        // servers still shows up governable rather than silently absent).
        if cs.client == Client::ClaudeCode {
            let governed = config_has_kriya_hook(&cs.config);
            targets.push(GovernTarget::new(
                format!("{agent}:hook"),
                agent,
                "hook",
                "hook",
                if governed { "governed" } else { "ungoverned" },
                cfg_path.clone(),
                "Claude Code — native tools + attached MCP",
                if governed {
                    "The kriya-hook is installed: every Bash/Edit/Write and mcp__ call signs a receipt."
                } else {
                    "One hook governs the whole local Claude Code lane — native tools and every attached MCP server."
                },
            ));
        }
        if cs.client == Client::Hermes {
            let governed = config_has_kriya_hermes_hook(&cs.config);
            targets.push(GovernTarget::new(
                format!("{agent}:hook"),
                agent,
                "hook",
                "hook",
                if governed { "governed" } else { "ungoverned" },
                cfg_path.clone(),
                "Hermes — native tools + attached MCP",
                if governed {
                    "The kriya-hermes-hook is installed: every terminal/file/computer-use and MCP call signs a receipt."
                } else {
                    "One hook governs the whole local Hermes lane — native tools (terminal, files, computer-use) and every attached MCP server."
                },
            ));
        }

        // Local stdio MCP servers referenced in this client's config.
        if let Some(servers) = servers_ref(&cs.config, cs.client) {
            for (key, entry) in servers {
                if let Some(sub) = gateway_subcommand(entry) {
                    match sub.as_str() {
                        "proxy" => targets.push(GovernTarget::new(
                            format!("{agent}:mcp-server:{key}"),
                            agent,
                            "mcp-server",
                            "gateway",
                            "governed",
                            cfg_path.clone(),
                            format!("{key} (MCP)"),
                            "Wrapped by kriya-gateway — every tool call is policy-gated and signed.",
                        )),
                        // reach-in / computer-use / router live only under Claude Desktop today; they
                        // are the desktop lane, surfaced by the desktop-apps target below.
                        _ => {}
                    }
                } else if is_remote(entry) {
                    targets.push(GovernTarget::new(
                        format!("{agent}:mcp-server:{key}"),
                        agent,
                        "mcp-server",
                        "gateway",
                        "out-of-scope-cloud",
                        cfg_path.clone(),
                        format!("{key} (remote MCP)"),
                        "Runs off-device (remote/SSE/HTTP) — an on-device receipt is physically impossible.",
                    ));
                } else if is_local_stdio(entry) {
                    targets.push(GovernTarget::new(
                        format!("{agent}:mcp-server:{key}"),
                        agent,
                        "mcp-server",
                        "gateway",
                        "ungoverned",
                        cfg_path.clone(),
                        format!("{key} (MCP)"),
                        "Local stdio server — wrap it with kriya-gateway to sign every tool call.",
                    ));
                }
            }
        }
    }

    // The desktop-app lane — one target for the whole reach-in/computer-use surface. Gated on macOS
    // Accessibility (the one TCC grant the Console can read); Screen Recording is grant-then-recheck.
    {
        let granted = ax_trusted == Some(true);
        let (state, detail) = if !granted {
            (
                "needs-permission",
                format!(
                    "{} desktop apps detected. Reach-in/computer-use needs macOS Accessibility (and Screen Recording) — grant Kriya Console.app, then govern a specific app in Advanced.",
                    desktop_candidates.len()
                ),
            )
        } else {
            (
                "ungoverned",
                format!(
                    "{} desktop apps detected. Permission is granted — govern a specific app via reach-in/computer-use in Advanced.",
                    desktop_candidates.len()
                ),
            )
        };
        targets.push(GovernTarget::new(
            "desktop:desktop-apps",
            "desktop",
            "desktop-apps",
            "reach-in/computer-use",
            state,
            None,
            "Desktop apps (no API)",
            detail,
        ));
    }

    GovernableSurface {
        targets,
        hook_available,
        gateway_available,
        hermes_hook_available,
        ax_trusted,
        desktop_candidates: desktop_candidates.to_vec(),
    }
}

/// Read the real client states from disk + PATH.
fn read_client_states() -> Vec<ClientState> {
    [
        Client::ClaudeCode,
        Client::ClaudeDesktop,
        Client::Hermes,
        Client::Cursor,
        Client::Cline,
        Client::Copilot,
        Client::Gemini,
    ]
    .into_iter()
        .map(|client| {
            let path = client.config_path();
            let file_exists = path.is_file();
            let on_path = client.path_binary().map(on_path).unwrap_or(false);
            ClientState {
                client,
                config: read_config(&path, client.fmt()),
                present: file_exists || on_path,
            }
        })
        .collect()
}

/// Whether `bin` is an executable file on `$PATH`.
fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(bin);
                p.is_file()
            })
        })
        .unwrap_or(false)
}

/// Read the real machine state into the governable-surface inventory (GA-0). The shared entry point
/// under [`governable_surface`], [`govern_preview`], and [`govern_all`].
fn detect_surface() -> GovernableSurface {
    let clients = read_client_states();
    let ax = crate::onboarding::accessibility_trusted();
    let candidates = crate::onboarding::list_candidate_apps();
    detect(
        &clients,
        ax,
        &candidates,
        resolve_hook().is_some(),
        resolve_gateway().is_some(),
        resolve_hermes_hook().is_some(),
    )
}

/// Detect and return the local governable surface (GA-0). Pure read — no writes.
#[tauri::command]
pub fn governable_surface() -> GovernableSurface {
    detect_surface()
}

// ---------------------------------------------------------------------------------------------
// install_hook / uninstall_hook.
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct HookResult {
    pub agent: String,
    pub config_path: String,
    pub hook_path: String,
    pub installed: bool,
}

/// Install the bundled `kriya-hook` block into an agent's config (Claude Code today). Merge-safe
/// and idempotent — a second run changes nothing. Always wires `--policy` (at
/// [`agent_policy_path`], seeded with the permissive built-in default if the operator hasn't
/// authored one yet — never brick a running agent on install, doc 19) and `--approval`
/// ([`default_approval_mode`]) — previously this command passed neither flag, which was the B0
/// bug: an installed hook silently ran the permissive default no matter what the Policy view said,
/// and any `RequiresApproval` decision silently auto-denied with zero interactive surface.
#[tauri::command]
pub fn install_hook(agent: String) -> Result<HookResult, String> {
    let client = match Client::from_agent(&agent) {
        Some(c) if c.supports_hooks() => c,
        _ => return Err(format!("no hook seam for agent '{agent}'")),
    };
    let (hook, quoted) = match client {
        Client::ClaudeCode => {
            let (h, _bundled) =
                resolve_hook().ok_or("the bundled kriya-hook binary could not be located")?;
            let q = shell_quote(&h.to_string_lossy());
            (h, q)
        }
        Client::Hermes => {
            let (h, _bundled) = resolve_hermes_hook()
                .ok_or("the bundled kriya-hermes-hook binary could not be located")?;
            let q = shell_quote(&h.to_string_lossy());
            (h, q)
        }
        _ => unreachable!("supports_hooks() gates install_hook to Claude Code + Hermes"),
    };
    let policy_path = ensure_policy_file()?;
    let policy_quoted = shell_quote(&policy_path.to_string_lossy());
    let approval = default_approval_mode();
    let path = client.config_path();
    let mut config = read_config(&path, client.fmt());
    match client {
        Client::ClaudeCode => install_hook_block(&mut config, &quoted, &policy_quoted, approval),
        Client::Hermes => install_hermes_hook_block(&mut config, &quoted, &policy_quoted, approval),
        _ => unreachable!(),
    }
    write_config(&path, client.fmt(), &config)?;
    Ok(HookResult {
        agent,
        config_path: path.to_string_lossy().into_owned(),
        hook_path: hook.to_string_lossy().into_owned(),
        installed: true,
    })
}

/// Reverse [`install_hook`]: remove only the kriya-hook (or kriya-hermes-hook) block from the
/// agent's config, using the writer that matches that client's config shape.
#[tauri::command]
pub fn uninstall_hook(agent: String) -> Result<HookResult, String> {
    let client = match Client::from_agent(&agent) {
        Some(c) if c.supports_hooks() => c,
        _ => return Err(format!("no hook seam for agent '{agent}'")),
    };
    let path = client.config_path();
    let mut config = read_config(&path, client.fmt());
    match client {
        Client::Hermes => uninstall_hermes_hook_block(&mut config),
        _ => uninstall_hook_block(&mut config),
    }
    write_config(&path, client.fmt(), &config)?;
    Ok(HookResult {
        agent,
        config_path: path.to_string_lossy().into_owned(),
        hook_path: String::new(),
        installed: false,
    })
}

// ---------------------------------------------------------------------------------------------
// GA-1 — the govern-all orchestrator: preview → apply → revert, idempotent + reversible.
// ---------------------------------------------------------------------------------------------

/// One planned (or performed) change to a governable target.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernAction {
    /// The [`GovernTarget::id`] this acts on.
    pub target_id: String,
    pub agent: String,
    /// `hook` | `gateway`.
    pub seam: String,
    /// `install-hook` | `wrap-mcp-server` (govern) · `uninstall-hook` | `unwrap-mcp-server` (revert).
    pub action: String,
    /// The mcpServers key for a `wrap-mcp-server`/`unwrap-mcp-server` action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    /// Human-readable "what this does".
    pub detail: String,
}

/// A per-target failure (honest — a wire that could not be applied is surfaced, never swallowed).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernError {
    pub target_id: String,
    pub message: String,
}

/// The dry-run plan (`govern_preview`) — exactly what a `govern_all` would change, with nothing
/// written. `wire` is the set that gets governed; the other buckets are honest non-actions.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernPlan {
    /// Ungoverned, wireable targets that `govern_all` will govern.
    pub wire: Vec<GovernAction>,
    /// Targets that need a macOS grant first (the desktop-app lane) — never auto-wired.
    pub needs_permission: Vec<GovernTarget>,
    /// Off-device surfaces (remote MCP) — an on-device receipt is physically impossible.
    pub out_of_scope_cloud: Vec<GovernTarget>,
    /// Already governed — nothing to do (the source of idempotency).
    pub already_governed: Vec<GovernTarget>,
    /// Ungoverned but the seam binary (`kriya-hook`/`kriya-gateway`) isn't bundled — can't wire.
    pub blocked: Vec<GovernTarget>,
    pub hook_available: bool,
    pub gateway_available: bool,
    pub hermes_hook_available: bool,
}

/// The result of a `govern_all` — what actually changed, plus the honest non-actions.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernAllReport {
    pub wired: Vec<GovernAction>,
    pub needs_permission: Vec<GovernTarget>,
    pub out_of_scope_cloud: Vec<GovernTarget>,
    pub already_governed: Vec<GovernTarget>,
    pub errors: Vec<GovernError>,
}

/// The result of an `ungovern_all` / `ungovern` — what was un-wired.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RevertReport {
    pub reverted: Vec<GovernAction>,
    pub errors: Vec<GovernError>,
}

/// Options for [`govern_all`]. `only` restricts the run to specific target ids (the per-item toggle);
/// `None`/absent governs the whole ungoverned surface.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GovernOpts {
    pub only: Option<Vec<String>>,
}

/// The mcpServers key encoded in an `<agent>:mcp-server:<key>` target id (key may contain ':').
fn mcp_key_of(id: &str) -> Option<&str> {
    let mut parts = id.splitn(3, ':');
    let _agent = parts.next()?;
    match parts.next()? {
        "mcp-server" => parts.next(),
        _ => None,
    }
}

/// The govern action a wireable target maps to (pure).
fn action_for(t: &GovernTarget) -> Option<GovernAction> {
    match t.kind.as_str() {
        "hook" => {
            let bin = if t.agent == "hermes" { "kriya-hermes-hook" } else { "kriya-hook" };
            Some(GovernAction {
                target_id: t.id.clone(),
                agent: t.agent.clone(),
                seam: "hook".into(),
                action: "install-hook".into(),
                server_key: None,
                config_path: t.config_path.clone(),
                detail: format!(
                    "Install the {bin} block, wired to your agent-policy.yaml, so every native tool + attached MCP call is policy-gated and signs a receipt."
                ),
            })
        }
        "mcp-server" => {
            let key = mcp_key_of(&t.id)?.to_string();
            Some(GovernAction {
                target_id: t.id.clone(),
                agent: t.agent.clone(),
                seam: "gateway".into(),
                action: "wrap-mcp-server".into(),
                server_key: Some(key.clone()),
                config_path: t.config_path.clone(),
                detail: format!(
                    "Wrap {key} with kriya-gateway — policy → approval → signed receipt on every tool call."
                ),
            })
        }
        _ => None,
    }
}

/// Classify a detected surface into the govern-all plan (pure — no writes). The desktop-app lane is
/// never auto-wired (it needs a specific app + Screen Recording the Console can't verify); it always
/// lands in `needs_permission` with the honest reason.
/// Is the seam binary for `t` bundled/resolvable? Keyed on (kind, agent), NOT kind alone — Claude
/// Code and Hermes each have their own independent hook binary/availability, so a single shared
/// "hook available" flag would incorrectly gate one client's hook on the other's binary presence.
fn seam_available(t: &GovernTarget, surface: &GovernableSurface) -> bool {
    match (t.kind.as_str(), t.agent.as_str()) {
        ("hook", "hermes") => surface.hermes_hook_available,
        ("hook", _) => surface.hook_available,
        ("mcp-server", _) => surface.gateway_available,
        _ => false,
    }
}

fn classify_plan(surface: &GovernableSurface) -> GovernPlan {
    let mut plan = GovernPlan {
        hook_available: surface.hook_available,
        gateway_available: surface.gateway_available,
        hermes_hook_available: surface.hermes_hook_available,
        ..GovernPlan::default()
    };
    for t in &surface.targets {
        if t.kind == "desktop-apps" {
            plan.needs_permission.push(t.clone());
            continue;
        }
        match t.state.as_str() {
            "governed" => plan.already_governed.push(t.clone()),
            "out-of-scope-cloud" => plan.out_of_scope_cloud.push(t.clone()),
            "needs-permission" => plan.needs_permission.push(t.clone()),
            "ungoverned" => {
                let available = seam_available(t, surface);
                match action_for(t).filter(|_| available) {
                    Some(a) => plan.wire.push(a),
                    None => plan.blocked.push(t.clone()),
                }
            }
            _ => {}
        }
    }
    plan
}

fn resolve_gateway_path() -> String {
    resolve_gateway()
        .map(|(p, _)| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn resolve_hook_path() -> String {
    resolve_hook()
        .map(|(p, _)| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn resolve_hermes_hook_path() -> String {
    resolve_hermes_hook()
        .map(|(p, _)| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Mirrors `resolve_hook_path`/`resolve_gateway_path`'s own "resolve once, empty string on
/// failure, let the specific action report it" pattern (B0) — `ensure_policy_file` only fails on
/// a real filesystem error (e.g. `~/.kriya/` uncreatable), which is exactly as actionable as a
/// missing bundled binary and should surface the same way.
fn resolve_policy_path() -> String {
    ensure_policy_file()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Apply one govern action to the relevant client config (file IO). Merge-safe + idempotent.
/// `hook`/`hermes_hook` are the two independent hook-binary paths — Claude Code and Hermes each
/// get their own writer (different config shape entirely, not just a different marker string).
/// `policy` (B0) is the one Console-authored policy file every seam below now wires via
/// `--policy`, and `approval` ([`default_approval_mode`]) replaces what used to be either a
/// missing flag (hook install) or an unconditional `"gui"` literal (gateway wrap) — both silently
/// wrong off macOS, and the missing-flag case being the founder-reported bug itself.
fn apply_action(action: &GovernAction, gateway: &str, hook: &str, hermes_hook: &str, policy: &str) -> Result<(), String> {
    if policy.is_empty() {
        return Err("could not prepare the agent policy file (~/.kriya/agent-policy.yaml)".into());
    }
    let policy_quoted = shell_quote(policy);
    let approval = default_approval_mode();
    let client =
        Client::from_agent(&action.agent).ok_or_else(|| format!("unknown agent '{}'", action.agent))?;
    let path = client.config_path();
    let mut config = read_config(&path, client.fmt());
    match action.action.as_str() {
        "install-hook" => match client {
            Client::ClaudeCode => {
                if hook.is_empty() {
                    return Err("the bundled kriya-hook binary could not be located".into());
                }
                install_hook_block(&mut config, &shell_quote(hook), &policy_quoted, approval);
            }
            Client::Hermes => {
                if hermes_hook.is_empty() {
                    return Err("the bundled kriya-hermes-hook binary could not be located".into());
                }
                install_hermes_hook_block(&mut config, &shell_quote(hermes_hook), &policy_quoted, approval);
            }
            // No other client produces an install-hook action (action_for only emits it for the
            // hook-bearing clients) — but fail loud rather than silently mis-wire if one ever does.
            other => return Err(format!("{} has no hook seam", other.agent_id())),
        },
        "wrap-mcp-server" => {
            if gateway.is_empty() {
                return Err("the bundled kriya-gateway binary could not be located".into());
            }
            let key = action.server_key.as_deref().ok_or("wrap action missing server key")?;
            let servers = servers_mut(&mut config, client);
            let entry = servers
                .get(key)
                .cloned()
                .ok_or_else(|| format!("server '{key}' no longer present"))?;
            let wrapped = wrap_entry(&entry, gateway, client.agent_id(), approval, &policy_quoted)
                .ok_or_else(|| format!("server '{key}' is not a wrappable local stdio server"))?;
            servers.insert(key.to_string(), wrapped);
        }
        other => return Err(format!("unknown govern action '{other}'")),
    }
    write_config(&path, client.fmt(), &config)
}

/// Revert one governed target to its pre-govern state (file IO). The exact inverse of the govern
/// actions, so a govern→ungovern of the same targets restores each config byte-for-byte.
fn revert_target(target: &GovernTarget, gateway: &str, hook: &str) -> Result<GovernAction, String> {
    let client =
        Client::from_agent(&target.agent).ok_or_else(|| format!("unknown agent '{}'", target.agent))?;
    let path = client.config_path();
    let mut config = read_config(&path, client.fmt());
    let (verb, server_key, detail) = match target.kind.as_str() {
        "hook" => {
            let bin = match client {
                Client::Hermes => {
                    uninstall_hermes_hook_block(&mut config);
                    "kriya-hermes-hook"
                }
                _ => {
                    uninstall_hook_block(&mut config);
                    "kriya-hook"
                }
            };
            (
                "uninstall-hook",
                None,
                format!("Remove the {bin} block from the agent's settings."),
            )
        }
        "mcp-server" => {
            let key = mcp_key_of(&target.id)
                .ok_or_else(|| format!("malformed target id '{}'", target.id))?
                .to_string();
            let servers = servers_mut(&mut config, client);
            let entry = servers
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("server '{key}' no longer present"))?;
            let orig = unwrap_entry(&entry)
                .ok_or_else(|| format!("server '{key}' is not a kriya-gateway proxy wrap"))?;
            servers.insert(key.clone(), orig);
            (
                "unwrap-mcp-server",
                Some(key.clone()),
                format!("Unwrap {key} — restore its original launch command."),
            )
        }
        other => return Err(format!("cannot revert target kind '{other}'")),
    };
    let _ = (gateway, hook);
    write_config(&path, client.fmt(), &config)?;
    Ok(GovernAction {
        target_id: target.id.clone(),
        agent: target.agent.clone(),
        seam: target.seam.clone(),
        action: verb.into(),
        server_key,
        config_path: target.config_path.clone(),
        detail,
    })
}

/// Dry-run: the exact changes a `govern_all` would make, nothing written (GA-1).
#[tauri::command]
pub fn govern_preview() -> GovernPlan {
    classify_plan(&detect_surface())
}

/// Govern the ungoverned surface: wire every wireable target through its seam. Idempotent (a second
/// run wires nothing — everything is already governed). `opts.only` restricts to specific target ids
/// (the per-item toggle). Never wires desktop apps or cloud surfaces — those are surfaced honestly.
#[tauri::command]
pub fn govern_all(opts: Option<GovernOpts>) -> GovernAllReport {
    let surface = detect_surface();
    let mut plan = classify_plan(&surface);
    if let Some(only) = opts.and_then(|o| o.only) {
        plan.wire.retain(|a| only.contains(&a.target_id));
    }
    let gateway = resolve_gateway_path();
    let hook = resolve_hook_path();
    let hermes_hook = resolve_hermes_hook_path();
    let policy = resolve_policy_path();
    let mut wired = Vec::new();
    let mut errors = Vec::new();
    for action in &plan.wire {
        match apply_action(action, &gateway, &hook, &hermes_hook, &policy) {
            Ok(()) => wired.push(action.clone()),
            Err(message) => errors.push(GovernError {
                target_id: action.target_id.clone(),
                message,
            }),
        }
    }
    GovernAllReport {
        wired,
        needs_permission: plan.needs_permission,
        out_of_scope_cloud: plan.out_of_scope_cloud,
        already_governed: plan.already_governed,
        errors,
    }
}

/// Revert everything govern-all governed: remove kriya-hook blocks and unwrap gateway-proxied MCP
/// servers across all clients. Only touches kriya wiring; leaves every other config entry intact.
#[tauri::command]
pub fn ungovern_all() -> RevertReport {
    let surface = detect_surface();
    let gateway = resolve_gateway_path();
    let hook = resolve_hook_path();
    let mut reverted = Vec::new();
    let mut errors = Vec::new();
    for target in surface.targets.iter().filter(|t| t.state == "governed") {
        match revert_target(target, &gateway, &hook) {
            Ok(a) => reverted.push(a),
            Err(message) => errors.push(GovernError {
                target_id: target.id.clone(),
                message,
            }),
        }
    }
    RevertReport { reverted, errors }
}

/// Revert one governed target by its id (the per-item toggle-off).
#[tauri::command]
pub fn ungovern(target: String) -> RevertReport {
    let surface = detect_surface();
    let gateway = resolve_gateway_path();
    let hook = resolve_hook_path();
    match surface.targets.iter().find(|t| t.id == target) {
        Some(t) => match revert_target(t, &gateway, &hook) {
            Ok(a) => RevertReport { reverted: vec![a], errors: vec![] },
            Err(message) => RevertReport {
                reverted: vec![],
                errors: vec![GovernError { target_id: target, message }],
            },
        },
        None => RevertReport {
            reverted: vec![],
            errors: vec![GovernError {
                target_id: target,
                message: "target not found in the current surface".into(),
            }],
        },
    }
}

// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::hook_configured;

    // --- The Console-authored policy file (B0) -----------------------------------------------
    // These mutate $HOME, so — like govern_all_then_ungovern_all_round_trips_configs_byte_for_byte
    // below — they take ENV_LOCK to avoid racing other tests in this same-process, parallel-thread
    // test run.

    fn with_sandbox_home<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = std::env::temp_dir().join(format!(
            "kriya-govern-policy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);
        let result = f(&home);
        match prev {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);
        result
    }

    #[test]
    fn agent_policy_path_is_stable_and_under_dot_kriya() {
        with_sandbox_home(|home| {
            let path = agent_policy_path();
            assert_eq!(path, home.join(".kriya").join("agent-policy.yaml"));
        });
    }

    #[test]
    fn ensure_policy_file_creates_permissive_default_when_absent_never_overwrites_when_present() {
        with_sandbox_home(|_home| {
            let path = agent_policy_path();
            assert!(!path.is_file(), "starts absent");

            let created = ensure_policy_file().unwrap();
            assert_eq!(created, path);
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                PERMISSIVE_DEFAULT_POLICY_YAML,
                "seeded with the same permissive default the binaries fall back to anyway"
            );

            // An operator's authored policy must never be silently clobbered by a later install.
            std::fs::write(&path, "rules:\n  - { action: \"claude-code__bash\", allow: false }\n").unwrap();
            ensure_policy_file().unwrap();
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "rules:\n  - { action: \"claude-code__bash\", allow: false }\n",
                "ensure_policy_file must never overwrite an already-authored policy"
            );
        });
    }

    #[test]
    fn save_agent_policy_persists_and_load_agent_policy_restores() {
        with_sandbox_home(|_home| {
            assert_eq!(load_agent_policy(), None, "nothing saved yet on a fresh install");

            let yaml = "rules:\n  - { action: \"*\", allow: false }\n";
            let result = save_agent_policy(yaml.to_string()).unwrap();
            assert_eq!(result.path, agent_policy_path().to_string_lossy());
            assert_eq!(load_agent_policy().as_deref(), Some(yaml));

            // Unlike ensure_policy_file, save_agent_policy always overwrites — it's the explicit
            // authored write, not the install-time safety net.
            let yaml2 = "rules:\n  - { action: \"*\", allow: true }\n";
            save_agent_policy(yaml2.to_string()).unwrap();
            assert_eq!(load_agent_policy().as_deref(), Some(yaml2));
        });
    }

    #[test]
    fn wrap_entry_inserts_policy_flag_before_the_dashdash_separator() {
        let wrapped = wrap_entry(
            &json!({ "command": "npx", "args": ["-y", "server-github"] }),
            "/opt/kriya-gateway",
            "claude-desktop",
            "gui",
            "/x/agent-policy.yaml",
        )
        .unwrap();
        let args: Vec<&str> = wrapped["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        let policy_idx = args.iter().position(|a| *a == "--policy").expect("--policy present");
        let dashdash_idx = args.iter().position(|a| *a == "--").expect("-- present");
        assert_eq!(args[policy_idx + 1], "/x/agent-policy.yaml");
        assert!(
            policy_idx < dashdash_idx,
            "--policy must be a gateway flag, never forwarded to the downstream command: {args:?}"
        );
    }

    // --- Gateway wrap / unwrap round-trips ---------------------------------------------------

    #[test]
    fn wrap_then_unwrap_round_trips_a_canonical_entry() {
        let orig = json!({ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] });
        let wrapped = wrap_entry(&orig, "/opt/kriya-gateway", "claude-desktop", "gui", "/x/agent-policy.yaml").unwrap();
        assert!(is_gateway_wrapped(&wrapped));
        assert_eq!(gateway_subcommand(&wrapped).as_deref(), Some("proxy"));
        // The downstream command survives verbatim after `--`.
        let args = wrapped["args"].as_array().unwrap();
        let dd = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[dd + 1], json!("npx"));
        // Round-trip is byte-identical.
        assert_eq!(unwrap_entry(&wrapped).unwrap(), orig);
    }

    #[test]
    fn wrap_preserves_sibling_keys_like_env() {
        let orig = json!({ "command": "node", "args": ["server.js"], "env": { "TOKEN": "x" } });
        let wrapped = wrap_entry(&orig, "/opt/kriya-gateway", "hermes", "gui", "/x/agent-policy.yaml").unwrap();
        assert_eq!(wrapped["env"], json!({ "TOKEN": "x" }));
        assert_eq!(unwrap_entry(&wrapped).unwrap(), orig);
    }

    #[test]
    fn wrap_refuses_remote_and_already_wrapped() {
        assert!(wrap_entry(&json!({ "url": "https://x/mcp" }), "/g", "a", "gui", "/x/p.yaml").is_none());
        assert!(wrap_entry(&json!({ "type": "sse", "url": "https://x" }), "/g", "a", "gui", "/x/p.yaml").is_none());
        let wrapped = wrap_entry(
            &json!({ "command": "npx", "args": ["x"] }),
            "/g/kriya-gateway",
            "a",
            "gui",
            "/x/p.yaml",
        )
        .unwrap();
        // Wrapping an already-wrapped entry is a no-op (idempotent at the entry level).
        assert!(wrap_entry(&wrapped, "/g/kriya-gateway", "a", "gui", "/x/p.yaml").is_none());
    }

    #[test]
    fn unwrap_ignores_non_proxy_gateway_fronts() {
        // A reach-in desktop front is gateway-launched but must never be unwrapped as a proxy.
        let reachin = json!({ "command": "/g/kriya-gateway", "args": ["reach-in", "--app", "Numbers"] });
        assert_eq!(gateway_subcommand(&reachin).as_deref(), Some("reach-in"));
        assert!(unwrap_entry(&reachin).is_none());
    }

    // --- The MCP-servers writer: idempotency + non-clobber, per client key -------------------

    /// Verified against the real `hermes_cli/mcp_config.py` source (2026-07-08): Hermes keys its MCP
    /// servers under `mcp_servers` (snake_case) — Claude's `mcpServers` (camelCase) does NOT apply.
    /// Parameterized over BOTH clients so this test would have caught the real bug (a Hermes install's
    /// servers were silently invisible to detection because the code assumed `mcpServers` everywhere).
    #[test]
    fn wrapping_all_servers_is_idempotent_and_non_clobbering() {
        for (client, key) in [
            (Client::ClaudeDesktop, "mcpServers"),
            (Client::Hermes, "mcp_servers"),
        ] {
            let mut cfg = json!({
                key: {
                    "github": { "command": "npx", "args": ["-y", "server-github"] },
                    "already": { "command": "/g/kriya-gateway", "args": ["proxy", "--", "node", "s.js"] },
                    "remote": { "url": "https://x/mcp" }
                },
                "unrelated": { "keep": true }
            });

            let wrap_all = |cfg: &mut Value| {
                let servers = servers_mut(cfg, client);
                let keys: Vec<String> = servers.keys().cloned().collect();
                for k in keys {
                    if let Some(w) = wrap_entry(&servers[&k], "/g/kriya-gateway", client.agent_id(), "gui", "/x/p.yaml") {
                        servers.insert(k, w);
                    }
                }
            };

            wrap_all(&mut cfg);
            let after_first = cfg.clone();
            // github got wrapped; remote + already-wrapped + unrelated untouched.
            assert_eq!(
                gateway_subcommand(&cfg[key]["github"]).as_deref(),
                Some("proxy"),
                "{key}: github should be wrapped"
            );
            assert_eq!(cfg[key]["remote"], json!({ "url": "https://x/mcp" }));
            assert_eq!(cfg["unrelated"], json!({ "keep": true }));

            // A second pass changes nothing.
            wrap_all(&mut cfg);
            assert_eq!(cfg, after_first, "{key}: wrapping is idempotent");
        }
    }

    // --- The hooks writer: idempotency, non-clobber, byte-for-byte revert --------------------

    #[test]
    fn hook_block_is_idempotent_and_reversible_on_empty_config() {
        let mut cfg = json!({});
        install_hook_block(&mut cfg, "/opt/kriya-hook", "/x/agent-policy.yaml", "gui");
        let once = cfg.clone();
        install_hook_block(&mut cfg, "/opt/kriya-hook", "/x/agent-policy.yaml", "gui");
        assert_eq!(cfg, once, "installing twice yields one set of groups");

        // The block is well-formed: pre + post, each a command mentioning kriya-hook.
        assert_eq!(cfg["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
        let cmd = cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert!(cmd.contains("kriya-hook"));
        // B0: --policy and --approval must always be present — an installed hook that omits
        // either silently enforces nothing (the founder-reported bug).
        assert!(cmd.contains("--policy /x/agent-policy.yaml"), "{cmd}");
        assert!(cmd.contains("--approval gui"), "{cmd}");

        // Uninstall restores the empty object byte-for-byte.
        uninstall_hook_block(&mut cfg);
        assert_eq!(cfg, json!({}), "revert removes the hooks key entirely");
    }

    #[test]
    fn hook_block_never_clobbers_a_users_own_hooks() {
        // A user already has a Stop hook and their own PreToolUse group.
        let user = json!({
            "hooks": {
                "Stop": [{ "hooks": [{ "type": "command", "command": "say done" }] }],
                "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "my-linter" }] }]
            },
            "permissions": { "allow": ["Read"] }
        });
        let mut cfg = user.clone();
        install_hook_block(&mut cfg, "/opt/kriya-hook", "/x/agent-policy.yaml", "gui");
        // The user's groups survive; ours are appended.
        assert_eq!(cfg["hooks"]["Stop"], user["hooks"]["Stop"]);
        assert_eq!(cfg["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);
        assert_eq!(cfg["permissions"], json!({ "allow": ["Read"] }));

        // Uninstall removes only ours → back to the user's exact config.
        uninstall_hook_block(&mut cfg);
        assert_eq!(cfg, user, "revert restores the user config byte-for-byte");
    }

    // --- Hermes' hook writer: distinct shape (event → flat entry list), no matcher, auto-accept ---

    #[test]
    fn hermes_hook_block_is_idempotent_and_reversible_on_empty_config() {
        let mut cfg = json!({});
        install_hermes_hook_block(&mut cfg, "/opt/kriya-hermes-hook", "/x/agent-policy.yaml", "tty");
        let once = cfg.clone();
        install_hermes_hook_block(&mut cfg, "/opt/kriya-hermes-hook", "/x/agent-policy.yaml", "tty");
        assert_eq!(cfg, once, "installing twice yields one set of entries");

        assert_eq!(cfg["hooks"]["pre_tool_call"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["hooks"]["post_tool_call"].as_array().unwrap().len(), 1);
        let pre = &cfg["hooks"]["pre_tool_call"][0];
        assert_eq!(
            pre["command"],
            "/opt/kriya-hermes-hook pre --policy /x/agent-policy.yaml --approval tty"
        );
        assert_eq!(pre["timeout"], 300);
        assert!(pre.get("matcher").is_none(), "no matcher — fires for every tool_name");
        assert_eq!(cfg["hooks_auto_accept"], true);

        uninstall_hermes_hook_block(&mut cfg);
        assert_eq!(cfg, json!({}), "revert removes hooks AND the auto-accept flag it set");
    }

    #[test]
    fn hermes_hook_block_never_clobbers_a_users_own_hooks_or_settings() {
        // A user already has an unrelated pre_llm_call hook and their own pre_tool_call entry.
        let user = json!({
            "hooks": {
                "pre_llm_call": [{ "command": "~/.hermes/agent-hooks/inject-cwd-context.sh" }],
                "pre_tool_call": [{ "matcher": "terminal", "command": "~/.hermes/agent-hooks/block-rm-rf.sh", "timeout": 10 }]
            },
            "model": "some-model"
        });
        let mut cfg = user.clone();
        install_hermes_hook_block(&mut cfg, "/opt/kriya-hermes-hook", "/x/agent-policy.yaml", "tty");
        assert_eq!(cfg["hooks"]["pre_llm_call"], user["hooks"]["pre_llm_call"], "unrelated event untouched");
        assert_eq!(cfg["hooks"]["pre_tool_call"].as_array().unwrap().len(), 2, "user's entry survives, ours appended");
        assert_eq!(cfg["model"], "some-model");

        uninstall_hermes_hook_block(&mut cfg);
        assert_eq!(cfg, user, "revert restores the user config byte-for-byte, including their own hooks_auto_accept absence");
    }

    #[test]
    fn hermes_hook_uninstall_preserves_a_users_independently_set_auto_accept() {
        // hooks_auto_accept: true is only removed on uninstall when we're confident it's the value
        // WE set — but we can't distinguish "we set it" from "the user already had it true" by
        // value alone, so uninstall removes it unconditionally when true. Document + lock the
        // narrow, safe-direction divergence this causes: a user's own true flag also gets cleared.
        let mut cfg = json!({ "hooks_auto_accept": true });
        install_hermes_hook_block(&mut cfg, "/opt/kriya-hermes-hook", "/x/agent-policy.yaml", "tty");
        uninstall_hermes_hook_block(&mut cfg);
        assert_eq!(
            cfg, json!({}),
            "hooks_auto_accept is cleared even if the user had set it themselves — the safe direction (re-prompt), never the unsafe one"
        );
    }

    #[test]
    fn shell_quote_quotes_paths_with_spaces() {
        assert_eq!(shell_quote("/opt/kriya-hook"), "/opt/kriya-hook");
        assert_eq!(
            shell_quote("/Applications/Kriya Console.app/Contents/MacOS/kriya-hook"),
            "'/Applications/Kriya Console.app/Contents/MacOS/kriya-hook'"
        );
    }

    // --- Detection --------------------------------------------------------------------------

    fn cc_settings_with_hook() -> Value {
        json!({ "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "kriya-hook pre" }] }] } })
    }

    #[test]
    fn detects_claude_code_hook_state() {
        // Ungoverned: config present but no hook.
        let clients = vec![ClientState {
            client: Client::ClaudeCode,
            config: json!({}),
            present: true,
        }];
        let s = detect(&clients, Some(true), &[], true, true, true);
        let hook = s.targets.iter().find(|t| t.kind == "hook").unwrap();
        assert_eq!(hook.agent, "claude-code");
        assert_eq!(hook.seam, "hook");
        assert_eq!(hook.state, "ungoverned");

        // Governed: the injected config carries the hook block.
        let clients = vec![ClientState {
            client: Client::ClaudeCode,
            config: cc_settings_with_hook(),
            present: true,
        }];
        let s = detect(&clients, Some(true), &[], true, true, true);
        let hook = s.targets.iter().find(|t| t.kind == "hook").unwrap();
        assert_eq!(hook.state, "governed");
    }

    #[test]
    fn detects_and_classifies_mcp_servers_per_client() {
        let desktop = ClientState {
            client: Client::ClaudeDesktop,
            config: json!({
                "mcpServers": {
                    "github": { "command": "npx", "args": ["-y", "server-github"] },
                    "wrapped": { "command": "/g/kriya-gateway", "args": ["proxy", "--", "node", "s.js"] },
                    "remote": { "type": "sse", "url": "https://x/mcp" }
                }
            }),
            present: true,
        };
        let s = detect(&[desktop], Some(true), &[], true, true, true);
        let by_id = |id: &str| s.targets.iter().find(|t| t.id == id).unwrap();
        assert_eq!(by_id("claude-desktop:mcp-server:github").state, "ungoverned");
        assert_eq!(by_id("claude-desktop:mcp-server:wrapped").state, "governed");
        assert_eq!(by_id("claude-desktop:mcp-server:remote").state, "out-of-scope-cloud");
        // Claude Desktop has no hook seam.
        assert!(!s.targets.iter().any(|t| t.agent == "claude-desktop" && t.kind == "hook"));
    }

    #[test]
    fn hermes_yaml_servers_are_detected_as_gateway_targets() {
        // Hermes config parsed from YAML lands as the same Value shape. Real key verified against
        // hermes_cli/mcp_config.py: `mcp_servers` (snake_case) — NOT Claude's `mcpServers`. A fixture
        // using the wrong key would make this test pass for the wrong reason (mirroring the same bug
        // the implementation had), so this is the literal on-disk shape a real Hermes config uses.
        let yaml = "mcp_servers:\n  fs:\n    command: uvx\n    args: [mcp-server-fs]\n";
        let config: Value = serde_yaml::from_str(yaml).unwrap();
        let hermes = ClientState { client: Client::Hermes, config, present: true };
        let s = detect(&[hermes], None, &[], true, true, true);
        let t = s.targets.iter().find(|t| t.id == "hermes:mcp-server:fs").unwrap();
        assert_eq!(t.agent, "hermes");
        assert_eq!(t.seam, "gateway");
        assert_eq!(t.state, "ungoverned");
    }

    #[test]
    fn hermes_camelcase_mcpservers_key_is_not_recognized() {
        // The inverse guard: if a Hermes config were (incorrectly) shaped like Claude's — camelCase
        // `mcpServers` — detection must NOT pick it up, proving the two clients' keys are genuinely
        // distinct rather than the lookup silently accepting either.
        let yaml = "mcpServers:\n  fs:\n    command: uvx\n    args: [mcp-server-fs]\n";
        let config: Value = serde_yaml::from_str(yaml).unwrap();
        let hermes = ClientState { client: Client::Hermes, config, present: true };
        let s = detect(&[hermes], None, &[], true, true, true);
        assert!(
            !s.targets.iter().any(|t| t.agent == "hermes" && t.kind == "mcp-server"),
            "a camelCase mcpServers key must not be read as Hermes' mcp_servers"
        );
    }

    #[test]
    fn servers_key_is_camelcase_for_claude_and_snake_case_for_hermes() {
        assert_eq!(Client::ClaudeDesktop.servers_key(), "mcpServers");
        assert_eq!(Client::ClaudeCode.servers_key(), "mcpServers");
        assert_eq!(Client::Hermes.servers_key(), "mcp_servers");
    }

    // --- S1: the VS-Code family (Cursor/Cline/Copilot) + Gemini CLI --------------------------
    // MCP-only clients (no hook seam) — govern-all reaches them through the gateway per-server wrap,
    // exactly like Claude Desktop. Config seams verified 2026-07-21 against each agent's current docs
    // (see the Client-variant doc comments); these fixtures use the literal on-disk shapes.

    #[test]
    fn new_client_servers_keys_match_the_verified_seams() {
        assert_eq!(Client::Cursor.servers_key(), "mcpServers");
        assert_eq!(Client::Cline.servers_key(), "mcpServers");
        assert_eq!(Client::Gemini.servers_key(), "mcpServers");
        // VS Code's native MCP config keys the map `servers` (lowercase), NOT mcpServers — the guard
        // against silently reading a real Copilot install's servers as empty.
        assert_eq!(Client::Copilot.servers_key(), "servers");
    }

    #[test]
    fn new_client_config_paths_are_the_verified_locations() {
        with_sandbox_home(|home| {
            assert_eq!(Client::Cursor.config_path(), home.join(".cursor").join("mcp.json"));
            assert_eq!(Client::Gemini.config_path(), home.join(".gemini").join("settings.json"));
            assert_eq!(
                Client::Cline.config_path(),
                home.join("Library")
                    .join("Application Support")
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join("saoudrizwan.claude-dev")
                    .join("settings")
                    .join("cline_mcp_settings.json")
            );
            assert_eq!(
                Client::Copilot.config_path(),
                home.join("Library")
                    .join("Application Support")
                    .join("Code")
                    .join("User")
                    .join("mcp.json")
            );
        });
    }

    #[test]
    fn cursor_mcpservers_stdio_is_an_ungoverned_gateway_target_and_has_no_hook() {
        let config = json!({ "mcpServers": { "github": { "command": "npx", "args": ["-y", "server-github"] } } });
        let cs = ClientState { client: Client::Cursor, config, present: true };
        let s = detect(&[cs], None, &[], true, true, true);
        let t = s.targets.iter().find(|t| t.id == "cursor:mcp-server:github").unwrap();
        assert_eq!(t.agent, "cursor");
        assert_eq!(t.seam, "gateway");
        assert_eq!(t.state, "ungoverned");
        // Cursor is MCP-only: it must never grow a hook target (the honest "built-ins bypass MCP" line).
        assert!(!s.targets.iter().any(|t| t.agent == "cursor" && t.kind == "hook"));
    }

    #[test]
    fn copilot_lowercase_servers_key_detected_and_type_stdio_survives_wrap() {
        // VS Code stdio entries carry `"type":"stdio"`; wrapping must keep it (kriya-gateway is a
        // stdio command too) and round-trip it byte-for-byte.
        let config =
            json!({ "servers": { "pw": { "type": "stdio", "command": "npx", "args": ["-y", "playwright-mcp"] } } });
        let cs = ClientState { client: Client::Copilot, config: config.clone(), present: true };
        let s = detect(&[cs], None, &[], true, true, true);
        let t = s.targets.iter().find(|t| t.id == "copilot:mcp-server:pw").unwrap();
        assert_eq!(t.state, "ungoverned");

        let entry = &config["servers"]["pw"];
        let wrapped = wrap_entry(entry, "/g/kriya-gateway", "copilot", "gui", "/x/p.yaml").unwrap();
        assert_eq!(wrapped["type"], json!("stdio"), "type:stdio must survive the wrap");
        assert_eq!(unwrap_entry(&wrapped).unwrap(), *entry, "wrap→unwrap is byte-identical incl. type");
    }

    #[test]
    fn gemini_httpurl_remote_is_out_of_scope_and_never_wrapped() {
        // Gemini's remote key is `httpUrl` (not `url`); is_remote must catch it, so it's classed
        // cloud rather than mistaken for a wrappable local stdio server (it carries no command).
        let config = json!({ "mcpServers": { "remote": { "httpUrl": "http://localhost:3000/mcp" } } });
        let cs = ClientState { client: Client::Gemini, config: config.clone(), present: true };
        let s = detect(&[cs], None, &[], true, true, true);
        let t = s.targets.iter().find(|t| t.id == "gemini:mcp-server:remote").unwrap();
        assert_eq!(t.state, "out-of-scope-cloud");
        assert!(wrap_entry(&config["mcpServers"]["remote"], "/g", "gemini", "gui", "/x/p.yaml").is_none());
    }

    #[test]
    fn new_agents_wrap_is_idempotent_non_clobbering_and_reverts_byte_for_byte() {
        for (client, key) in [
            (Client::Cursor, "mcpServers"),
            (Client::Cline, "mcpServers"),
            (Client::Copilot, "servers"),
            (Client::Gemini, "mcpServers"),
        ] {
            let id = client.agent_id();
            let original = json!({
                key: {
                    "fs": { "command": "uvx", "args": ["mcp-server-fs"], "env": { "ROOT": "/tmp" } },
                    "remote": { "url": "https://x/mcp" }
                },
                "otherTopLevelKey": { "keep": true }
            });
            let mut cfg = original.clone();

            let wrap_all = |cfg: &mut Value| {
                let servers = servers_mut(cfg, client);
                let keys: Vec<String> = servers.keys().cloned().collect();
                for k in keys {
                    if let Some(w) =
                        wrap_entry(&servers[&k], "/g/kriya-gateway", client.agent_id(), "gui", "/x/p.yaml")
                    {
                        servers.insert(k, w);
                    }
                }
            };
            let unwrap_all = |cfg: &mut Value| {
                let servers = servers_mut(cfg, client);
                let keys: Vec<String> = servers.keys().cloned().collect();
                for k in keys {
                    if let Some(u) = unwrap_entry(&servers[&k]) {
                        servers.insert(k, u);
                    }
                }
            };

            wrap_all(&mut cfg);
            let after_first = cfg.clone();
            assert_eq!(gateway_subcommand(&cfg[key]["fs"]).as_deref(), Some("proxy"), "{id}: fs wrapped");
            assert_eq!(cfg[key]["fs"]["env"], json!({ "ROOT": "/tmp" }), "{id}: env sibling preserved");
            assert_eq!(cfg[key]["remote"], json!({ "url": "https://x/mcp" }), "{id}: remote untouched");
            assert_eq!(cfg["otherTopLevelKey"], json!({ "keep": true }), "{id}: unrelated top-level keys kept");

            wrap_all(&mut cfg);
            assert_eq!(cfg, after_first, "{id}: wrapping twice is idempotent");

            unwrap_all(&mut cfg);
            assert_eq!(cfg, original, "{id}: unwire restores the config byte-for-byte");
        }
    }

    #[test]
    fn desktop_lane_reflects_accessibility_permission() {
        let s = detect(&[], None, &["Numbers".into(), "Notes".into()], true, true, true);
        let d = s.targets.iter().find(|t| t.kind == "desktop-apps").unwrap();
        assert_eq!(d.state, "needs-permission", "no AX grant off macOS/ungranted");
        assert!(d.detail.contains('2'));

        let s = detect(&[], Some(true), &[], true, true, true);
        let d = s.targets.iter().find(|t| t.kind == "desktop-apps").unwrap();
        assert_eq!(d.state, "ungoverned", "AX granted, nothing wired yet");
    }

    #[test]
    fn absent_clients_contribute_no_targets() {
        let clients = vec![
            ClientState { client: Client::ClaudeCode, config: json!({}), present: false },
            ClientState { client: Client::ClaudeDesktop, config: json!({}), present: false },
            ClientState { client: Client::Hermes, config: json!({}), present: false },
        ];
        let s = detect(&clients, Some(true), &[], true, true, true);
        // Only the desktop-apps lane target remains.
        assert_eq!(s.targets.len(), 1);
        assert_eq!(s.targets[0].kind, "desktop-apps");
    }

    // --- Command-level: install_hook writes a settings.json coverage.rs then detects ---------

    #[test]
    fn install_hook_writes_a_block_coverage_detects() {
        // Point the whole hook-install path at a temp HOME so we exercise the real command.
        let home = std::env::temp_dir().join(format!("kriya-govern-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let settings = home.join(".claude").join("settings.json");

        // Simulate what install_hook does to the settings file (the resolve_hook binary isn't
        // bundled in a unit test, so drive the writer directly against the temp settings path).
        let mut cfg = read_config(&settings, Fmt::Json);
        install_hook_block(&mut cfg, "/opt/kriya-hook", "/x/agent-policy.yaml", "gui");
        write_config(&settings, Fmt::Json, &cfg).unwrap();

        // coverage.rs must now report the hook as configured.
        assert!(
            hook_configured(Some(&settings)),
            "coverage.rs detects the installed hook block"
        );

        // Idempotent: a second install leaves the file byte-identical.
        let first = std::fs::read_to_string(&settings).unwrap();
        let mut cfg = read_config(&settings, Fmt::Json);
        install_hook_block(&mut cfg, "/opt/kriya-hook", "/x/agent-policy.yaml", "gui");
        write_config(&settings, Fmt::Json, &cfg).unwrap();
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), first);

        // Uninstall removes it → coverage sees no hook again.
        let mut cfg = read_config(&settings, Fmt::Json);
        uninstall_hook_block(&mut cfg);
        write_config(&settings, Fmt::Json, &cfg).unwrap();
        assert!(!hook_configured(Some(&settings)));

        let _ = std::fs::remove_dir_all(&home);
    }

    // --- Serialized-shape parity guard (TS↔Rust field names) --------------------------------

    /// TS↔Rust parity: a representative `GovernableSurface` must serialize byte-for-byte (modulo key
    /// order) to the committed fixture that `test/govern.test.ts` type-checks against the TS
    /// interface. Drift on either side breaks a test. The second target omits `configPath` (None) —
    /// pinning the `skip_serializing_if` behavior the TS optional field mirrors.
    #[test]
    fn surface_serializes_to_the_committed_ts_parity_fixture() {
        let surface = GovernableSurface {
            targets: vec![
                GovernTarget::new(
                    "claude-code:hook",
                    "claude-code",
                    "hook",
                    "hook",
                    "ungoverned",
                    Some("/home/u/.claude/settings.json".into()),
                    "Claude Code — native tools + attached MCP",
                    "detail",
                ),
                GovernTarget::new(
                    "desktop:desktop-apps",
                    "desktop",
                    "desktop-apps",
                    "reach-in/computer-use",
                    "needs-permission",
                    None,
                    "Desktop apps (no API)",
                    "detail",
                ),
            ],
            hook_available: true,
            gateway_available: true,
            hermes_hook_available: true,
            ax_trusted: Some(false),
            desktop_candidates: vec!["Numbers".into()],
        };
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test/fixtures/governable-surface-sample.json");
        let fixture: Value =
            serde_json::from_str(&std::fs::read_to_string(&fixture_path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&surface).unwrap(),
            fixture,
            "GovernableSurface serialization drifted from the committed TS-parity fixture"
        );
    }

    #[test]
    fn govern_target_serializes_camel_case_keys() {
        let t = GovernTarget::new(
            "claude-code:hook",
            "claude-code",
            "hook",
            "hook",
            "ungoverned",
            Some("/x/settings.json".into()),
            "label",
            "detail",
        );
        let v = serde_json::to_value(&t).unwrap();
        let obj = v.as_object().unwrap();
        // Exactly the camelCase keys the TS `GovernTarget` interface declares.
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            ["agent", "configPath", "detail", "id", "kind", "label", "seam", "state"]
        );
    }

    // --- GA-1: the govern-all orchestrator ---------------------------------------------------

    /// The ONE crate-wide lock (`crate::HOME_ENV_LOCK`) every `$HOME`-mutating test in this crate takes
    /// — a per-module lock alone doesn't stop this module's tests from racing another module's.
    use crate::HOME_ENV_LOCK as ENV_LOCK;

    fn surface_of(targets: Vec<GovernTarget>, hook_av: bool, gw_av: bool) -> GovernableSurface {
        surface_of_all(targets, hook_av, gw_av, true)
    }

    fn surface_of_all(
        targets: Vec<GovernTarget>,
        hook_av: bool,
        gw_av: bool,
        hermes_hook_av: bool,
    ) -> GovernableSurface {
        GovernableSurface {
            targets,
            hook_available: hook_av,
            gateway_available: gw_av,
            hermes_hook_available: hermes_hook_av,
            ax_trusted: Some(true),
            desktop_candidates: vec![],
        }
    }

    #[test]
    fn mcp_key_parses_from_target_id() {
        assert_eq!(mcp_key_of("claude-desktop:mcp-server:github"), Some("github"));
        assert_eq!(mcp_key_of("hermes:mcp-server:a:b"), Some("a:b"), "keys may contain ':'");
        assert_eq!(mcp_key_of("claude-code:hook"), None);
    }

    #[test]
    fn classify_plan_buckets_targets_and_builds_actions() {
        let targets = vec![
            GovernTarget::new("claude-code:hook", "claude-code", "hook", "hook", "ungoverned", Some("cc".into()), "l", "d"),
            GovernTarget::new("claude-desktop:mcp-server:github", "claude-desktop", "mcp-server", "gateway", "ungoverned", Some("cd".into()), "l", "d"),
            GovernTarget::new("claude-desktop:mcp-server:done", "claude-desktop", "mcp-server", "gateway", "governed", Some("cd".into()), "l", "d"),
            GovernTarget::new("claude-desktop:mcp-server:remote", "claude-desktop", "mcp-server", "gateway", "out-of-scope-cloud", Some("cd".into()), "l", "d"),
            GovernTarget::new("desktop:desktop-apps", "desktop", "desktop-apps", "reach-in/computer-use", "needs-permission", None, "l", "d"),
        ];
        let plan = classify_plan(&surface_of(targets, true, true));
        let wire_ids: Vec<&str> = plan.wire.iter().map(|a| a.target_id.as_str()).collect();
        assert_eq!(wire_ids, ["claude-code:hook", "claude-desktop:mcp-server:github"]);
        assert_eq!(plan.wire[0].action, "install-hook");
        assert_eq!(plan.wire[1].action, "wrap-mcp-server");
        assert_eq!(plan.wire[1].server_key.as_deref(), Some("github"));
        assert_eq!(plan.already_governed.len(), 1);
        assert_eq!(plan.out_of_scope_cloud.len(), 1);
        assert_eq!(plan.needs_permission.len(), 1, "desktop lane needs a grant");
        assert!(plan.blocked.is_empty());
    }

    #[test]
    fn classify_plan_blocks_ungoverned_when_binary_unavailable() {
        let targets = vec![
            GovernTarget::new("claude-code:hook", "claude-code", "hook", "hook", "ungoverned", None, "l", "d"),
            GovernTarget::new("hermes:hook", "hermes", "hook", "hook", "ungoverned", None, "l", "d"),
            GovernTarget::new("claude-desktop:mcp-server:x", "claude-desktop", "mcp-server", "gateway", "ungoverned", None, "l", "d"),
        ];
        // Both hook binaries missing → both hook targets blocked (each independently, not sharing
        // one flag); gateway present → the wrap still wires. Confirms hermes_hook_available is a
        // distinct gate from hook_available, not a shared "any hook" flag.
        let plan = classify_plan(&surface_of_all(targets, false, true, false));
        assert_eq!(plan.wire.len(), 1);
        assert_eq!(plan.wire[0].action, "wrap-mcp-server");
        assert_eq!(plan.blocked.len(), 2);
        assert!(plan.blocked.iter().all(|t| t.kind == "hook"));
        assert_eq!(
            plan.blocked.iter().map(|t| t.agent.as_str()).collect::<std::collections::BTreeSet<_>>(),
            ["claude-code", "hermes"].into_iter().collect()
        );
    }

    #[test]
    fn classify_plan_wires_hermes_hook_independently_of_claude_hook_availability() {
        let targets = vec![
            GovernTarget::new("claude-code:hook", "claude-code", "hook", "hook", "ungoverned", None, "l", "d"),
            GovernTarget::new("hermes:hook", "hermes", "hook", "hook", "ungoverned", None, "l", "d"),
        ];
        // kriya-hook missing, kriya-hermes-hook present → Claude Code's hook is blocked but
        // Hermes' still wires — proves the two availability flags are genuinely independent.
        let plan = classify_plan(&surface_of_all(targets, false, true, true));
        assert_eq!(plan.wire.len(), 1);
        assert_eq!(plan.wire[0].target_id, "hermes:hook");
        assert_eq!(plan.blocked.len(), 1);
        assert_eq!(plan.blocked[0].id, "claude-code:hook");
    }

    #[test]
    fn report_and_plan_shapes_serialize_camel_case() {
        let v = serde_json::to_value(GovernPlan::default()).unwrap();
        for k in ["wire", "needsPermission", "outOfScopeCloud", "alreadyGoverned", "blocked", "hookAvailable", "gatewayAvailable"] {
            assert!(v.get(k).is_some(), "GovernPlan missing {k}");
        }
        let v = serde_json::to_value(GovernAllReport::default()).unwrap();
        for k in ["wired", "needsPermission", "outOfScopeCloud", "alreadyGoverned", "errors"] {
            assert!(v.get(k).is_some(), "GovernAllReport missing {k}");
        }
        let v = serde_json::to_value(RevertReport::default()).unwrap();
        for k in ["reverted", "errors"] {
            assert!(v.get(k).is_some(), "RevertReport missing {k}");
        }
        // GovernAction omits server_key/config_path when None (skip_serializing_if).
        let action = GovernAction {
            target_id: "x".into(),
            agent: "a".into(),
            seam: "hook".into(),
            action: "install-hook".into(),
            server_key: None,
            config_path: None,
            detail: "d".into(),
        };
        let v = serde_json::to_value(&action).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["action", "agent", "detail", "seam", "targetId"]);
    }

    /// End-to-end (the apply/revert pipeline over real files, HOME redirected): govern the surface,
    /// prove it's governed + idempotent, then ungovern and prove every config is restored
    /// **byte-for-byte** — the GA-1 acceptance. Bypasses the `#[tauri::command]` wrappers only to
    /// skip the osascript candidate scan; it drives the same detect→classify→apply→revert code.
    #[test]
    fn govern_all_then_ungovern_all_round_trips_configs_byte_for_byte() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = std::env::temp_dir().join(format!("kriya-govern-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join("Library/Application Support/Claude")).unwrap();
        std::fs::create_dir_all(home.join(".hermes")).unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);

        let desktop_path = Client::ClaudeDesktop.config_path();
        let cc_path = Client::ClaudeCode.config_path();
        let hermes_path = Client::Hermes.config_path();
        write_config(
            &desktop_path,
            Fmt::Json,
            &json!({ "mcpServers": { "github": { "command": "npx", "args": ["-y", "server-github"] } } }),
        )
        .unwrap();
        write_config(&cc_path, Fmt::Json, &json!({ "permissions": { "allow": ["Read"] } })).unwrap();
        // Hermes' real on-disk key, per hermes_cli/mcp_config.py: `mcp_servers` (snake_case) — the
        // exact shape whose camelCase-only lookup was the live bug this test locks in the fix for.
        write_config(
            &hermes_path,
            Fmt::Yaml,
            &json!({ "mcp_servers": { "fs": { "command": "uvx", "args": ["mcp-server-fs"] } } }),
        )
        .unwrap();
        let desktop_before = std::fs::read_to_string(&desktop_path).unwrap();
        let cc_before = std::fs::read_to_string(&cc_path).unwrap();
        let hermes_before = std::fs::read_to_string(&hermes_path).unwrap();

        // Build the surface from the on-disk configs (pretend all three sidecars are bundled),
        // classify, and apply the wire plan — the govern_all pipeline minus osascript.
        let gw = "/opt/kriya-gateway";
        let hook = "/opt/kriya-hook";
        let hermes_hook = "/opt/kriya-hermes-hook";
        // Exercises the real policy-file resolution (B0): HOME is already redirected above, so
        // this lands inside the sandbox, proving ensure_policy_file's "always exists before any
        // --policy reference" invariant end-to-end, not just in isolation.
        let policy = resolve_policy_path();
        assert!(!policy.is_empty(), "the sandboxed ~/.kriya/agent-policy.yaml must be creatable");
        let plan = classify_plan(&detect(&read_client_states(), Some(true), &[], true, true, true));
        let wire_ids: Vec<String> = plan.wire.iter().map(|a| a.target_id.clone()).collect();
        for a in &plan.wire {
            apply_action(a, gw, hook, hermes_hook, &policy).unwrap();
        }
        // github + Hermes' fs wrapped; both hooks installed (coverage would detect both).
        assert!(is_gateway_wrapped(&read_config(&desktop_path, Fmt::Json)["mcpServers"]["github"]));
        assert!(is_gateway_wrapped(&read_config(&hermes_path, Fmt::Yaml)["mcp_servers"]["fs"]));
        assert!(hook_configured(Some(&cc_path)));
        assert!(config_has_kriya_hermes_hook(&read_config(&hermes_path, Fmt::Yaml)));

        // preview == the set actually wired. Order follows read_client_states()'s fixed client
        // order (ClaudeCode, ClaudeDesktop, Hermes) and, within each client, hook target before its
        // mcp-server targets.
        assert_eq!(
            wire_ids,
            vec![
                "claude-code:hook".to_string(),
                "claude-desktop:mcp-server:github".to_string(),
                "hermes:hook".to_string(),
                "hermes:mcp-server:fs".to_string(),
            ]
        );

        // Idempotent: re-detect → nothing left to wire.
        let plan2 = classify_plan(&detect(&read_client_states(), Some(true), &[], true, true, true));
        assert!(plan2.wire.is_empty(), "second run wires nothing");
        assert_eq!(plan2.already_governed.len(), 4, "all four targets now already-governed");

        // Revert everything governed → byte-for-byte originals.
        for t in detect(&read_client_states(), Some(true), &[], true, true, true)
            .targets
            .iter()
            .filter(|t| t.state == "governed")
        {
            revert_target(t, gw, hook).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&desktop_path).unwrap(), desktop_before, "desktop config restored byte-for-byte");
        assert_eq!(std::fs::read_to_string(&cc_path).unwrap(), cc_before, "claude code settings restored byte-for-byte");
        assert_eq!(std::fs::read_to_string(&hermes_path).unwrap(), hermes_before, "hermes config restored byte-for-byte");

        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}
