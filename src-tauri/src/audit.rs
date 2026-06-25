//! Auto-discovery + live tailing of the standard on-device audit directory (`~/.kriya/audit/`,
//! D-018 / R27). The whole point of the control-plane app: open it and *see* governance, with no
//! file to hunt for and no manual import. On launch the backend reads the directory and streams the
//! verified receipts to the UI; a background watcher re-emits an `audit-changed` event whenever a log
//! grows or a new front starts writing, so the cockpit updates as an agent drives an app.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::receipts::{load_rows, AuditRow};

/// The standard on-device audit directory — the same `~/.kriya/audit/` convention the gateway writes
/// to (`kriya::audit::default_audit_dir`). Created on demand so a fresh machine has somewhere for the
/// first front's receipts to land and for the Console to watch. Falls back to the temp dir when no
/// home is resolvable.
pub fn default_audit_dir() -> PathBuf {
    match home_dir().map(|h| h.join(".kriya").join("audit")) {
        Some(dir) if std::fs::create_dir_all(&dir).is_ok() => dir,
        _ => std::env::temp_dir(),
    }
}

/// `~/.kriya/console/` — Console-private on-device state (the installed license lives here). Created
/// on demand; temp-dir fallback mirrors [`default_audit_dir`].
pub fn console_dir() -> PathBuf {
    match home_dir().map(|h| h.join(".kriya").join("console")) {
        Some(dir) if std::fs::create_dir_all(&dir).is_ok() => dir,
        _ => std::env::temp_dir(),
    }
}

pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFileInfo {
    pub name: String,
    pub path: String,
    pub receipts: usize,
    pub bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLocation {
    pub dir: String,
    pub files: Vec<AuditFileInfo>,
}

/// List the `*.jsonl` logs the standard audit dir currently holds (name, path, receipt count). Cheap
/// metadata for the "watching ~/.kriya/audit/" empty/live state — the per-receipt verification is in
/// [`read_audit`].
#[tauri::command]
pub fn audit_location() -> AuditLocation {
    let dir = default_audit_dir();
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let receipts = text.lines().filter(|l| !l.trim().is_empty()).count();
            let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
            files.push(AuditFileInfo {
                name: path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                path: path.to_string_lossy().into_owned(),
                receipts,
                bytes,
            });
        }
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    AuditLocation {
        dir: dir.to_string_lossy().into_owned(),
        files,
    }
}

/// Read **and verify** every receipt across all `*.jsonl` logs in the standard audit dir, in compiled
/// Rust (the authoritative verifier). The filename is the row's `source` (= the "app"), so the cockpit
/// groups receipts per front exactly as the gateway names them (`reach-in-numbers.jsonl`, etc.).
#[tauri::command]
pub fn read_audit() -> Vec<AuditRow> {
    let dir = default_audit_dir();
    let mut rows = Vec::new();
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                paths.push(path);
            }
        }
    }
    paths.sort();
    for path in paths {
        let source = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        rows.extend(load_rows(&source, &text));
    }
    rows
}

/// Verify a single log file the operator opened by hand (the demoted "open a file…" path for ad-hoc
/// inspection of a log outside the standard dir). `source` is the basename for display.
#[tauri::command]
pub fn read_audit_file(path: String) -> Result<Vec<AuditRow>, String> {
    let p = Path::new(&path);
    let source = p
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    let text = std::fs::read_to_string(p).map_err(|e| format!("cannot read {path}: {e}"))?;
    Ok(load_rows(&source, &text))
}

/// A cheap fingerprint of the audit dir — the set of (filename, length) pairs. Changes whenever a log
/// grows (a new receipt) or a new front starts a log, which is exactly when the cockpit should refresh.
fn dir_fingerprint(dir: &Path) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((name, len));
        }
    }
    out.sort();
    out
}

/// Tail the audit dir on a background thread and emit `audit-changed` to the webview whenever it
/// changes (poll-based — robust, dependency-free, and ~1s latency is invisible for a governance
/// cockpit). The frontend re-invokes [`read_audit`] on each event, so receipts an agent generates
/// appear live while the Console stays open.
pub fn spawn_watcher(app: AppHandle) {
    std::thread::spawn(move || {
        let dir = default_audit_dir();
        let mut last = dir_fingerprint(&dir);
        loop {
            std::thread::sleep(Duration::from_millis(1200));
            let now = dir_fingerprint(&dir);
            if now != last {
                last = now;
                // A dropped event is non-fatal — the next tick re-detects any pending change.
                let _ = app.emit("audit-changed", ());
            }
        }
    });
}
