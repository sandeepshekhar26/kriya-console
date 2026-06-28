//! The Evidence Compiler (1.14–1.18) — the device's window loop.
//!
//! 1.14 is the SKELETON: the *pending* flag (set on each `audit-changed` tick) + the fixed,
//! boundary-aligned window-W timer. `audit-changed` only marks receipts pending; the W boundary is
//! what closes a window and (1.15) emits an envelope. Time is injected, so the timer math is testable
//! without a real clock or Tauri. The per-source compile (1.15), dense-seq empty envelope (1.16),
//! heartbeat (1.17), and the `lib.rs` spawn (1.18) build on this.

/// Default window length W — the pilot's 1h cadence (LLD §B.3.1). Boundary-aligned.
pub const DEFAULT_WINDOW_MS: u64 = 60 * 60 * 1000;

/// The Compiler's window state.
pub struct Compiler {
    window_ms: u64,
    /// The `to_ms` of the last window the Compiler closed (0 = none closed yet).
    last_closed_to_ms: u64,
    /// New receipts have arrived since the last closed window.
    pending: bool,
}

impl Compiler {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms: window_ms.max(1),
            last_closed_to_ms: 0,
            pending: false,
        }
    }

    /// Mark that new receipts arrived (called on each `audit-changed` tick). Does NOT emit.
    pub fn mark_pending(&mut self) {
        self.pending = true;
    }

    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// The boundary-aligned window that has CLOSED at or before `now_ms` and not yet been emitted, if
    /// any: `(from_ms, to_ms)` where `to_ms` is the most recent W boundary ≤ `now_ms` and `from_ms =
    /// to_ms − W`. `None` while still inside the already-closed-through window. Windows tile with no
    /// gaps or overlaps (boundary-aligned, NOT first/last receipt timestamps).
    pub fn due_window(&self, now_ms: u64) -> Option<(u64, u64)> {
        let boundary = (now_ms / self.window_ms) * self.window_ms;
        (boundary > self.last_closed_to_ms)
            .then(|| (boundary.saturating_sub(self.window_ms), boundary))
    }

    /// Record that the window ending at `to_ms` has been emitted; clears `pending`.
    pub fn close_window(&mut self, to_ms: u64) {
        self.last_closed_to_ms = to_ms;
        self.pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_flag_and_boundary_aligned_windows() {
        let mut c = Compiler::new(1000); // W = 1s
        assert!(!c.is_pending());
        c.mark_pending();
        assert!(c.is_pending());

        // Still inside the first window (now < W) → nothing due yet.
        assert_eq!(c.due_window(500), None);
        // Crossed the W boundary → the window [0, 1000) is due.
        assert_eq!(c.due_window(1500), Some((0, 1000)));

        c.close_window(1000);
        assert!(!c.is_pending(), "closing a window clears pending");
        assert_eq!(
            c.due_window(1500),
            None,
            "already-closed window is not due again"
        );

        // The next boundary makes the following window due; windows tile exactly.
        assert_eq!(c.due_window(2500), Some((1000, 2000)));
        c.close_window(2000);
        assert_eq!(c.due_window(2999), None);
        assert_eq!(c.due_window(3000), Some((2000, 3000)));
    }
}
