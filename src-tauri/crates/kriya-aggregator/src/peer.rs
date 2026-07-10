//! Peer identity + role gating (P6, doc 22 §11-B2). Pre-P6 every cert chaining to the pinned CA was
//! equal — any fleet cert could read the whole fleet and post heartbeats/inventory for arbitrary
//! `device_pub`s. This module reads the ROLE stamped into a client cert's SAN URI (parsed post-
//! handshake in [`crate::tls`]) and turns it into a [`PeerAuth`] the route table gates on:
//!
//!   * a **device** cert may only POST its OWN evidence (envelopes/heartbeat/device-info bound to the
//!     `device_pub` in its cert) and pull its own policy — it cannot read the fleet;
//!   * an **operator** cert may read the fleet + author policy — it cannot POST device evidence.
//!
//! The SAN URIs (minted by `scripts/kriyd-ca.sh`):
//!   operator :  `kriya://role=operator`
//!   device   :  `kriya://role=device;device_pub=<lowercase-hex ed25519 evidence pubkey>`
//!
//! **BC-4 (a documented migration path, not a silent break):** a cert with NO kriya role SAN (every
//! pre-P6 cert) is a [`PeerAuth::Rejected`] by default, but is honored as [`PeerAuth::Legacy`] (behaving
//! exactly as pre-P6 — every route, no binding) when `KRIYAD_ALLOW_LEGACY_CERTS=1`. Operators reissue
//! role-stamped certs onto the same CA, roll them out, then turn grace off to enforce. **Plain-HTTP dev
//! mode** (no mTLS at all — `KRIYAD_CA_DIR` absent) carries no cert, so requests default to
//! [`PeerAuth::Plaintext`], which enforces no roles: plain HTTP is documented dev/local-only and is
//! already fully open, so P6 changes nothing there — role enforcement is a property of the mTLS layer.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;

/// The role a validly-chaining client cert claims via its SAN URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerRole {
    /// A device, bound to its own receipt-signing pubkey (lowercase hex) — it may only introduce
    /// evidence for THIS `device_pub`.
    Device(String),
    /// The fleet operator cockpit — reads coverage/evidence, authors policy.
    Operator,
}

/// The authenticated identity attached to every request. Injected into request extensions by the mTLS
/// acceptor (`crate::tls::RoleAcceptor`); route handlers read it via the [`FromRequestParts`] impl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerAuth {
    /// A role-stamped cert — the strict-enforcement path.
    Role(PeerRole),
    /// A role-LESS cert accepted under `KRIYAD_ALLOW_LEGACY_CERTS=1` — behaves as pre-P6 (every route,
    /// no `device_pub` binding), the documented migration grace window.
    Legacy,
    /// A role-less cert with grace OFF, or a malformed/unknown role SAN — 403 on every route. The
    /// string is the operator-facing reason.
    Rejected(String),
    /// No mTLS at all (plain-HTTP dev/local mode). Roles are not enforced — plain HTTP is dev-only and
    /// already fully open; the security boundary is the mTLS listener.
    Plaintext,
}

/// Does `s` look like an ed25519 pubkey hex (32 bytes = 64 lowercase-hex chars)? Envelopes carry
/// `hex::encode(pubkey)` (lowercase), so the cert-bound `device_pub` must match that exact shape.
fn is_pubkey_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse ONE SAN URI. Returns:
///   * `None`               — not a `kriya://role=` URI (some other SAN; ignore it),
///   * `Some(Ok(role))`     — a well-formed kriya role,
///   * `Some(Err(reason))`  — a kriya role URI that is malformed / names an unknown role.
fn parse_role_uri(uri: &str) -> Option<Result<PeerRole, String>> {
    let body = uri.strip_prefix("kriya://")?;
    // Must start with `role=` to be one of ours.
    if !body.starts_with("role=") {
        return None;
    }
    // `role=operator` | `role=device;device_pub=<hex>`
    let mut role: Option<&str> = None;
    let mut device_pub: Option<&str> = None;
    for part in body.split(';') {
        // A `;`-segment with no `=` is a MALFORMED kriya role SAN — a hard error, NOT a silent
        // fall-through to legacy (returning `None` here would let `kriya://role=operator;junk` be
        // treated as a role-less legacy cert, which under grace mode would grant pre-P6 god-mode).
        let Some((k, v)) = part.split_once('=') else {
            return Some(Err(format!("malformed kriya role SAN segment: {part:?}")));
        };
        match k {
            "role" => role = Some(v),
            "device_pub" => device_pub = Some(v),
            _ => {} // tolerate unknown future attrs (forward-compat), as long as role parses
        }
    }
    match role {
        Some("operator") => Some(Ok(PeerRole::Operator)),
        Some("device") => match device_pub {
            Some(p) if is_pubkey_hex(p) => Some(Ok(PeerRole::Device(p.to_string()))),
            Some(_) => Some(Err("device role SAN has a malformed device_pub (want 64 lowercase-hex chars)".into())),
            None => Some(Err("device role SAN is missing device_pub".into())),
        },
        Some(other) => Some(Err(format!("unknown kriya cert role: {other:?}"))),
        None => Some(Err("kriya role SAN is malformed".into())),
    }
}

/// Parse the kriya role out of a leaf cert's SAN URIs.
///   * `Ok(Some(role))` — a well-formed kriya role SAN,
///   * `Ok(None)`       — no kriya role SAN at all (a legacy, role-less cert),
///   * `Err(reason)`    — the cert won't parse, or it carries a malformed/unknown kriya role SAN.
pub fn parse_role(cert_der: &[u8]) -> Result<Option<PeerRole>, String> {
    use x509_parser::prelude::*;
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| format!("parse client cert: {e}"))?;
    let san = match cert.subject_alternative_name() {
        Ok(Some(san)) => san,
        Ok(None) => return Ok(None), // no SAN extension → legacy
        Err(e) => return Err(format!("read SAN: {e}")),
    };
    // First kriya role URI wins; a malformed one is a hard error (don't silently fall through to legacy).
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            if let Some(result) = parse_role_uri(uri) {
                return result.map(Some);
            }
        }
    }
    Ok(None) // SAN present but no kriya role URI → still legacy
}

/// Turn a leaf cert (+ the grace flag) into the [`PeerAuth`] to inject. Total — never panics.
pub fn auth_from_leaf(cert_der: &[u8], allow_legacy: bool) -> PeerAuth {
    match parse_role(cert_der) {
        Ok(Some(role)) => PeerAuth::Role(role),
        Ok(None) if allow_legacy => PeerAuth::Legacy,
        Ok(None) => PeerAuth::Rejected(
            "client certificate carries no kriya role SAN and legacy-cert grace is off \
             (reissue role-stamped certs, or set KRIYAD_ALLOW_LEGACY_CERTS=1 during migration)"
                .into(),
        ),
        Err(e) => PeerAuth::Rejected(format!("client certificate role rejected: {e}")),
    }
}

fn forbidden(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, format!("{}\n", msg.into()))
}

impl PeerAuth {
    /// Operator-only routes: `GET /v1/coverage`, `GET /v1/verify`, `POST /v1/policy`.
    pub fn require_operator(&self) -> Result<(), (StatusCode, String)> {
        match self {
            PeerAuth::Role(PeerRole::Operator) | PeerAuth::Legacy | PeerAuth::Plaintext => Ok(()),
            PeerAuth::Role(PeerRole::Device(_)) => Err(forbidden(
                "this route requires an operator certificate — a device certificate may not read the fleet or author policy",
            )),
            PeerAuth::Rejected(r) => Err(forbidden(r)),
        }
    }

    /// Device-only routes: `POST /v1/envelopes`, `POST /v1/heartbeat`, `POST /v1/device-info`. Returns
    /// the cert-bound `device_pub` to enforce against the payload (`None` for Legacy/Plaintext, where
    /// there is no binding to enforce — pre-P6 / dev behavior).
    pub fn require_device(&self) -> Result<Option<&str>, (StatusCode, String)> {
        match self {
            PeerAuth::Role(PeerRole::Device(p)) => Ok(Some(p.as_str())),
            PeerAuth::Legacy | PeerAuth::Plaintext => Ok(None),
            PeerAuth::Role(PeerRole::Operator) => Err(forbidden(
                "this route requires a device certificate — an operator certificate may not post device evidence",
            )),
            PeerAuth::Rejected(r) => Err(forbidden(r)),
        }
    }

    /// `GET /v1/policy` — the device pulls its OWN scoped bundle (binding enforced), but the operator
    /// cockpit ALSO reads it for its publish-preview + org-evidence fetch (P3–P5), so an operator is
    /// permitted here with no `device_pub` binding. Returns the cert-bound `device_pub` for a device.
    pub fn require_device_or_operator(&self) -> Result<Option<&str>, (StatusCode, String)> {
        match self {
            PeerAuth::Role(PeerRole::Device(p)) => Ok(Some(p.as_str())),
            PeerAuth::Role(PeerRole::Operator) | PeerAuth::Legacy | PeerAuth::Plaintext => Ok(None),
            PeerAuth::Rejected(r) => Err(forbidden(r)),
        }
    }

    /// `/healthz` + `/metrics` — any authenticated role (incl. legacy grace + plain-HTTP dev). Only an
    /// outright-rejected cert (role-less with grace off, or a malformed role) is 403'd.
    pub fn require_any(&self) -> Result<(), (StatusCode, String)> {
        match self {
            PeerAuth::Rejected(r) => Err(forbidden(r)),
            _ => Ok(()),
        }
    }
}

/// Read the injected [`PeerAuth`] off the request, defaulting to [`PeerAuth::Plaintext`] when absent
/// (plain-HTTP dev mode, where the mTLS acceptor never ran). Infallible.
impl<S: Send + Sync> FromRequestParts<S> for PeerAuth {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<PeerAuth>()
            .cloned()
            .unwrap_or(PeerAuth::Plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_operator_and_device_role_uris() {
        assert_eq!(parse_role_uri("kriya://role=operator"), Some(Ok(PeerRole::Operator)));
        let hex = "a".repeat(64);
        assert_eq!(
            parse_role_uri(&format!("kriya://role=device;device_pub={hex}")),
            Some(Ok(PeerRole::Device(hex.clone())))
        );
    }

    #[test]
    fn non_kriya_uris_are_ignored_not_errors() {
        assert_eq!(parse_role_uri("https://example.com"), None);
        assert_eq!(parse_role_uri("spiffe://td/workload"), None);
        // A kriya URI that isn't a role SAN (some future kriya:// use) is also "not ours".
        assert_eq!(parse_role_uri("kriya://something-else"), None);
    }

    #[test]
    fn malformed_kriya_role_uris_are_hard_errors_not_legacy() {
        assert!(matches!(parse_role_uri("kriya://role=banana"), Some(Err(_))));
        assert!(matches!(parse_role_uri("kriya://role=device"), Some(Err(_)))); // no device_pub
        assert!(matches!(
            parse_role_uri("kriya://role=device;device_pub=NOTHEX"),
            Some(Err(_))
        ));
        assert!(matches!(
            parse_role_uri("kriya://role=device;device_pub=abc"), // too short
            Some(Err(_))
        ));
        // A trailing/extra `;`-segment with no `=` is a hard error, never a silent legacy fall-through.
        assert!(matches!(parse_role_uri("kriya://role=operator;junk"), Some(Err(_))));
        assert!(matches!(
            parse_role_uri(&format!("kriya://role=device;device_pub={};x", "a".repeat(64))),
            Some(Err(_))
        ));
        // Uppercase hex is rejected — envelopes use lowercase `hex::encode`.
        assert!(matches!(
            parse_role_uri(&format!("kriya://role=device;device_pub={}", "A".repeat(64))),
            Some(Err(_))
        ));
    }

    #[test]
    fn auth_from_leaf_grace_semantics() {
        // A malformed DER never panics — it is a clean Rejected.
        assert!(matches!(auth_from_leaf(b"not a cert", false), PeerAuth::Rejected(_)));
        assert!(matches!(auth_from_leaf(b"not a cert", true), PeerAuth::Rejected(_)));
    }

    #[test]
    fn operator_gate() {
        assert!(PeerAuth::Role(PeerRole::Operator).require_operator().is_ok());
        assert!(PeerAuth::Legacy.require_operator().is_ok());
        assert!(PeerAuth::Plaintext.require_operator().is_ok());
        assert!(PeerAuth::Role(PeerRole::Device("x".into())).require_operator().is_err());
        assert!(PeerAuth::Rejected("nope".into()).require_operator().is_err());
    }

    #[test]
    fn device_gate_returns_binding() {
        let hex = "b".repeat(64);
        assert_eq!(
            PeerAuth::Role(PeerRole::Device(hex.clone())).require_device().unwrap(),
            Some(hex.as_str())
        );
        assert_eq!(PeerAuth::Legacy.require_device().unwrap(), None);
        assert_eq!(PeerAuth::Plaintext.require_device().unwrap(), None);
        assert!(PeerAuth::Role(PeerRole::Operator).require_device().is_err());
        assert!(PeerAuth::Rejected("nope".into()).require_device().is_err());
    }

    #[test]
    fn get_policy_gate_allows_both_device_and_operator() {
        let hex = "c".repeat(64);
        assert_eq!(
            PeerAuth::Role(PeerRole::Device(hex.clone())).require_device_or_operator().unwrap(),
            Some(hex.as_str())
        );
        assert_eq!(
            PeerAuth::Role(PeerRole::Operator).require_device_or_operator().unwrap(),
            None
        );
        assert!(PeerAuth::Rejected("nope".into()).require_device_or_operator().is_err());
    }

    #[test]
    fn any_gate_only_blocks_rejected() {
        assert!(PeerAuth::Role(PeerRole::Operator).require_any().is_ok());
        assert!(PeerAuth::Legacy.require_any().is_ok());
        assert!(PeerAuth::Plaintext.require_any().is_ok());
        assert!(PeerAuth::Rejected("nope".into()).require_any().is_err());
    }
}
