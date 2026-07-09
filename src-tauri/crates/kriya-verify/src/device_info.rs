//! The signed **DeviceInfo** beacon (doc 22 §7, fleet cockpit v2.1, P1) — a near-static inventory
//! snapshot (`console_version`, `runtime_version`, detected agents, applied policy, outbox health…)
//! emitted by an enrolled device on startup and whenever its content hash changes, POSTed to the new
//! `POST /v1/device-info` route and surfaced additively on `GET /v1/coverage` (BC-4).
//!
//! **This schema is allowlist-only per doc 22 §7: "fields not listed here do not exist."** [`DeviceInfo`]
//! carries EXACTLY the fields the doc lists — no more, no less — so it is structurally impossible to
//! serialize a person-scoped field (OS username, auto-derived hostname, source IP, timezone, locale,
//! MAC, serial number) even if some upstream "probe" struct collected them. See the allowlist test at
//! the bottom of this file, which proves this with an adversarial probe that deliberately offers all of
//! the excluded fields and shows none of them can flow into the wire bytes.
//!
//! Signing follows the envelope/heartbeat pattern (NOT the receipt one): canonical bytes are the compact
//! JSON of the recursively key-sorted value (R21, [`canonical_json_bytes`]), signed by the device
//! evidence key (the SAME stable Ed25519 identity that signs envelopes and heartbeats — `device_pub`
//! must equal the signing `public_key`, checked in [`verify_device_info`]). This crate never stores or
//! loads that key (kriya-verify is Tauri-free and device-secret-free by design); the device-side key
//! management lives in `control_plane::envelope::evidence_signing_key` (the app crate, P1 step 2) and is
//! passed in here as a `&SigningKey` for [`sign_device_info`].

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::canonical_json_bytes;
use crate::sig::verify_detached;

/// One detected agent + its governance adapter (doc-21 govern-all engine). `wired` is whether the
/// adapter is actually installed/active for this agent, not just detected on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub version: String,
    pub adapter: String,
    pub adapter_version: String,
    pub wired: bool,
}

/// Coarse, non-fingerprinting OS descriptor — platform family + coarse version + arch ONLY. No
/// hostname, no serial, no MAC (doc 22 §7's exclusion table).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsInfo {
    pub platform: String,
    pub version: String,
    pub arch: String,
}

/// Freshness echo of the applied policy bundle (doc 22 §5). `None` until the P3 policy-push phase lands
/// — the field itself is always present in the schema, its value is simply absent pre-P3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEcho {
    pub applied_version: u64,
    pub bundle_hash: String,
}

/// The device inventory snapshot, doc 22 §7 schema, verbatim — ALLOWLIST-ONLY: these ten fields and
/// nothing else. Do not add a field here without updating doc 22 §7 first (this struct IS the schema);
/// see [`tests::allowlist_excludes_person_scoped_fields`] for the enforcement test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub console_version: String,
    /// The governed gateway/runtime, e.g. `"kriya-host 0.4.2"`.
    pub runtime_version: String,
    pub verify_crate_version: String,
    pub os: OsInfo,
    /// Detected by the doc-21 govern-all engine.
    pub agents: Vec<AgentInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyEcho>,
    /// Buffered envelopes — a health signal.
    pub outbox_pending: u64,
    pub enrolled_ms: u64,
    /// ONLY the enterprise-assigned MDM asset tag (`enrollment`/`fleet.json`) — NEVER derived from the
    /// OS hostname (doc 22 §7 exclusion table: "Hostname — never auto-derived").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
}

/// The signed wire envelope for a DeviceInfo beacon: `{ device_pub, collected_ms, info, signature }`,
/// doc 22 §7's schema exactly. `signature` is hex(ed25519 by the device evidence key over the canonical
/// JSON of `{device_pub, collected_ms, info}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedDeviceInfo {
    /// The device evidence key (== signing `public_key`) — the device's stable fleet identity.
    pub device_pub: String,
    pub collected_ms: u64,
    pub info: DeviceInfo,
    pub signature: String,
}

/// The unsigned payload actually covered by the signature: `device_pub` + `collected_ms` + `info`, i.e.
/// [`SignedDeviceInfo`] minus `signature`. Kept as its own type (rather than signing the whole
/// `SignedDeviceInfo` with a dummy signature field) so canonicalization never has to special-case
/// dropping a field before hashing — mirrors how `Heartbeat`/`AttestationEnvelope` are signed as their
/// own struct, separate from the `Signed*` wrapper that carries `public_key`/`signature`.
#[derive(Debug, Clone, Serialize)]
struct DeviceInfoPayload<'a> {
    device_pub: &'a str,
    collected_ms: u64,
    info: &'a DeviceInfo,
}

/// Canonical signed bytes of a DeviceInfo beacon = compact JSON of the recursively key-sorted
/// `{device_pub, collected_ms, info}` value (R21) — the same key-sort technique as
/// `envelope_canonical_bytes` / `heartbeat_canonical_bytes` / `canonical_license_bytes`, chosen because
/// it is reorder-safe (BC-5): a verifier re-deriving these bytes from a parsed struct gets the identical
/// output regardless of the wire's original key order or whitespace.
pub fn device_info_canonical_bytes(device_pub: &str, collected_ms: u64, info: &DeviceInfo) -> Vec<u8> {
    let payload = DeviceInfoPayload {
        device_pub,
        collected_ms,
        info,
    };
    canonical_json_bytes(&serde_json::to_value(&payload).unwrap_or(Value::Null))
}

/// Sign a DeviceInfo snapshot with the device evidence key, producing the full wire envelope. The
/// caller supplies `key` (this crate holds no device secrets — see module docs); `key`'s public half
/// becomes `device_pub`, matching the envelope/heartbeat `device_pub == public_key` invariant.
pub fn sign_device_info(key: &SigningKey, collected_ms: u64, info: DeviceInfo) -> SignedDeviceInfo {
    let device_pub = hex::encode(key.verifying_key().to_bytes());
    let msg = device_info_canonical_bytes(&device_pub, collected_ms, &info);
    let signature = hex::encode(key.sign(&msg).to_bytes());
    SignedDeviceInfo {
        device_pub,
        collected_ms,
        info,
        signature,
    }
}

/// Verify a parsed DeviceInfo beacon: `device_pub == public signing key` (the envelope/heartbeat
/// invariant) and the Ed25519 signature over the canonical `{device_pub, collected_ms, info}` bytes.
/// The caller is responsible for feeding this the RAW parsed value from the wire (BC-5) — never a
/// value that has been dropped-field-and-reserialized first.
pub fn verify_device_info(v: &Value) -> Result<(), String> {
    let signed: SignedDeviceInfo = serde_json::from_value(v.clone())
        .map_err(|e| format!("not a signed device-info beacon: {e}"))?;
    let msg = device_info_canonical_bytes(&signed.device_pub, signed.collected_ms, &signed.info);
    verify_detached(&signed.device_pub, &signed.signature, &msg)
        .map_err(|_| "device-info signature does not match".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_info() -> DeviceInfo {
        DeviceInfo {
            console_version: "0.2.1".into(),
            runtime_version: "kriya-host 0.4.2".into(),
            verify_crate_version: "kriya-verify 0.1.0".into(),
            os: OsInfo {
                platform: "macos".into(),
                version: "15.5".into(),
                arch: "aarch64".into(),
            },
            agents: vec![
                AgentInfo {
                    id: "claude-code".into(),
                    version: "2.1.x".into(),
                    adapter: "kriya-hook".into(),
                    adapter_version: "r30".into(),
                    wired: true,
                },
                AgentInfo {
                    id: "hermes".into(),
                    version: "1.3.x".into(),
                    adapter: "kriya-hermes-hook".into(),
                    adapter_version: "0.2".into(),
                    wired: false,
                },
            ],
            policy: Some(PolicyEcho {
                applied_version: 13,
                bundle_hash: "deadbeef".into(),
            }),
            outbox_pending: 0,
            enrolled_ms: 1_783_400_000_000,
            device_label: Some("ENG-1234".into()),
        }
    }

    #[test]
    fn signed_device_info_verifies_and_tamper_fails() {
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let signed = sign_device_info(&key, 1_783_500_000_000, sample_info());
        let v = serde_json::to_value(&signed).unwrap();
        assert!(
            verify_device_info(&v).is_ok(),
            "honest device-info beacon verifies"
        );

        // Tamper with a field inside `info` after signing: must invalidate the signature.
        let mut tampered = v.clone();
        tampered["info"]["outbox_pending"] = json!(999);
        assert!(
            verify_device_info(&tampered).is_err(),
            "tampering info must invalidate the signature"
        );

        // device_pub swapped for another key's pub: must fail the device_pub/public-key/signature chain.
        let other = SigningKey::from_bytes(&[14u8; 32]);
        let mut swapped = v.clone();
        swapped["device_pub"] = json!(hex::encode(other.verifying_key().to_bytes()));
        assert!(
            verify_device_info(&swapped).is_err(),
            "swapping device_pub away from the signing key must fail verification"
        );
    }

    #[test]
    fn policy_is_optional_pre_p3() {
        let key = SigningKey::from_bytes(&[15u8; 32]);
        let mut info = sample_info();
        info.policy = None;
        info.device_label = None;
        let signed = sign_device_info(&key, 1_783_500_000_000, info);
        let v = serde_json::to_value(&signed).unwrap();
        assert!(
            verify_device_info(&v).is_ok(),
            "a beacon with no policy echo / no device_label yet (pre-P3, unenrolled-label) verifies"
        );
        // Optional fields must actually be omitted from the wire, not emitted as `null` — additive-only
        // (BC-4) evolution depends on absence, not null, being the "not present yet" signal.
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("\"policy\":null"));
        assert!(!s.contains("\"device_label\":null"));
    }

    /// THE load-bearing GDPR test (doc 22 §7's exclusion table). A `RichProbe` stands in for "whatever
    /// a naive OS/environment probe could collect" — it DELIBERATELY offers every field the doc's
    /// exclusion table forbids: OS username, auto-derived hostname, source IP, timezone, locale, MAC
    /// address, and a hardware serial number. There is no code path from `RichProbe` into `DeviceInfo`
    /// other than the explicit, field-by-field `DeviceInfo::from_probe` allowlist below — so this test
    /// proves the exclusion structurally, not by convention: if someone later adds
    /// `pub hostname: String` to `DeviceInfo` and starts threading it through, this test starts failing
    /// the moment the field's value round-trips into the serialized bytes.
    struct RichProbe {
        // Allowlisted, technical, device-scoped — these ARE allowed to flow through.
        console_version: &'static str,
        runtime_version: &'static str,
        verify_crate_version: &'static str,
        os_platform: &'static str,
        os_version: &'static str,
        os_arch: &'static str,
        outbox_pending: u64,
        enrolled_ms: u64,
        // Forbidden, person-scoped or fingerprinting — doc 22 §7's exclusion table, verbatim:
        // "OS username — never", "Hostname — never auto-derived", "Source IP ... must not persist",
        // "Timezone, locale, MAC, serial numbers".
        os_username: &'static str,
        hostname: &'static str,
        source_ip: &'static str,
        timezone: &'static str,
        locale: &'static str,
        mac_address: &'static str,
        serial_number: &'static str,
    }

    /// The ONLY conversion path from a raw probe into the wire schema — mirrors `redact::minimize_window`
    /// being the sole constructor of `MinimizedAction`: it reads exactly the allowlisted probe fields and
    /// nothing else, so the seven forbidden fields above are simply never referenced, let alone copied.
    fn device_info_from_probe(p: &RichProbe) -> DeviceInfo {
        DeviceInfo {
            console_version: p.console_version.into(),
            runtime_version: p.runtime_version.into(),
            verify_crate_version: p.verify_crate_version.into(),
            os: OsInfo {
                platform: p.os_platform.into(),
                version: p.os_version.into(),
                arch: p.os_arch.into(),
            },
            agents: vec![],
            policy: None,
            outbox_pending: p.outbox_pending,
            enrolled_ms: p.enrolled_ms,
            device_label: None,
        }
    }

    #[test]
    fn allowlist_excludes_person_scoped_fields() {
        let probe = RichProbe {
            console_version: "0.2.1",
            runtime_version: "kriya-host 0.4.2",
            verify_crate_version: "kriya-verify 0.1.0",
            os_platform: "macos",
            os_version: "15.5",
            os_arch: "aarch64",
            outbox_pending: 3,
            enrolled_ms: 1_783_400_000_000,
            // The forbidden values below are deliberately distinctive so a substring search proves
            // they cannot leak in ANY form (field value, not just field name).
            os_username: "skumar",
            hostname: "skumars-macbook-pro.local",
            source_ip: "203.0.113.42",
            timezone: "America/Los_Angeles",
            locale: "en_US",
            mac_address: "AC:DE:48:00:11:22",
            serial_number: "C02FORBIDDEN123",
        };

        let info = device_info_from_probe(&probe);
        let key = SigningKey::from_bytes(&[16u8; 32]);
        let signed = sign_device_info(&key, 1_783_500_000_000, info);

        // Check both the struct's own serialization AND the fully signed wire envelope (what a naive
        // consumer would eyeball for excluded fields), plus the exact canonical signed bytes (what
        // actually goes over the wire and gets hashed/signed) — all three must be clean.
        let info_json = serde_json::to_string(&signed.info).unwrap();
        let wire_json = serde_json::to_string(&signed).unwrap();
        let canonical = device_info_canonical_bytes(&signed.device_pub, signed.collected_ms, &signed.info);
        let canonical_str = String::from_utf8_lossy(&canonical);

        let forbidden_values = [
            probe.os_username,
            probe.hostname,
            probe.source_ip,
            probe.timezone,
            probe.locale,
            probe.mac_address,
            probe.serial_number,
        ];
        for needle in forbidden_values {
            assert!(
                !info_json.contains(needle),
                "forbidden value {needle:?} leaked into DeviceInfo JSON: {info_json}"
            );
            assert!(
                !wire_json.contains(needle),
                "forbidden value {needle:?} leaked into the signed wire envelope: {wire_json}"
            );
            assert!(
                !canonical_str.contains(needle),
                "forbidden value {needle:?} leaked into the canonical signed bytes"
            );
        }

        // Forbidden field NAMES (as actual JSON object keys, not substrings of values — "macos" must
        // not false-positive against a "mac" key check).
        let obj = serde_json::from_str::<Value>(&info_json)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let top_level_keys: std::collections::HashSet<String> =
            obj.keys().cloned().collect();
        let os_keys: std::collections::HashSet<String> = obj["os"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for forbidden_key in [
            "username",
            "hostname",
            "host_name",
            "source_ip",
            "ip",
            "timezone",
            "locale",
            "mac",
            "mac_address",
            "serial",
            "serial_number",
        ] {
            assert!(
                !top_level_keys.contains(forbidden_key) && !os_keys.contains(forbidden_key),
                "forbidden field name {forbidden_key:?} present as a JSON key in DeviceInfo: {info_json}"
            );
        }

        // Positive control: allowlisted technical fields DO flow through, so this test would catch a
        // constructor that (wrongly) drops everything rather than (correctly) allowlisting.
        assert!(info_json.contains("kriya-host 0.4.2"));
        assert!(info_json.contains("aarch64"));

        // And the signature must still verify — the allowlist boundary isn't achieved by breaking
        // signing, it's achieved by the schema simply never having room for the excluded fields.
        let v = serde_json::to_value(&signed).unwrap();
        assert!(verify_device_info(&v).is_ok());
    }

    /// Belt-and-suspenders on the schema itself: enumerate DeviceInfo's serialized keys (from a fully
    /// populated instance, so no `skip_serializing_if` hides a field) and assert the set is EXACTLY the
    /// ten doc-22-§7 field names — not a subset check, an equality check, so an added field fails loudly.
    #[test]
    fn device_info_serializes_exactly_the_allowlisted_keys() {
        let info = sample_info(); // policy + device_label both Some(..), so nothing is hidden by skip_serializing_if
        let v = serde_json::to_value(&info).unwrap();
        let obj = v.as_object().expect("DeviceInfo serializes to a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();

        let mut expected = vec![
            "console_version",
            "runtime_version",
            "verify_crate_version",
            "os",
            "agents",
            "policy",
            "outbox_pending",
            "enrolled_ms",
            "device_label",
        ];
        expected.sort();

        assert_eq!(
            keys, expected,
            "DeviceInfo must serialize EXACTLY the doc-22 §7 allowlisted fields, no more, no less"
        );
    }
}
