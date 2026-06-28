//! Device control-plane secrets (1.8) + the envelope BUILDER (1.10).
//!
//! The **evidence key** (a stable Ed25519 identity, the device's fleet identity) SIGNS attestation
//! envelopes; its public half is `device_pub`. The **pepper** keys the operator-pseudonym HMAC, so the
//! server can dedup an operator WITHOUT ever seeing a plaintext name. Both live `0600` under
//! `~/.kriya/console/` and NEVER leave the device. (1.8 is the keys; the builder lands in 1.10.)

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

/// The device evidence signing key, persisted at `~/.kriya/console/evidence.key` (32-byte hex seed,
/// `0600`). Stable across runs — the `device_pub` an auditor pins stays the same deployment-to-deployment.
pub fn evidence_signing_key() -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&load_or_create_seed(
        &evidence_key_path(),
    )?))
}

/// The device's stable public identity (lowercase hex of the evidence verifying key) = `device_pub`.
pub fn evidence_public_hex() -> Result<String, String> {
    Ok(hex::encode(
        evidence_signing_key()?.verifying_key().to_bytes(),
    ))
}

/// The operator-pseudonym pepper (32 bytes), persisted `0600` at `~/.kriya/console/pepper`. Device-local
/// and never transmitted — so the server can dedup an operator via the HMAC pseudonym but can never
/// recover the plaintext name (the pseudonym map stays OFF the aggregator).
pub fn pepper() -> Result<Vec<u8>, String> {
    Ok(load_or_create_seed(&pepper_path())?.to_vec())
}

fn evidence_key_path() -> PathBuf {
    crate::audit::console_dir().join("evidence.key")
}
fn pepper_path() -> PathBuf {
    crate::audit::console_dir().join("pepper")
}

/// Load a 32-byte seed from `path` (lowercase hex), or generate one with the OS CSPRNG and persist it
/// (`0600` on unix; parents created). Mirrors the runtime host's durable-identity pattern. An
/// existing-but-invalid file is an ERROR, never overwritten — losing a device identity must be a
/// deliberate act, not a side effect of a typo'd path.
fn load_or_create_seed(path: &Path) -> Result<[u8; 32], String> {
    if path.exists() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let bytes = hex::decode(text.trim())
            .map_err(|e| format!("{} is not valid hex: {e}", path.display()))?;
        return bytes
            .try_into()
            .map_err(|_| format!("{} must be 32 bytes (64 hex chars)", path.display()));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("OS CSPRNG failed: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(path, hex::encode(seed))
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    restrict_perms(path);
    Ok(seed)
}

#[cfg(unix)]
fn restrict_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_path: &Path) {}

// ── The envelope BUILDER (1.10) ──────────────────────────────────────────────────────────────────

use std::collections::BTreeMap;

use ed25519_dalek::Signer;
use serde_json::Value;

use crate::control_plane::redact::{default_allowlist, operator_pseudonym};
use kriya_verify::{
    canonical_json_bytes, chain_continues_from, envelope_canonical_bytes, is_destructive,
    merkle_root, minimize_window, sha256_hex, verify_value, AttestationEnvelope, CompilerInfo,
    Counts, Integrity, NonEgress, OperatorRollup, SignedEnvelope, SignerRollup, Window,
};

const ATTESTATION_ON_DEVICE: &str = "kriya.attestation.on_device";
const ENVELOPE_SCHEMA: &str = "kriya.envelope.v1";

/// One source's new receipt lines for a window, plus the prior window's tail hash (to seed the
/// windowed chain check). `lines` are the exact on-disk JSON lines, in order.
pub struct SourceWindow {
    pub source: String,
    pub lines: Vec<String>,
    pub prev_tail_hash: Option<String>,
}

/// Everything the builder needs to assemble + sign one window's envelope. The Compiler (1.13+) fills
/// this from the audit dir; here it is explicit so the builder is pure + testable.
pub struct WindowInput {
    pub org_id: String,
    pub business_unit: Option<String>,
    pub window_from_ms: u64,
    pub window_to_ms: u64,
    pub seq: u64,
    pub prev_envelope_hash: Option<String>,
    pub produced_ms: u64,
    pub sources: Vec<SourceWindow>,
}

/// Assemble + sign one `AttestationEnvelope` from a verified window. Reuses the shared trust core
/// throughout (`verify_value`, `chain_continues_from`, `merkle_root`, `minimize_window`); reads no
/// `params`; operators appear only as HMAC pseudonyms. `key` + `pepper` are injected (the Compiler
/// loads them from the device secrets) so this stays pure + testable.
pub fn build_signed_envelope(
    input: &WindowInput,
    key: &SigningKey,
    pepper: &[u8],
) -> Result<SignedEnvelope, String> {
    // 1. Per-source windowed chain check; collect line bytes in the TOTAL order the auditor will
    //    reconstruct (source filename ascending, then on-disk line index).
    let mut sources: Vec<&SourceWindow> = input.sources.iter().collect();
    sources.sort_by(|a, b| a.source.cmp(&b.source));

    let mut chain_intact = true;
    let mut broken_sources = Vec::new();
    let mut ordered_line_bytes: Vec<Vec<u8>> = Vec::new();
    let mut all_values: Vec<Value> = Vec::new();

    for sw in &sources {
        let line_refs: Vec<&str> = sw.lines.iter().map(String::as_str).collect();
        if let Some(line) = chain_continues_from(sw.prev_tail_hash.as_deref(), &line_refs) {
            chain_intact = false;
            broken_sources.push(format!("{}@{}", sw.source, line));
        }
        for line in &sw.lines {
            ordered_line_bytes.push(line.as_bytes().to_vec());
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                all_values.push(v);
            }
        }
    }
    let total_receipts = ordered_line_bytes.len() as u32;

    // 2. Keep only receipts whose signature verifies; everything else is "failed" (a tamper signal).
    let verified_values: Vec<Value> = all_values
        .into_iter()
        .filter(|v| verify_value(v).is_ok())
        .collect();
    let verified = verified_values.len() as u32;
    let failed = total_receipts.saturating_sub(verified);

    // 3. Minimized actions (drop-by-default) over verified receipts.
    let actions = minimize_window(&verified_values, &default_allowlist());

    // 4. Signer-fingerprint rollup + 5. operator-pseudonym rollup (HMAC; never the plaintext name).
    let mut by_signer: BTreeMap<String, u32> = BTreeMap::new();
    let mut by_op: BTreeMap<String, u32> = BTreeMap::new();
    for v in &verified_values {
        if let Some(pk) = v.get("public_key").and_then(Value::as_str) {
            *by_signer.entry(pk.to_string()).or_default() += 1;
        }
        if let Some(user) = v
            .get("actor")
            .and_then(|a| a.get("user"))
            .and_then(Value::as_str)
        {
            *by_op.entry(operator_pseudonym(pepper, user)).or_default() += 1;
        }
    }
    let signers: Vec<SignerRollup> = by_signer
        .into_iter()
        .map(|(pk, n)| SignerRollup {
            fingerprint: pk.chars().take(16).collect(),
            receipts: n,
            verified: n,
        })
        .collect();
    let operators: Vec<OperatorRollup> = by_op
        .into_iter()
        .map(|(op_ref, actions)| OperatorRollup { op_ref, actions })
        .collect();

    // 6. Counts + 8. non-egress digest over the in-window attestation receipts.
    let destructive = verified_values
        .iter()
        .filter(|v| {
            v.get("action_id")
                .and_then(Value::as_str)
                .map(is_destructive)
                .unwrap_or(false)
        })
        .count() as u32;
    let attestations: Vec<&Value> = verified_values
        .iter()
        .filter(|v| v.get("action_id").and_then(Value::as_str) == Some(ATTESTATION_ON_DEVICE))
        .collect();
    let attestation_count = attestations.len() as u32;
    let proof_digest = (attestation_count > 0).then(|| {
        let mut concat = Vec::new();
        for v in &attestations {
            concat.extend_from_slice(&canonical_json_bytes(v));
        }
        sha256_hex(&concat)
    });

    // 7. Merkle root over the covered lines (total order) + 9. assemble + sign.
    let root = merkle_root(&ordered_line_bytes);
    let device_pub = hex::encode(key.verifying_key().to_bytes());
    let envelope = AttestationEnvelope {
        schema: ENVELOPE_SCHEMA.into(),
        device_pub: device_pub.clone(),
        org_id: input.org_id.clone(),
        business_unit: input.business_unit.clone(),
        operators,
        seq: input.seq,
        prev_envelope_hash: input.prev_envelope_hash.clone(),
        window: Window {
            from_ms: input.window_from_ms,
            to_ms: input.window_to_ms,
        },
        signers,
        actions,
        counts: Counts {
            receipts: total_receipts,
            verified,
            failed,
            destructive,
            attestations: attestation_count,
        },
        integrity: Integrity {
            merkle_root: root,
            chain_intact,
            broken_sources,
        },
        non_egress: NonEgress {
            attested: attestation_count > 0,
            attestation_count,
            proof_digest,
        },
        compiler: CompilerInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            produced_ms: input.produced_ms,
        },
    };
    let signature = hex::encode(key.sign(&envelope_canonical_bytes(&envelope)).to_bytes());
    Ok(SignedEnvelope {
        envelope,
        public_key: device_pub,
        signature,
    })
}

#[cfg(test)]
mod builder_tests {
    use super::*;
    use kriya_verify::verify_envelope;

    /// Build a signed receipt LINE whose canonical bytes match what `verify_value` re-derives
    /// (declaration order: step_id, action_id, params, success, ts_ms, actor, then optional prev_hash).
    fn signed_receipt_line(
        host: &SigningKey,
        step: &str,
        action: &str,
        user: &str,
        prev_hash: Option<&str>,
    ) -> String {
        let mut fields = format!(
            r#""step_id":{},"action_id":{},"params":{{}},"success":true,"ts_ms":1,"actor":{{"agent":"claude","user":{}}}"#,
            serde_json::json!(step),
            serde_json::json!(action),
            serde_json::json!(user),
        );
        if let Some(p) = prev_hash {
            fields.push_str(&format!(r#","prev_hash":{}"#, serde_json::json!(p)));
        }
        let canon = format!("{{{fields}}}");
        let sig = hex::encode(host.sign(canon.as_bytes()).to_bytes());
        let pk = hex::encode(host.verifying_key().to_bytes());
        format!(r#"{{{fields},"public_key":"{pk}","signature":"{sig}"}}"#)
    }

    #[test]
    fn builds_a_verifiable_envelope_with_redacted_rollups() {
        let host = SigningKey::from_bytes(&[42u8; 32]);
        let l1 = signed_receipt_line(&host, "s1", "delete_note", "Jane Q. Operator", None);
        let h1 = sha256_hex(l1.as_bytes());
        let l2 = signed_receipt_line(&host, "s2", "wire_funds", "Jane Q. Operator", Some(&h1));

        let input = WindowInput {
            org_id: "acme".into(),
            business_unit: Some("enclave-7".into()),
            window_from_ms: 1000,
            window_to_ms: 2000,
            seq: 1,
            prev_envelope_hash: None,
            produced_ms: 2000,
            sources: vec![SourceWindow {
                source: "notes.jsonl".into(),
                lines: vec![l1, l2],
                prev_tail_hash: None,
            }],
        };
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let signed = build_signed_envelope(&input, &key, &[3u8; 32]).expect("build");

        // Round-trips through the shared verifier.
        let v = serde_json::to_value(&signed).unwrap();
        assert!(
            verify_envelope(&v).is_ok(),
            "the built envelope must verify"
        );

        // Redaction held: no operator name; a non-allowlisted destructive id bucketed; pseudonym present.
        let s = serde_json::to_string(&signed).unwrap();
        assert!(!s.contains("Jane"), "operator name must not leak");
        assert!(
            !s.contains("wire_funds"),
            "a non-allowlisted destructive id must bucket, not pass verbatim"
        );
        assert!(s.contains("\"op_"), "operator appears only as a pseudonym");

        // Coherent counts + intact chain.
        assert_eq!(signed.envelope.counts.receipts, 2);
        assert_eq!(signed.envelope.counts.verified, 2);
        assert_eq!(signed.envelope.counts.failed, 0);
        assert_eq!(signed.envelope.counts.destructive, 2); // delete_note + wire_funds
        assert!(signed.envelope.integrity.chain_intact);
        assert!(signed.envelope.integrity.broken_sources.is_empty());

        // Tamper a signed field → verification fails.
        let mut t = v.clone();
        t["envelope"]["org_id"] = serde_json::json!("evil-corp");
        assert!(verify_envelope(&t).is_err());
    }

    #[test]
    fn a_broken_source_chain_is_flagged() {
        let host = SigningKey::from_bytes(&[42u8; 32]);
        // l2 declares a prev_hash but its predecessor is absent → a break at line 1 of the source.
        let l2 = signed_receipt_line(&host, "s2", "list_notes", "op", Some("deadbeef"));
        let input = WindowInput {
            org_id: "acme".into(),
            business_unit: None,
            window_from_ms: 0,
            window_to_ms: 1,
            seq: 1,
            prev_envelope_hash: None,
            produced_ms: 1,
            sources: vec![SourceWindow {
                source: "notes.jsonl".into(),
                lines: vec![l2],
                prev_tail_hash: None,
            }],
        };
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let signed = build_signed_envelope(&input, &key, &[3u8; 32]).unwrap();
        assert!(
            !signed.envelope.integrity.chain_intact,
            "a dangling prev_hash must break the chain"
        );
        assert_eq!(
            signed.envelope.integrity.broken_sources,
            vec!["notes.jsonl@1"]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `load_or_create_seed` is stable across reloads, `0600`, and refuses to overwrite a corrupt file.
    /// Tests the core directly with a temp path (no `$HOME` override → no cross-test races).
    #[test]
    fn seed_is_stable_persisted_0600_and_corrupt_is_an_error() {
        let dir = std::env::temp_dir().join(format!("kriya-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("evidence.key");

        let s1 = load_or_create_seed(&path).expect("mint seed");
        let s2 = load_or_create_seed(&path).expect("reload seed");
        assert_eq!(s1, s2, "seed must be stable across reloads");
        assert_eq!(s1.len(), 32);
        // The evidence key derived from a stable seed is a stable device_pub.
        assert_eq!(
            hex::encode(SigningKey::from_bytes(&s1).verifying_key().to_bytes()),
            hex::encode(SigningKey::from_bytes(&s2).verifying_key().to_bytes()),
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the seed file must be 0600");
        }

        std::fs::write(&path, "not-valid-hex").unwrap();
        assert!(
            load_or_create_seed(&path).is_err(),
            "a corrupt seed file must error, never be silently regenerated"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
