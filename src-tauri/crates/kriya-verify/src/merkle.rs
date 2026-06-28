//! RFC-6962-style Merkle tree over receipt LINE bytes — SHA-256 composed, no new crypto (0.7). An
//! envelope commits to its window's raw receipt lines via [`merkle_root`] WITHOUT revealing them; a
//! later spot-audit proves a specific line was in the window via [`merkle_proof`]/[`merkle_verify`].
//!
//! **Domain separation is load-bearing.** Leaf = `sha256(0x00 || line)`, internal node =
//! `sha256(0x01 || left || right)`. The distinct tags mean a leaf hash can never equal an
//! internal-node hash, so an interior node cannot be presented as a leaf (the classic second-preimage
//! / tree-restructuring forgery). [`merkle_verify`] re-applies the `0x00` leaf tag, so the caller
//! passes the RAW line, not a pre-hash.

use sha2::{Digest, Sha256};

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

/// SHA-256 over the concatenation of `parts`, as a fixed 32-byte array (avoids GenericArray churn).
fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn leaf_hash(line: &[u8]) -> [u8; 32] {
    sha256_concat(&[&[LEAF_TAG], line])
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[&[NODE_TAG], left, right])
}

fn decode32(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

/// Build the next level up, duplicating the last node on an odd count.
fn fold_up(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        let left = level[i];
        let right = if i + 1 < level.len() {
            level[i + 1]
        } else {
            level[i] // duplicate-last
        };
        next.push(node_hash(&left, &right));
        i += 2;
    }
    next
}

/// Merkle root (lowercase hex) over `leaves` (each the RAW receipt line bytes), in the given order.
/// Empty input → `sha256(0x00)` (the leaf tag over no data), a documented sentinel.
pub fn merkle_root(leaves: &[Vec<u8>]) -> String {
    if leaves.is_empty() {
        return hex::encode(leaf_hash(&[]));
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| leaf_hash(l)).collect();
    while level.len() > 1 {
        level = fold_up(&level);
    }
    hex::encode(level[0])
}

/// The audit path for the leaf at `index`: `(sibling_hex, sibling_is_right)` from the leaf level up to
/// the root. Empty when `index` is out of range.
pub fn merkle_proof(leaves: &[Vec<u8>], index: usize) -> Vec<(String, bool)> {
    let mut proof = Vec::new();
    if index >= leaves.len() {
        return proof;
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| leaf_hash(l)).collect();
    let mut idx = index;
    while level.len() > 1 {
        // If the current node is a left child its sibling is on the RIGHT (or itself, if it is the
        // odd last node — duplicate-last); if it is a right child the sibling is on the left.
        let sibling_is_right = idx % 2 == 0;
        let sibling_idx = if sibling_is_right {
            if idx + 1 < level.len() {
                idx + 1
            } else {
                idx
            }
        } else {
            idx - 1
        };
        proof.push((hex::encode(level[sibling_idx]), sibling_is_right));
        level = fold_up(&level);
        idx /= 2;
    }
    proof
}

/// Verify that `leaf_line` (the RAW line) is committed under `root` via `proof`. Re-applies the `0x00`
/// leaf tag, so an internal-node value cannot masquerade as a leaf.
pub fn merkle_verify(leaf_line: &[u8], proof: &[(String, bool)], root: &str) -> bool {
    let mut acc = leaf_hash(leaf_line);
    for (sib_hex, sib_is_right) in proof {
        let sib = match decode32(sib_hex) {
            Some(s) => s,
            None => return false,
        };
        acc = if *sib_is_right {
            node_hash(&acc, &sib)
        } else {
            node_hash(&sib, &acc)
        };
    }
    hex::encode(acc) == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| format!("receipt-line-{i}").into_bytes())
            .collect()
    }

    #[test]
    fn root_is_deterministic_and_order_sensitive() {
        let a = leaves(4);
        assert_eq!(merkle_root(&a), merkle_root(&a), "deterministic");
        let mut b = a.clone();
        b.swap(0, 1);
        assert_ne!(
            merkle_root(&a),
            merkle_root(&b),
            "leaf order changes the root"
        );
    }

    #[test]
    fn empty_root_is_tagged_hash_of_nothing() {
        let expect = hex::encode(sha256_concat(&[&[LEAF_TAG]]));
        assert_eq!(merkle_root(&[]), expect, "empty → sha256(0x00)");
    }

    #[test]
    fn membership_proof_verifies_for_every_leaf() {
        // Cover even, odd, and single-leaf trees (the duplicate-last path).
        for n in [1usize, 2, 3, 4, 5, 8, 9] {
            let ls = leaves(n);
            let root = merkle_root(&ls);
            for i in 0..n {
                let proof = merkle_proof(&ls, i);
                assert!(
                    merkle_verify(&ls[i], &proof, &root),
                    "leaf {i} of {n} must verify"
                );
                let other = (i + 1) % n;
                if other != i {
                    assert!(
                        !merkle_verify(&ls[other], &proof, &root),
                        "a different leaf must not verify with leaf {i}'s proof (n={n})"
                    );
                }
            }
        }
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let ls = leaves(4);
        let root = merkle_root(&ls);
        let mut proof = merkle_proof(&ls, 2);
        // Flip the first hex nibble of the first sibling — still valid hex, wrong value.
        let mut chars: Vec<char> = proof[0].0.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        proof[0].0 = chars.into_iter().collect();
        assert!(
            !merkle_verify(&ls[2], &proof, &root),
            "a tampered proof must fail"
        );
    }

    #[test]
    fn internal_node_cannot_masquerade_as_a_leaf() {
        // The classic second-preimage / leaf-as-internal-node forgery. For a 2-leaf tree the root IS
        // the internal node node_hash(leaf(a), leaf(b)). Hand the verifier the EXACT preimage of the
        // root (0x01 || leaf(a) || leaf(b)) as if it were a leaf, with an empty proof. Because
        // merkle_verify re-applies the 0x00 LEAF tag, leaf_hash(preimage) = sha256(0x00 || 0x01||..)
        // can never equal root = sha256(0x01 || ..). Domain separation defeats the attack.
        let (a, b) = (b"a".to_vec(), b"b".to_vec());
        let root = merkle_root(&[a.clone(), b.clone()]);

        let mut root_preimage = vec![NODE_TAG];
        root_preimage.extend_from_slice(&leaf_hash(&a));
        root_preimage.extend_from_slice(&leaf_hash(&b));
        // Sanity: this really is the root's preimage (an UNTAGGED sha256 of it equals the root).
        assert_eq!(
            hex::encode(sha256_concat(&[&root_preimage])),
            root,
            "constructed the genuine internal-node preimage"
        );
        // ...yet presenting it as a leaf fails, because the verifier leaf-tags it.
        assert!(
            !merkle_verify(&root_preimage, &[], &root),
            "an internal-node value must NOT verify as a leaf (domain separation)"
        );
    }
}
