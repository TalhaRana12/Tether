//! Merkle inclusion proof verification, RFC 6962 §2.1.1.
//!
//! This is check 2 of the four in spec §6.1. Its purpose is not to prevent a rogue
//! release — an attacker holding the signing key can still produce one. Its purpose
//! is to make a rogue release **undeniable**: a signature only verifies if the
//! artifact also appears in a public append-only log, so the forgery is published
//! where you can find it. Detection, not prevention (T5, T16).
//!
//! Hash construction is RFC 6962's, and the domain-separation prefixes are the
//! whole point of it: leaves are hashed with 0x00 and interior nodes with 0x01, so
//! no leaf can be forged to collide with a node. Dropping the prefixes is a
//! second-preimage attack, not a micro-optimisation.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// A Rekor inclusion proof: the audit path from a leaf to the tree root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// 0-based index of the leaf within the log.
    pub leaf_index: u64,
    /// Total number of leaves in the tree the proof was issued against.
    pub tree_size: u64,
    /// The root the proof must reproduce.
    pub root_hash: Hash,
    /// Audit path, leaf-ward first.
    pub path: Vec<Hash>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RekorError {
    #[error("leaf index {index} is outside a tree of size {tree_size}")]
    IndexOutOfRange { index: u64, tree_size: u64 },

    #[error("empty tree cannot contain an inclusion proof")]
    EmptyTree,

    #[error("audit path has {got} hashes; a tree of size {tree_size} needs {expected}")]
    PathLengthMismatch {
        got: usize,
        expected: usize,
        tree_size: u64,
    },

    #[error("recomputed root does not match the proof's root; artifact is not in the log")]
    RootMismatch,
}

/// RFC 6962 leaf hash: `SHA256(0x00 || data)`.
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA256(0x01 || left || right)`.
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n`. RFC 6962's `k`. Requires `n > 1`.
fn split_point(n: u64) -> u64 {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Verify that `leaf_hash` is included in the log described by `proof`.
///
/// Returns `Ok(())` only when the audit path reproduces `proof.root_hash` exactly.
pub fn verify_inclusion(leaf_hash: &Hash, proof: &InclusionProof) -> Result<(), RekorError> {
    // Structural checks first, so a malformed proof is rejected on its shape rather
    // than left to fail on an accidental hash comparison. Order matters for the
    // empty-tree case: index 0 in a tree of size 0 satisfies both guards, and
    // "empty tree" is the more accurate diagnosis.
    if proof.tree_size == 0 {
        return Err(RekorError::EmptyTree);
    }
    if proof.leaf_index >= proof.tree_size {
        return Err(RekorError::IndexOutOfRange {
            index: proof.leaf_index,
            tree_size: proof.tree_size,
        });
    }

    let expected = expected_path_length(proof.leaf_index, proof.tree_size);
    if proof.path.len() != expected {
        return Err(RekorError::PathLengthMismatch {
            got: proof.path.len(),
            expected,
            tree_size: proof.tree_size,
        });
    }

    // RFC 6962 section 2.1.1. `node` tracks the position within the current level and
    // `last` the index of the rightmost node at that level; comparing them is how the
    // algorithm knows it is on a ragged right edge, where a node is promoted rather
    // than paired.
    let mut node = proof.leaf_index;
    let mut last = proof.tree_size - 1;
    let mut acc = *leaf_hash;

    for sibling in &proof.path {
        // An odd index is a right child, so its sibling is on the left. `node ==
        // last` is the ragged-right-edge case: the rightmost node at this level has
        // no right sibling, so it too pairs on the left.
        let is_right_child = !node.is_multiple_of(2);

        if is_right_child || node == last {
            acc = hash_children(sibling, &acc);
            // Climb past the levels this node was promoted through unchanged.
            while node != 0 && node.is_multiple_of(2) {
                node /= 2;
                last /= 2;
            }
        } else {
            acc = hash_children(&acc, sibling);
        }
        node /= 2;
        last /= 2;
    }

    // Constant-time comparison is not required here: both values are public. The
    // root is published in the log and the recomputed value is derived from public
    // inputs, so there is no secret for a timing side channel to leak.
    if acc == proof.root_hash {
        Ok(())
    } else {
        Err(RekorError::RootMismatch)
    }
}

/// Expected audit-path length for a leaf in a tree of the given size.
///
/// Checked before walking the path so a truncated or padded proof is rejected on
/// structure rather than on an accidental hash collision.
pub fn expected_path_length(leaf_index: u64, tree_size: u64) -> usize {
    let mut n = tree_size;
    let mut i = leaf_index;
    let mut len = 0;

    while n > 1 {
        let k = split_point(n);
        if i < k {
            n = k;
        } else {
            i -= k;
            n -= k;
        }
        len += 1;
    }

    len
}
