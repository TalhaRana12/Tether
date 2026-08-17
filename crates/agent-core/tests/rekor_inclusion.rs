//! HR-12.2 check 2 — Merkle inclusion proof verification (RFC 6962 §2.1.1).
//!
//! **On fixture honesty.** WORKING-AGREEMENT §6 requires fixtures to be real shapes
//! and warns that inventing a payload matching your assumption tests the assumption
//! against itself. So the trees here are built by `reference` below — a deliberately
//! naive *recursive* transcription of RFC 6962 §2.1, independent of the *iterative*
//! algorithm under test. Two implementations of the same spec agreeing is real
//! evidence; one implementation agreeing with itself is not.
//!
//! It is still synthetic. Replacing these with captured Rekor proofs is required
//! before Phase 10 ships an auto-updater — tracked as BLK-12, which also covers the
//! unpinned Rekor entry body format.

use tether_agent_core::rekor::{
    expected_path_length, hash_children, hash_leaf, verify_inclusion, Hash, InclusionProof,
    RekorError,
};

/// Independent reference implementation of RFC 6962 §2.1, recursive form.
mod reference {
    use super::*;

    /// Largest power of two strictly less than n. RFC 6962's `k`.
    fn split(n: usize) -> usize {
        assert!(n > 1);
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        k
    }

    /// MTH(D[n]) — the Merkle Tree Hash.
    pub fn root(leaves: &[Vec<u8>]) -> Hash {
        match leaves.len() {
            0 => panic!("reference: empty tree has no root in this test"),
            1 => hash_leaf(&leaves[0]),
            n => {
                let k = split(n);
                hash_children(&root(&leaves[..k]), &root(&leaves[k..]))
            }
        }
    }

    /// PATH(m, D[n]) — the audit path, leaf-ward first.
    pub fn path(m: usize, leaves: &[Vec<u8>]) -> Vec<Hash> {
        let n = leaves.len();
        if n <= 1 {
            return vec![];
        }
        let k = split(n);
        if m < k {
            let mut p = path(m, &leaves[..k]);
            p.push(root(&leaves[k..]));
            p
        } else {
            let mut p = path(m - k, &leaves[k..]);
            p.push(root(&leaves[..k]));
            p
        }
    }
}

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("artifact-digest-{i}").into_bytes())
        .collect()
}

fn proof_for(leaf_index: usize, ls: &[Vec<u8>]) -> InclusionProof {
    InclusionProof {
        leaf_index: leaf_index as u64,
        tree_size: ls.len() as u64,
        root_hash: reference::root(ls),
        path: reference::path(leaf_index, ls),
    }
}

/// The property that matters: a genuine proof verifies, for every leaf, across tree
/// shapes that exercise both balanced and ragged right edges.
#[test]
fn genuine_proof_verifies_for_every_leaf() {
    for n in 1..=9usize {
        let ls = leaves(n);
        for i in 0..n {
            let proof = proof_for(i, &ls);
            assert_eq!(
                verify_inclusion(&hash_leaf(&ls[i]), &proof),
                Ok(()),
                "tree_size={n} leaf_index={i} should verify"
            );
        }
    }
}

/// An artifact that is not in the log must not verify — this is the whole control.
#[test]
fn leaf_not_in_the_log_is_rejected() {
    let ls = leaves(8);
    let proof = proof_for(3, &ls);
    let impostor = hash_leaf(b"artifact-digest-not-logged");

    assert_eq!(
        verify_inclusion(&impostor, &proof),
        Err(RekorError::RootMismatch),
        "a digest absent from the log must fail; otherwise a rogue release is \
         invisible, which is the only thing this check buys us (T5, T16)"
    );
}

#[test]
fn tampered_root_is_rejected() {
    let ls = leaves(5);
    let mut proof = proof_for(2, &ls);
    proof.root_hash[0] ^= 0x01;

    assert_eq!(
        verify_inclusion(&hash_leaf(&ls[2]), &proof),
        Err(RekorError::RootMismatch)
    );
}

#[test]
fn tampered_path_element_is_rejected() {
    let ls = leaves(7);
    let mut proof = proof_for(6, &ls);
    proof.path[0][31] ^= 0xff;

    assert_eq!(
        verify_inclusion(&hash_leaf(&ls[6]), &proof),
        Err(RekorError::RootMismatch)
    );
}

#[test]
fn index_outside_the_tree_is_rejected() {
    let ls = leaves(4);
    let mut proof = proof_for(1, &ls);
    proof.leaf_index = 4;

    assert_eq!(
        verify_inclusion(&hash_leaf(&ls[1]), &proof),
        Err(RekorError::IndexOutOfRange {
            index: 4,
            tree_size: 4
        })
    );
}

#[test]
fn empty_tree_is_rejected() {
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 0,
        root_hash: [0u8; 32],
        path: vec![],
    };
    assert_eq!(
        verify_inclusion(&hash_leaf(b"anything"), &proof),
        Err(RekorError::EmptyTree)
    );
}

/// Structural checks before hashing. A truncated or padded path must be rejected on
/// its shape, not left to fail by accidental collision.
#[test]
fn truncated_path_is_rejected_on_structure() {
    let ls = leaves(8);
    let mut proof = proof_for(5, &ls);
    let full = proof.path.len();
    proof.path.pop();

    assert_eq!(
        verify_inclusion(&hash_leaf(&ls[5]), &proof),
        Err(RekorError::PathLengthMismatch {
            got: full - 1,
            expected: full,
            tree_size: 8
        })
    );
}

#[test]
fn overlong_path_is_rejected_on_structure() {
    let ls = leaves(8);
    let mut proof = proof_for(5, &ls);
    let full = proof.path.len();
    proof.path.push([0u8; 32]);

    assert_eq!(
        verify_inclusion(&hash_leaf(&ls[5]), &proof),
        Err(RekorError::PathLengthMismatch {
            got: full + 1,
            expected: full,
            tree_size: 8
        })
    );
}

#[test]
fn expected_path_length_matches_the_reference() {
    for n in 1..=17usize {
        let ls = leaves(n);
        for i in 0..n {
            assert_eq!(
                expected_path_length(i as u64, n as u64),
                reference::path(i, &ls).len(),
                "tree_size={n} leaf_index={i}"
            );
        }
    }
}

/// RFC 6962's domain separation, and why it is not decoration.
///
/// Leaves hash with 0x00 and interior nodes with 0x01. Without the prefixes an
/// attacker can present an interior node as a leaf — a second-preimage attack that
/// forges inclusion for content that was never logged.
#[test]
fn leaf_and_node_hashing_are_domain_separated() {
    let a = hash_leaf(b"left");
    let b = hash_leaf(b"right");

    let node = hash_children(&a, &b);

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&a);
    concatenated.extend_from_slice(&b);
    let as_leaf = hash_leaf(&concatenated);

    assert_ne!(
        node, as_leaf,
        "interior nodes and leaves must not share a hash construction, or an \
         interior node can be replayed as a leaf (RFC 6962 §2.1)"
    );
}
