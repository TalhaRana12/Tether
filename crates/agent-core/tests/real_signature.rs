//! The loop that actually matters: does the **agent** accept what the **operator tool**
//! produced, using a key sealed in a real TPM?
//!
//! Every other test in this crate signs with a deterministic seed defined inside the test.
//! That proves the verifier is self-consistent — and self-consistency is exactly what a
//! signing pipeline fails at. The interesting failure is not "the verifier is wrong", it
//! is "the signer and the verifier disagree", and no test that generates its own
//! signature can ever see it.
//!
//! WORKING-AGREEMENT §6: *"Fixtures must be real shapes. Capture what the actual system
//! produces. Never invent a payload that matches your assumption — that tests your
//! assumption against itself."*
//!
//! So the fixtures here were **captured from a real signing ceremony** on 2026-08-17:
//!
//!   1. `tether-sign-release keygen` produced an Ed25519 keypair from OS CSPRNG
//!   2. the 32-byte seed was sealed under a **non-exportable TPM RSA key**
//!      (`tools/tpm-seal.ps1`, export policy `None`)
//!   3. the plaintext seed was deleted; the sealed blob is the only copy
//!   4. `tpm-seal.ps1 -Unseal | tether-sign-release sign` produced the signature below
//!
//! Nothing in this file was hand-written except the assertions. If the signer changes how
//! it canonicalises, pads, or orders anything, this test goes red and the deterministic
//! tests stay green — which is the whole point of keeping it separate.
//!
//! This is spec Phase 0's exit criterion *"you sign one manually with the YubiKey"*, with
//! the TPM substituted for the YubiKey and the substitution's cost recorded at HR-0.2.

use tether_agent_core::release::{PinnedReleaseKey, Reject, SignedManifest};

const MANIFEST: &[u8] = include_bytes!("fixtures/real-release-manifest.json");
const SIG_HEX: &str = include_str!("fixtures/real-release-manifest.sig");
const PUB_HEX: &str = include_str!("fixtures/release-signing-key.pub");

fn pinned() -> PinnedReleaseKey {
    let raw: [u8; 32] = hex::decode(PUB_HEX.trim())
        .expect("fixture public key is hex")
        .try_into()
        .expect("fixture public key is 32 bytes");
    PinnedReleaseKey::from_bytes(&raw).expect("fixture public key is a valid Ed25519 point")
}

fn signed() -> SignedManifest {
    let sig: [u8; 64] = hex::decode(SIG_HEX.trim())
        .expect("fixture signature is hex")
        .try_into()
        .expect("fixture signature is 64 bytes");
    SignedManifest {
        bytes: MANIFEST.to_vec(),
        signature: sig,
    }
}

/// The agent accepts a signature produced by the real TPM-backed ceremony.
///
/// Uses the crate's own signature check rather than a separate Ed25519 call, so this
/// exercises the code path an agent actually runs.
#[test]
fn agent_accepts_a_signature_from_the_real_tpm_ceremony() {
    let err = tether_agent_core::release::verify_release(
        &signed(),
        &tether_agent_core::rekor::InclusionProof {
            leaf_index: 0,
            tree_size: 1,
            root_hash: tether_agent_core::rekor::hash_leaf(
                &tether_agent_core::release::manifest_digest(MANIFEST),
            ),
            path: vec![],
        },
        &pinned(),
        &tether_agent_core::release::AgentState {
            current_version: semver::Version::parse("0.0.1").unwrap(),
            last_rollback_epoch: 0,
            cohort_percent: 5,
        },
    );

    // The signature and the Rekor proof must both pass. If this returns BadSignature the
    // signer and the verifier have diverged, which is the failure this file exists to
    // catch. Any *other* rejection would be about manifest contents, not the ceremony.
    assert!(
        !matches!(err, Err(Reject::BadSignature)),
        "the agent REJECTED a signature produced by the real signing ceremony. \
         The operator tool and the shipped verifier have diverged — releases signed \
         with this key would be refused by every agent in the field. Got: {err:?}"
    );

    err.expect("the real ceremony signature must verify end to end");
}

/// A single flipped bit in the manifest must break it.
///
/// Guards against the fixture passing for an uninteresting reason — for example a
/// verifier that ignored the signature entirely would pass the test above and fail here.
#[test]
fn one_flipped_bit_in_the_real_manifest_breaks_the_real_signature() {
    let mut s = signed();
    s.bytes[10] ^= 0x01;

    assert_eq!(
        tether_agent_core::release::verify_release(
            &s,
            &tether_agent_core::rekor::InclusionProof {
                leaf_index: 0,
                tree_size: 1,
                root_hash: tether_agent_core::rekor::hash_leaf(
                    &tether_agent_core::release::manifest_digest(&s.bytes)
                ),
                path: vec![],
            },
            &pinned(),
            &tether_agent_core::release::AgentState {
                current_version: semver::Version::parse("0.0.1").unwrap(),
                last_rollback_epoch: 0,
                cohort_percent: 5,
            },
        ),
        Err(Reject::BadSignature)
    );
}

/// The fixtures are what they claim to be.
///
/// A positive control: if `include_bytes!` ever picked up an empty or truncated file,
/// the tests above could pass or fail for reasons unrelated to the ceremony.
#[test]
fn fixtures_are_well_formed() {
    assert_eq!(
        PUB_HEX.trim().len(),
        64,
        "public key must be 32 bytes of hex"
    );
    assert_eq!(
        SIG_HEX.trim().len(),
        128,
        "signature must be 64 bytes of hex"
    );
    assert!(
        MANIFEST.len() > 50,
        "manifest fixture looks truncated: {} bytes",
        MANIFEST.len()
    );
    assert!(
        MANIFEST.starts_with(b"{"),
        "manifest fixture is not JSON as captured"
    );
}
