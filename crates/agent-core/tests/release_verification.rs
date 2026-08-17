//! HR-12.2 and HR-12.3 — the four release checks and the rollback path.
//!
//! Spec Phase 0 exit criteria covered here, quoted verbatim:
//!
//! "a stub agent verifies signature + Rekor proof + version monotonicity and rejects
//! a deliberately downgraded build"
//!
//! "a rollback manifest with a stale epoch is rejected; one with a fresh epoch is
//! accepted"
//!
//! Spec §8 (Update row): "Downgrade attempt, missing Rekor proof, valid signature
//! with wrong embedded key — all rejected. Rollback manifest: stale epoch rejected,
//! fresh epoch accepted, replay of a used manifest rejected."
//!
//! Signing keys here are deterministic test seeds. That is safe *because* nothing in
//! this project derives a real key from a guessable value (HR-0.3) — the real
//! release key is an offline YubiKey (HR-12.1) and never appears in source.

use ed25519_dalek::{Signer, SigningKey};
use semver::Version;
use tether_agent_core::rekor::{hash_children, hash_leaf, Hash, InclusionProof};
use tether_agent_core::release::{
    manifest_digest, verify_release, verify_rollback, AgentState, PinnedReleaseKey, Reject,
    SignedManifest, MANIFEST_V,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn real_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A different key entirely — the "valid signature, wrong embedded key" case.
fn attacker_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn pinned(k: &SigningKey) -> PinnedReleaseKey {
    PinnedReleaseKey::from_bytes(&k.verifying_key().to_bytes()).expect("valid test key")
}

fn sign_with(k: &SigningKey, bytes: &[u8]) -> SignedManifest {
    SignedManifest {
        bytes: bytes.to_vec(),
        signature: k.sign(bytes).to_bytes(),
    }
}

fn release_json(version: &str, rollout: u8) -> Vec<u8> {
    format!(
        r#"{{"v":{MANIFEST_V},"version":"{version}","artifacts":[{{"name":"tether-agent.exe","sha256":"{}"}}],"rollout_percent":{rollout}}}"#,
        "ab".repeat(32)
    )
    .into_bytes()
}

fn rollback_json(epoch: u64, target: &str, bad: &str) -> Vec<u8> {
    format!(
        r#"{{"v":{MANIFEST_V},"epoch":{epoch},"target_version":"{target}","bad_version":"{bad}","artifacts":[{{"name":"tether-agent.exe","sha256":"{}"}}]}}"#,
        "cd".repeat(32)
    )
    .into_bytes()
}

/// A genuine 2-leaf inclusion proof placing `bytes`' digest in the log.
///
/// The sibling is a fixed unrelated leaf, so the tree is real rather than
/// degenerate — a 1-leaf tree would let a broken verifier pass by ignoring the path.
fn genuine_proof(bytes: &[u8]) -> InclusionProof {
    let ours = hash_leaf(&manifest_digest(bytes));
    let sibling = hash_leaf(b"some other logged entry");
    InclusionProof {
        leaf_index: 0,
        tree_size: 2,
        root_hash: hash_children(&ours, &sibling),
        path: vec![sibling],
    }
}

fn state(current: &str, cohort: u8, last_epoch: u64) -> AgentState {
    AgentState {
        current_version: Version::parse(current).unwrap(),
        last_rollback_epoch: last_epoch,
        cohort_percent: cohort,
    }
}

// ---------------------------------------------------------------------------
// Check 1 — signature against the compiled-in key
// ---------------------------------------------------------------------------

#[test]
fn valid_release_passing_all_four_checks_is_accepted() {
    let k = real_key();
    let bytes = release_json("1.2.0", 100);
    let m = verify_release(
        &sign_with(&k, &bytes),
        &genuine_proof(&bytes),
        &pinned(&k),
        &state("1.1.0", 50, 0),
    )
    .expect("a genuine release must be accepted");

    assert_eq!(m.version, Version::parse("1.2.0").unwrap());
    assert_eq!(m.artifacts.len(), 1);
}

/// Spec §8: "valid signature with wrong embedded key — rejected."
///
/// The signature is cryptographically valid; it is simply not by *our* key. An agent
/// that accepted this would accept any release from anyone.
#[test]
fn signature_by_a_different_key_is_rejected() {
    let bytes = release_json("1.2.0", 100);
    assert_eq!(
        verify_release(
            &sign_with(&attacker_key(), &bytes),
            &genuine_proof(&bytes),
            &pinned(&real_key()),
            &state("1.1.0", 50, 0),
        ),
        Err(Reject::BadSignature)
    );
}

#[test]
fn tampered_manifest_body_is_rejected() {
    let k = real_key();
    let bytes = release_json("1.2.0", 100);
    let mut signed = sign_with(&k, &bytes);
    // Flip the release version after signing — the classic downgrade-in-transit.
    signed.bytes = release_json("9.9.9", 100);

    assert_eq!(
        verify_release(
            &signed,
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.1.0", 50, 0)
        ),
        Err(Reject::BadSignature)
    );
}

/// **Ordering test.** Signature verification must happen before the JSON parser
/// runs, so unsigned input never reaches the larger attack surface. Garbage bytes
/// with a bad signature must be rejected as `BadSignature`, never as `Malformed` —
/// a `Malformed` here would prove the parser ran first.
#[test]
fn signature_is_checked_before_the_body_is_parsed() {
    let k = real_key();
    let garbage = b"}{ this is not json at all".to_vec();
    let signed = SignedManifest {
        bytes: garbage.clone(),
        signature: [0u8; 64],
    };

    assert_eq!(
        verify_release(
            &signed,
            &genuine_proof(&garbage),
            &pinned(&k),
            &state("1.1.0", 50, 0)
        ),
        Err(Reject::BadSignature),
        "a Malformed error here means the JSON parser was reached by unsigned \
         input — the same class of mistake HR-2.5 forbids for gated message bodies"
    );
}

// ---------------------------------------------------------------------------
// Check 2 — Rekor inclusion proof
// ---------------------------------------------------------------------------

#[test]
fn release_absent_from_the_transparency_log_is_rejected() {
    let k = real_key();
    let bytes = release_json("1.2.0", 100);

    // A structurally valid proof for a *different* artifact.
    let bogus = genuine_proof(b"a manifest we never published");

    assert!(matches!(
        verify_release(
            &sign_with(&k, &bytes),
            &bogus,
            &pinned(&k),
            &state("1.1.0", 50, 0)
        ),
        Err(Reject::RekorProofInvalid(_))
    ));
}

// ---------------------------------------------------------------------------
// Check 3 — version monotonicity
// ---------------------------------------------------------------------------

/// Spec Phase 0 exit: "rejects a deliberately downgraded build."
#[test]
fn downgrade_is_refused() {
    let k = real_key();
    let bytes = release_json("1.0.0", 100);

    assert_eq!(
        verify_release(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.1.0", 50, 0)
        ),
        Err(Reject::NotAnUpgrade {
            offered: Version::parse("1.0.0").unwrap(),
            current: Version::parse("1.1.0").unwrap(),
        })
    );
}

/// HR-12.2 says `version > current_version`, strictly. Re-serving the running
/// version is a replay, so `>=` would be a bug.
#[test]
fn same_version_is_refused_not_reinstalled() {
    let k = real_key();
    let bytes = release_json("1.1.0", 100);

    assert!(matches!(
        verify_release(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.1.0", 50, 0)
        ),
        Err(Reject::NotAnUpgrade { .. })
    ));
}

// ---------------------------------------------------------------------------
// Check 4 — staged rollout cohort
// ---------------------------------------------------------------------------

#[test]
fn agent_outside_the_current_cohort_waits() {
    let k = real_key();
    let bytes = release_json("1.2.0", 5);

    assert_eq!(
        verify_release(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.1.0", 60, 0)
        ),
        Err(Reject::CohortNotReached {
            cohort: 60,
            rollout: 5
        })
    );
}

#[test]
fn agent_inside_the_current_cohort_proceeds() {
    let k = real_key();
    let bytes = release_json("1.2.0", 25);

    assert!(verify_release(
        &sign_with(&k, &bytes),
        &genuine_proof(&bytes),
        &pinned(&k),
        &state("1.1.0", 25, 0)
    )
    .is_ok());
}

#[test]
fn rollout_percent_outside_the_staged_values_is_rejected() {
    let k = real_key();
    let bytes = release_json("1.2.0", 73);

    assert_eq!(
        verify_release(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.1.0", 1, 0)
        ),
        Err(Reject::InvalidRolloutPercent { got: 73 })
    );
}

// ---------------------------------------------------------------------------
// Manifest hygiene
// ---------------------------------------------------------------------------

#[test]
fn wrong_manifest_schema_version_is_rejected() {
    let k = real_key();
    let bytes = br#"{"v":99,"version":"1.2.0","artifacts":[],"rollout_percent":100}"#.to_vec();

    assert_eq!(
        verify_release(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.1.0", 1, 0)
        ),
        Err(Reject::WrongManifestVersion { got: 99 })
    );
}

#[test]
fn unknown_manifest_field_is_rejected_not_ignored() {
    let k = real_key();
    let bytes = br#"{"v":1,"version":"1.2.0","artifacts":[],"rollout_percent":100,"skip_signature_check":true}"#.to_vec();

    assert!(matches!(
        verify_release(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.1.0", 1, 0)
        ),
        Err(Reject::Malformed(_))
    ));
}

// ---------------------------------------------------------------------------
// HR-12.3 — the rollback path
// ---------------------------------------------------------------------------

/// Spec Phase 0 exit: "one with a fresh epoch is accepted."
#[test]
fn rollback_with_fresh_epoch_is_accepted() {
    let k = real_key();
    let bytes = rollback_json(4, "1.1.0", "1.2.0");

    let m = verify_rollback(
        &sign_with(&k, &bytes),
        &genuine_proof(&bytes),
        &pinned(&k),
        &state("1.2.0", 50, 3),
    )
    .expect("a fresh, correctly-targeted rollback must be accepted");

    assert_eq!(m.target_version, Version::parse("1.1.0").unwrap());
    assert_eq!(m.epoch, 4);
}

/// Spec Phase 0 exit: "a rollback manifest with a stale epoch is rejected."
#[test]
fn rollback_with_stale_epoch_is_rejected() {
    let k = real_key();
    let bytes = rollback_json(2, "1.1.0", "1.2.0");

    assert_eq!(
        verify_rollback(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.2.0", 50, 3)
        ),
        Err(Reject::RollbackEpochNotFresh {
            offered: 2,
            last_seen: 3
        })
    );
}

/// Spec §8: "replay of a used manifest rejected."
///
/// The epoch equal to the last one seen is exactly a replay of the manifest already
/// applied. Without this, an attacker could re-serve a legitimate old rollback to
/// force a downgrade — which would defeat check 3 through the side door.
#[test]
fn replay_of_an_already_applied_rollback_is_rejected() {
    let k = real_key();
    let bytes = rollback_json(3, "1.1.0", "1.2.0");

    assert_eq!(
        verify_rollback(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.2.0", 50, 3)
        ),
        Err(Reject::RollbackEpochNotFresh {
            offered: 3,
            last_seen: 3
        })
    );
}

/// HR-12.3: the bad version is named explicitly, so a rollback issued against one
/// release cannot be repurposed against another.
#[test]
fn rollback_naming_a_version_this_agent_is_not_running_is_rejected() {
    let k = real_key();
    let bytes = rollback_json(4, "1.0.0", "1.1.0");

    assert_eq!(
        verify_rollback(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.2.0", 50, 3)
        ),
        Err(Reject::RollbackDoesNotNameCurrentVersion {
            named: Version::parse("1.1.0").unwrap(),
            current: Version::parse("1.2.0").unwrap(),
        })
    );
}

#[test]
fn rollback_that_is_not_actually_a_downgrade_is_rejected() {
    let k = real_key();
    let bytes = rollback_json(4, "1.3.0", "1.2.0");

    assert_eq!(
        verify_rollback(
            &sign_with(&k, &bytes),
            &genuine_proof(&bytes),
            &pinned(&k),
            &state("1.2.0", 50, 3)
        ),
        Err(Reject::RollbackIsNotADowngrade {
            target: Version::parse("1.3.0").unwrap(),
            current: Version::parse("1.2.0").unwrap(),
        })
    );
}

#[test]
fn rollback_signed_by_the_wrong_key_is_rejected() {
    let bytes = rollback_json(4, "1.1.0", "1.2.0");

    assert_eq!(
        verify_rollback(
            &sign_with(&attacker_key(), &bytes),
            &genuine_proof(&bytes),
            &pinned(&real_key()),
            &state("1.2.0", 50, 3)
        ),
        Err(Reject::BadSignature),
        "HR-12.3: signing a rollback still requires the offline key. The panel only \
         stages the request (HR-9.8)."
    );
}

/// Sanity check on the digest helper the Rekor leaf is built from.
#[test]
fn manifest_digest_is_over_the_bytes_as_received() {
    let a = manifest_digest(b"one");
    let b = manifest_digest(b"two");
    assert_ne!(a, b);
    assert_eq!(a, manifest_digest(b"one"), "must be deterministic");
    assert_eq!(a.len(), 32);
    let _: Hash = a;
}
