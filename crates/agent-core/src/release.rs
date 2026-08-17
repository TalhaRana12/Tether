//! Release and rollback manifest verification.
//!
//! HR-12.2 — an agent accepts an update only when **all four** pass:
//!   1. Ed25519 signature over the manifest, against the key compiled into the binary
//!   2. Sigstore/Rekor inclusion proof for that digest
//!   3. version > current_version   (downgrade refused)
//!   4. rollout_cohort gate — staged 5% / 25% / 100% over 24h
//!
//! HR-12.3 — a lower version is accepted **only** inside a signed rollback manifest
//! carrying its own epoch above the last one seen, naming the bad version
//! explicitly. Signing still requires the offline key; the panel only stages.
//!
//! HR-0.2 / HR-12.1 — nothing here signs anything. This module is the verify side.
//! The signing key is an offline YubiKey with touch policy `always`, and CI holds
//! no signing credential of any kind (spec §6.1, T5, T16).

use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::rekor::{self, Hash, InclusionProof, RekorError};

/// Manifest schema version. Distinct from the *release* version inside it.
pub const MANIFEST_V: u32 = 1;

/// The release signing public key, compiled into the binary.
///
/// HR-12.2 check 1 is "against the key compiled into the binary" — deliberately not
/// against anything fetched at runtime. A key the agent downloads is a key an
/// attacker who controls the CDN can replace, which is the entire AnyDesk shape
/// spec §0 rule 2 exists to avoid.
#[derive(Debug, Clone)]
pub struct PinnedReleaseKey(VerifyingKey);

impl PinnedReleaseKey {
    pub fn from_bytes(raw: &[u8; 32]) -> Result<Self, Reject> {
        VerifyingKey::from_bytes(raw).map(Self).map_err(|_| {
            Reject::Malformed("pinned release key is not a valid Ed25519 point".into())
        })
    }
}

/// One shipped file and the digest it must hash to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub sha256: Hash,
}

/// A forward release.
///
/// The Rekor inclusion proof is deliberately **not** a field here. It cannot be:
/// the proof attests the digest *of this manifest*, so embedding it would make the
/// digest depend on itself. Sigstore delivers the proof alongside the signed
/// artifact for exactly this reason, and [`verify_release`] takes it as a separate
/// argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub v: u32,
    pub version: Version,
    pub artifacts: Vec<Artifact>,
    /// Staged rollout: 5, 25, or 100 (spec §6.1 check 4).
    pub rollout_percent: u8,
}

/// A deliberate downgrade (spec §6.27, HR-12.3).
///
/// This exists because version monotonicity plus no-remote-reconfiguration plus
/// staged rollout means a broken build reaching the 5% cohort would otherwise strand
/// those machines until someone reinstalls by hand — the safety property and the
/// recovery property collide (T34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackManifest {
    pub v: u32,
    /// Monotonic. Must exceed the highest epoch this agent has seen, which is what
    /// stops a stale rollback manifest being replayed to force a downgrade.
    pub epoch: u64,
    /// The version to go back to. Lower than current — that is the point.
    pub target_version: Version,
    /// HR-12.3: the bad version is named **explicitly**, so a rollback manifest
    /// cannot be repurposed against a release it was not issued for.
    pub bad_version: Version,
    pub artifacts: Vec<Artifact>,
}

/// A manifest exactly as received, plus its detached signature.
///
/// The signature is verified over `bytes` **as received** — never over a re-encoded
/// struct. Re-serialising before verifying invites a canonicalisation bug, and two
/// distinct manifests that serialise identically is a forgery. This is also why
/// verification runs before parsing: see [`verify_release`].
#[derive(Debug, Clone)]
pub struct SignedManifest {
    pub bytes: Vec<u8>,
    pub signature: [u8; 64],
}

/// What this agent currently knows about itself.
#[derive(Debug, Clone)]
pub struct AgentState {
    pub current_version: Version,
    /// Highest rollback epoch already applied. Persisted.
    pub last_rollback_epoch: u64,
    /// This agent's staged-rollout bucket, 1..=100. Derived deterministically from
    /// the device id so a given machine is always in the same cohort.
    pub cohort_percent: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Reject {
    #[error("signature does not verify against the pinned release key (HR-12.2 check 1)")]
    BadSignature,

    #[error("manifest schema version {got}, expected {MANIFEST_V}")]
    WrongManifestVersion { got: u32 },

    #[error("malformed manifest: {0}")]
    Malformed(String),

    #[error("Rekor inclusion proof failed (HR-12.2 check 2): {0}")]
    RekorProofInvalid(#[from] RekorError),

    #[error("offered version {offered} is not newer than current {current}; downgrade refused (HR-12.2 check 3)")]
    NotAnUpgrade { offered: Version, current: Version },

    #[error("this agent is in cohort {cohort}%, rollout has reached {rollout}%; waiting (HR-12.2 check 4)")]
    CohortNotReached { cohort: u8, rollout: u8 },

    #[error("rollout_percent {got} is not one of the staged values 5/25/100")]
    InvalidRolloutPercent { got: u8 },

    #[error("rollback epoch {offered} does not exceed the last seen {last_seen}; stale or replayed manifest refused (HR-12.3)")]
    RollbackEpochNotFresh { offered: u64, last_seen: u64 },

    #[error("rollback manifest names bad version {named}, but this agent runs {current}; refused (HR-12.3)")]
    RollbackDoesNotNameCurrentVersion { named: Version, current: Version },

    #[error("rollback target {target} is not lower than current {current}; use a normal release")]
    RollbackIsNotADowngrade { target: Version, current: Version },
}

/// Verify a forward release. All four HR-12.2 checks, in order.
///
/// **Order is a security property, not a style choice.** The signature is checked
/// over the raw bytes before anything parses them, so the JSON parser — a far larger
/// attack surface than an Ed25519 verify — is never reached by an unsigned input.
/// This is the same principle as HR-2.5: enforcement before parsing a gated body,
/// never after.
pub fn verify_release(
    signed: &SignedManifest,
    proof: &InclusionProof,
    key: &PinnedReleaseKey,
    state: &AgentState,
) -> Result<ReleaseManifest, Reject> {
    // --- HR-12.2 check 1: signature, over the bytes as received ---------------
    verify_signature(signed, key)?;

    // --- HR-12.2 check 2: Rekor inclusion proof ------------------------------
    verify_logged(signed, proof)?;

    // Only now is it safe to parse. Everything above operated on opaque bytes.
    let wire: WireRelease = serde_json::from_slice(&signed.bytes)
        .map_err(|e| Reject::Malformed(format!("release manifest: {e}")))?;

    if wire.v != MANIFEST_V {
        return Err(Reject::WrongManifestVersion { got: wire.v });
    }

    // Validate at the boundary, in one place (WORKING-AGREEMENT §7). A rollout value
    // outside the staged set means the manifest was not produced by our release
    // process, whatever else is true of it.
    if !matches!(wire.rollout_percent, 5 | 25 | 100) {
        return Err(Reject::InvalidRolloutPercent {
            got: wire.rollout_percent,
        });
    }

    let version = parse_version(&wire.version, "version")?;
    let artifacts = parse_artifacts(wire.artifacts)?;

    // --- HR-12.2 check 3: strictly newer ------------------------------------
    // `>` not `>=`: re-serving the running version is a replay, and the rollback
    // manifest of HR-12.3 is the only sanctioned way to move backwards.
    if version <= state.current_version {
        return Err(Reject::NotAnUpgrade {
            offered: version,
            current: state.current_version.clone(),
        });
    }

    // --- HR-12.2 check 4: staged rollout cohort -----------------------------
    if state.cohort_percent > wire.rollout_percent {
        return Err(Reject::CohortNotReached {
            cohort: state.cohort_percent,
            rollout: wire.rollout_percent,
        });
    }

    Ok(ReleaseManifest {
        v: wire.v,
        version,
        artifacts,
        rollout_percent: wire.rollout_percent,
    })
}

/// Verify a rollback manifest (HR-12.3).
pub fn verify_rollback(
    signed: &SignedManifest,
    proof: &InclusionProof,
    key: &PinnedReleaseKey,
    state: &AgentState,
) -> Result<RollbackManifest, Reject> {
    verify_signature(signed, key)?;
    verify_logged(signed, proof)?;

    let wire: WireRollback = serde_json::from_slice(&signed.bytes)
        .map_err(|e| Reject::Malformed(format!("rollback manifest: {e}")))?;

    if wire.v != MANIFEST_V {
        return Err(Reject::WrongManifestVersion { got: wire.v });
    }

    // Epoch first. This is the check that keeps downgrade protection intact against
    // replay: a stale manifest, or the very manifest already applied, fails here. An
    // attacker re-serving a legitimate old rollback would otherwise defeat check 3
    // through the side door (spec §6.27).
    if wire.epoch <= state.last_rollback_epoch {
        return Err(Reject::RollbackEpochNotFresh {
            offered: wire.epoch,
            last_seen: state.last_rollback_epoch,
        });
    }

    let target_version = parse_version(&wire.target_version, "target_version")?;
    let bad_version = parse_version(&wire.bad_version, "bad_version")?;

    // HR-12.3: the bad version is named explicitly, so a rollback issued against one
    // release cannot be repurposed against another.
    if bad_version != state.current_version {
        return Err(Reject::RollbackDoesNotNameCurrentVersion {
            named: bad_version,
            current: state.current_version.clone(),
        });
    }

    if target_version >= state.current_version {
        return Err(Reject::RollbackIsNotADowngrade {
            target: target_version,
            current: state.current_version.clone(),
        });
    }

    Ok(RollbackManifest {
        v: wire.v,
        epoch: wire.epoch,
        target_version,
        bad_version,
        artifacts: parse_artifacts(wire.artifacts)?,
    })
}

/// HR-12.2 check 1.
///
/// `verify_strict` rather than `verify`: it rejects small-order and non-canonical
/// public keys, which is what stops a signature being valid under more than one key.
/// The permissive variant is a footgun in exactly this position.
fn verify_signature(signed: &SignedManifest, key: &PinnedReleaseKey) -> Result<(), Reject> {
    let sig = Signature::from_bytes(&signed.signature);
    key.0
        .verify_strict(&signed.bytes, &sig)
        .map_err(|_| Reject::BadSignature)
}

/// HR-12.2 check 2.
fn verify_logged(signed: &SignedManifest, proof: &InclusionProof) -> Result<(), Reject> {
    let leaf = rekor::hash_leaf(&manifest_digest(&signed.bytes));
    rekor::verify_inclusion(&leaf, proof).map_err(Reject::from)
}

fn parse_version(s: &str, field: &str) -> Result<Version, Reject> {
    Version::parse(s).map_err(|e| Reject::Malformed(format!("{field}: {e}")))
}

fn parse_artifacts(wire: Vec<WireArtifact>) -> Result<Vec<Artifact>, Reject> {
    wire.into_iter()
        .map(|a| {
            let sha256 = parse_hash(&a.sha256, "artifact.sha256")?;
            Ok(Artifact {
                name: a.name,
                sha256,
            })
        })
        .collect()
}

/// The Rekor leaf whose inclusion is being proven: the manifest digest.
///
/// TODO(BLK-12): the exact Rekor entry body this digest corresponds to is not
/// pinned by the spec. Rekor leaves are canonicalised entry bodies, not bare
/// digests, so the byte-level leaf definition is an externally-observable shape and
/// must be fixed before Phase 10 ships an auto-updater. Verified against a
/// synthetic tree until then — see tests/rekor_inclusion.rs.
pub fn manifest_digest(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

// ---------------------------------------------------------------------------
// Wire form. Parsed only AFTER the signature has been verified.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WireArtifact {
    name: String,
    sha256: String,
}

/// `deny_unknown_fields` is a security choice, not tidiness. A manifest carrying a
/// field this build does not understand is either a newer format or an attacker
/// probing for a lenient parser; both should stop here rather than be silently
/// ignored (HR-0.5, and the same instinct as HR-1.5 for the wire protocol).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRelease {
    v: u32,
    version: String,
    artifacts: Vec<WireArtifact>,
    rollout_percent: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRollback {
    v: u32,
    epoch: u64,
    target_version: String,
    bad_version: String,
    artifacts: Vec<WireArtifact>,
}

fn parse_hash(s: &str, field: &str) -> Result<Hash, Reject> {
    let raw = hex::decode(s).map_err(|e| Reject::Malformed(format!("{field}: not hex: {e}")))?;
    raw.try_into()
        .map_err(|_| Reject::Malformed(format!("{field}: expected 32 bytes")))
}
