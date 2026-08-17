//! Platform-independent agent logic.
//!
//! Phase 0 scope: verification of release and rollback manifests (spec §6.1,
//! §6.27, HR-12.2, HR-12.3). No capture, input, or network code lives here — those
//! arrive in their own phases, in their own crates.

#![forbid(unsafe_code)]

pub mod rekor;
pub mod release;
