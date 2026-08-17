//! tether wire protocol.
//!
//! The security-relevant content of this crate is what the schema does **not**
//! contain — see the header comment in `proto/tether/v1/tether.proto` and HR-1.1.
//! `tests/protocol_absence.rs` enforces that mechanically.

#![forbid(unsafe_code)]

use prost::Message;

// Generated from proto/tether/v1/tether.proto by build.rs.
include!(concat!(env!("OUT_DIR"), "/tether.v1.rs"));

/// The oldest protocol version this build will speak.
///
/// HR-1.6: compiled into the binary, and anything below it is refused with **no
/// negotiation and no fallback path**. This constant lives in Rust rather than in
/// the schema on purpose: a constant in a schema is a suggestion, a constant in a
/// binary is a rule.
///
/// Raising this is a breaking change and a deliberate act — it is how a fixed
/// vulnerability stays fixed (spec §6.24, T31).
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// The version this build emits.
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// T31 / HR-1.6. There is deliberately no "negotiate down" branch to reach.
    #[error("protocol version {got} is below the compiled-in floor {floor}; refused, no negotiation (HR-1.6)")]
    VersionBelowFloor { got: u32, floor: u32 },

    /// HR-1.5: reject and log anything unrecognised. Includes an envelope from a
    /// future version whose payload this build cannot name — which is why no
    /// separate "version too new" branch is needed.
    #[error("envelope carried no recognised payload; dropped and logged (HR-1.5)")]
    UnrecognisedPayload,

    #[error("malformed envelope: {0}")]
    Malformed(String),
}

/// Enforce the version floor.
///
/// Call this **before** acting on any envelope contents.
pub fn check_version(v: u32) -> Result<(), ProtocolError> {
    // Note there is no `else` branch that negotiates, downgrades, or falls back.
    // The absence of that branch is the control (HR-1.6, T31) — adding one, however
    // reasonable it looks for compatibility, reopens the downgrade oracle.
    if v < MIN_PROTOCOL_VERSION {
        return Err(ProtocolError::VersionBelowFloor {
            got: v,
            floor: MIN_PROTOCOL_VERSION,
        });
    }
    Ok(())
}

/// Decode an envelope, enforcing the version floor before the payload is trusted.
///
/// Order matters and is not stylistic. The version check runs before the payload is
/// interpreted, for the same reason HR-2.5 requires a capability check before a
/// gated message body is parsed: a parser that runs first is a parser an attacker
/// reaches at the old version's semantics.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, ProtocolError> {
    // The envelope header must be decoded to read `v` at all, so "check the version
    // before parsing" cannot mean before *this* decode. What it does mean: the
    // version is enforced before any caller is handed the payload to act on. The
    // Envelope decode itself is deliberately tiny — a varint and a length-delimited
    // oneof — and the payload inside it stays untouched until the floor has passed.
    let env = Envelope::decode(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))?;

    check_version(env.v)?;

    Ok(env)
}

/// Whether this envelope carries a payload this build recognises.
///
/// HR-1.5 requires unrecognised inbound message types to be dropped and logged. A
/// `oneof` that decodes to `None` is exactly that case: either a future variant or
/// a deliberately empty envelope.
pub fn has_recognised_payload(env: &Envelope) -> bool {
    env.payload.is_some()
}
