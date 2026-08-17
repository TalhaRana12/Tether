//! HR-1.6 / T31 — the protocol version floor.
//!
//! "Versioning without a floor is a downgrade oracle" (spec §6.24). These tests
//! assert not only that a low version is refused, but that there is no path by
//! which a *well-formed, otherwise-valid* low-version message gets serviced — which
//! is what "no negotiation, no fallback path" actually means.

use prost::Message;
use tether_proto::{
    check_version, decode_envelope, envelope::Payload, ConnectRequest, Envelope, ProtocolError,
    CURRENT_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION,
};

fn envelope_at_version(v: u32) -> Vec<u8> {
    let env = Envelope {
        v,
        payload: Some(Payload::ConnectRequest(ConnectRequest {
            claimed_device_label: "probe".to_string(),
            capabilities_wanted: vec![],
        })),
    };
    env.encode_to_vec()
}

#[test]
fn version_at_floor_is_accepted() {
    assert_eq!(check_version(MIN_PROTOCOL_VERSION), Ok(()));
}

#[test]
fn version_below_floor_is_refused() {
    let below = MIN_PROTOCOL_VERSION - 1;
    assert_eq!(
        check_version(below),
        Err(ProtocolError::VersionBelowFloor {
            got: below,
            floor: MIN_PROTOCOL_VERSION,
        })
    );
}

#[test]
fn version_zero_is_refused() {
    // v=0 is what an omitted proto3 field decodes to, so an attacker stripping the
    // field must not land on a permissive default.
    assert!(matches!(
        check_version(0),
        Err(ProtocolError::VersionBelowFloor { .. })
    ));
}

/// The actual anti-downgrade property.
///
/// A below-floor envelope carrying a perfectly valid, parseable ConnectRequest is
/// still refused. If this passed, the floor would be advisory: an attacker could
/// re-select v1 semantics after a v2 fix, which is precisely T31.
#[test]
fn well_formed_message_below_floor_is_still_refused_no_fallback() {
    let bytes = envelope_at_version(MIN_PROTOCOL_VERSION - 1);
    assert!(matches!(
        decode_envelope(&bytes),
        Err(ProtocolError::VersionBelowFloor { .. })
    ));
}

#[test]
fn current_version_round_trips() {
    let bytes = envelope_at_version(CURRENT_PROTOCOL_VERSION);
    let env = decode_envelope(&bytes).expect("current version must decode");
    assert_eq!(env.v, CURRENT_PROTOCOL_VERSION);
}

/// HR-1.5 — reject and log anything unrecognised.
///
/// An envelope with no payload is the shape a future protocol version presents to
/// this build: version passes the floor, payload is unnameable. It must not be
/// treated as a benign empty message.
#[test]
fn envelope_without_recognised_payload_is_rejected() {
    let bytes = Envelope {
        v: CURRENT_PROTOCOL_VERSION,
        payload: None,
    }
    .encode_to_vec();

    let env = decode_envelope(&bytes).expect("version is fine; payload is the problem");
    assert!(
        !tether_proto::has_recognised_payload(&env),
        "HR-1.5: an envelope this build cannot name must be dropped and logged, \
         never treated as an empty no-op"
    );
}

#[test]
fn recognised_payload_is_detected() {
    // Positive control: proves has_recognised_payload is not simply always false.
    let bytes = envelope_at_version(CURRENT_PROTOCOL_VERSION);
    let env = decode_envelope(&bytes).unwrap();
    assert!(tether_proto::has_recognised_payload(&env));
}

#[test]
fn garbage_bytes_are_rejected_not_panicked_on() {
    // HR-0.5: every byte crossing a session is untrusted input. A decoder that
    // panics on hostile input is a denial of service in a process holding session
    // keys.
    let garbage = [0xffu8; 64];
    assert!(matches!(
        decode_envelope(&garbage),
        Err(ProtocolError::Malformed(_))
    ));
}
