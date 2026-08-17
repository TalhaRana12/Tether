//! Mechanical enforcement of HR-1.1 — the "does not exist" list.
//!
//! HR-1.2 asks for a comment in the `.proto` file so a future contributor does not
//! helpfully re-add a forbidden message. A comment is advice. This file is the
//! enforcement: adding `grant_capability` to the schema fails the build.
//!
//! Note the subtlety these tests have to handle — the schema *legitimately*
//! mentions every forbidden name, in the comments explaining why they are absent. A
//! naive substring search over the file would therefore fail against a perfectly
//! correct schema. So comments are stripped first, and `absence_test_can_actually
//! _see_declarations` is the positive control proving the stripped text is not
//! simply empty. A test that passes because it is looking at nothing is worse than
//! no test (WORKING-AGREEMENT §6).

const SCHEMA: &str = include_str!("../proto/tether/v1/tether.proto");

/// Strip `//` line comments, leaving only declarations.
fn declarations_only(schema: &str) -> String {
    schema
        .lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// HR-1.1: absent, not disabled, not permission-gated.
///
/// Each name below is a message whose existence would let an admin or a compromised
/// server reach a host. HR-15.8: any path by which that happens stops the project
/// until the protocol is fixed — so this test failing is not a lint, it is that.
#[test]
fn forbidden_messages_have_no_wire_representation() {
    let decls = declarations_only(SCHEMA).to_lowercase();

    // Ordered as HR-1.1 lists them.
    let forbidden = [
        "grant_capability",
        "grantcapability",
        "add_peer",
        "addpeer",
        "start_session",
        "startsession",
        "join_session",
        "joinsession",
        "observe_session",
        "observesession",
        "wipe",
        "reconfigure",
        "elevate",
        "approve_connection",
        "approveconnection",
        "set_access_mode",
        "setaccessmode",
        "access_mode",
        "backup_credential",
        "backupcredential",
        "sign_release",
        "signrelease",
    ];

    let found: Vec<&str> = forbidden
        .iter()
        .copied()
        .filter(|name| decls.contains(name))
        .collect();

    assert!(
        found.is_empty(),
        "HR-1.1 violation: the wire schema declares {found:?}. These have no wire \
         representation by design — their absence IS the security control. If a \
         feature seems to need one, that is HARD-RULES Appendix B question 1, and \
         the answer is stop."
    );
}

/// Positive control for the test above.
///
/// If comment-stripping ever over-matches and blanks the file, the absence test
/// would pass vacuously. This asserts the stripped text still contains real
/// declarations, so a pass means something.
#[test]
fn absence_test_can_actually_see_declarations() {
    let decls = declarations_only(SCHEMA);

    for expected in [
        "message Envelope",
        "message ConnectRequest",
        "message SignedServerCommand",
        "enum Capability",
    ] {
        assert!(
            decls.contains(expected),
            "comment-stripping removed real declarations; the absence test would \
             pass vacuously. Missing: {expected}"
        );
    }
}

/// HR-1.3: the distinction the comment in the schema is required to state.
///
/// `connect_request` DOES exist — peer-to-peer, answered by the host user. What
/// must not exist is server- or admin-originated session initiation, covered above.
#[test]
fn connect_request_exists_because_it_is_peer_to_peer() {
    let decls = declarations_only(SCHEMA);
    assert!(
        decls.contains("message ConnectRequest"),
        "HR-1.3: ConnectRequest must exist. It is how a paired device *asks*; the \
         host user answers (HR-2.1). Deleting it does not make the system safer, it \
         makes consent unexpressible."
    );
}

/// HR-1.4: exactly two server-originated commands, no more.
#[test]
fn exactly_two_server_originated_commands() {
    let decls = declarations_only(SCHEMA);

    assert!(
        decls.contains("KillSession"),
        "HR-1.4: KillSession must exist"
    );
    assert!(
        decls.contains("RevokeDevice"),
        "HR-1.4: RevokeDevice must exist"
    );

    // The ServerCommand oneof is the whole surface the agent obeys. Count its arms
    // rather than trusting the comment above it.
    let body = decls
        .split("message ServerCommand")
        .nth(1)
        .expect("ServerCommand message must exist");
    let oneof = body
        .split("oneof command")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("ServerCommand must contain `oneof command`");

    let arms = oneof.matches(';').count();
    assert_eq!(
        arms, 2,
        "HR-1.4: the agent obeys exactly two server-originated commands, both \
         strictly restrictive and both reversible. Found {arms} arms in `oneof \
         command`. A third arm means the control plane gained authority over a \
         host, which is HR-5.4's whole prohibition."
    );
}

/// HR-2.4: `elevate` never receives a field number.
///
/// Checked separately from the list above because it is the case most likely to be
/// re-added by someone who reads "remote software installation stopped working" as
/// a bug rather than the documented price (spec §6.14).
#[test]
fn capability_enum_has_no_elevate() {
    let decls = declarations_only(SCHEMA);
    let body = decls
        .split("enum Capability")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("Capability enum must exist")
        .to_lowercase();

    assert!(
        !body.contains("elevate"),
        "spec §6.14 / HR-2.4: `elevate` is removed from the protocol, not gated. \
         UAC renders on the secure desktop, which Desktop Duplication cannot \
         capture and a user-session SendInput cannot reach — delivering it needs \
         exactly the SYSTEM-session input primitive HR-7.3 exists to deny."
    );
}

/// HR-1.6: the floor is a compiled-in constant, and the schema must carry `v`.
#[test]
fn envelope_carries_explicit_version_field() {
    let decls = declarations_only(SCHEMA);
    let body = decls
        .split("message Envelope")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("Envelope must exist");

    assert!(
        body.contains("uint32 v = 1;"),
        "HR-1.6: the wire protocol carries an explicit `v`. Found Envelope body: \
         {body}"
    );
}
