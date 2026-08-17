# Security review — tether

**Required by spec Phase 0:** *"Write `SECURITY-REVIEW.md` from §6 and §6A."*

Findings themselves live in [implementation-spec-v4.md §6 and §6A](implementation-spec-v4.md) —
35 of them across two adversarial reviews, each with attack and resolution. They are not copied here,
for the reason given in [THREAT-MODEL.md](THREAT-MODEL.md): two copies disagree the first time one is
edited.

This file carries the two things the spec cannot: **the review discipline that must run at the end of
every phase**, and **the record of it actually running.**

---

## 1. The discipline

HR-15.6 and spec §6.37, and the wording matters. For **each control**, three separate questions:

> 1. **Does it exist?**
> 2. **Does it function?**
> 3. **Does it authorize, or does it merely inform?**

Then: **build a demo of each control failing. A control you have never seen fail is a control you have
never seen.**

### Why three questions and not one

This is the most transferable lesson in the whole spec, so it is worth stating plainly rather than
citing.

The v3 review was thorough. It asked, repeatedly and well, *"can I break this mitigation?"* — and that
question quietly presupposes two things: that the mitigation exists, and that it does what its name
suggests. Round two found three things round one structurally could not:

- **§6.13, §6.14 — components that did not work at all.** The Windows agent as specified could not
  capture the screen (services run in session 0). The `elevate` capability was unimplementable.
  Nobody asked whether the pieces were real.
- **§6.17 — an entire threat direction never modelled.** Every mitigation ran host-ward. Nothing
  considered a hostile host attacking the phone's `MediaCodec`.
- **§6.25 — a control that was well-built and the wrong *kind* of thing.** v3's consent architecture
  was complete, argued, and reviewed, and in it the person being watched never actually got to decide.
  The border, the tray icon, the toast: every one a *notification*. Not one an *authorization*.

Question 3 is the one that is easy to skip and expensive to get wrong. Spec §6.37 warns it will not be
the last time.

### Where review effort goes

HR-15.7: eight of eleven first-round findings, and the three worst second-round findings, sat in
components added to **protect** the system — the update channel, the elevation helper, the panel, the
revoke command, the audit log, the audit encryption. Security machinery is privileged by definition,
so a bug there is worth more than a bug in feature code. Weight review accordingly.

### The stop condition

HR-15.8, and it is not advisory: **any successful adversarial test — any path by which an admin or a
compromised server reaches a host — stops the project until the protocol is fixed.** Not the code: the
protocol.

---

## 2. Review log

One entry per completed phase. Empty rows are honest; a fabricated one is worse than none.

| Phase | Date | Controls reviewed | Watched fail? | Findings | Outcome |
|---|---|---|---|---|---|
| 0.1 | 2026-08-17 | 3 (below) | yes, 2 of 3 | 1 (HR-12.5) | see §3 |

---

## 3. Phase 0.1 review

Three controls were added. Each gets the three questions.

### Control 1 — HR-1.1 protocol absences

| Question | Answer |
|---|---|
| Does it exist? | Yes. [`tether.proto`](../crates/proto/proto/tether/v1/tether.proto) declares no `grant_capability`, `add_peer`, `start_session`, `join_session`, `observe_session`, `wipe`, `reconfigure`, or `elevate`; HR-1.2's explanatory comment is present |
| Does it function? | Yes, and this is enforced rather than asserted: [`protocol_absence.rs`](../crates/proto/tests/protocol_absence.rs) fails the build if any appears. It strips comments first, because the schema legitimately *names* every forbidden message while explaining its absence — a naive search would fail against a correct schema |
| Authorize or inform? | **Neither, and that is the point.** It removes the capability rather than guarding it. A message that does not exist has no authorization bug to find. This is the strongest form available |
| **Watched it fail?** | **Yes.** Added `grant_capability` to the schema → `HR-1.1 violation: the wire schema declares ["grant_capability", "grantcapability"]`. Added a third arm to the `ServerCommand` oneof → `Found 3 arms in oneof command`. Both reverted; schema re-verified clean, zero mutation residue |

A vacuous-pass guard is included (`absence_test_can_actually_see_declarations`): if comment-stripping
ever blanks the file, the absence test would pass while looking at nothing.

### Control 2 — HR-1.6 protocol version floor

| Question | Answer |
|---|---|
| Does it exist? | Yes. `MIN_PROTOCOL_VERSION` compiled into [`proto/src/lib.rs`](../crates/proto/src/lib.rs), not carried in the schema — a constant in a schema is a suggestion, in a binary it is a rule |
| Does it function? | Yes. 8 tests. The load-bearing one is `well_formed_message_below_floor_is_still_refused_no_fallback`: a *valid, parseable* below-floor message is still refused. Asserting only that a bad version errors would not prove the absence of a fallback path, which is the actual anti-downgrade property (T31) |
| Authorize or inform? | **Authorizes** — it refuses to proceed. There is deliberately no `else` branch that negotiates |
| **Watched it fail?** | **Partially.** Seen red at gate 3 with `not yet implemented`, and green after. Not mutation-tested by deleting the check and confirming red. **Gap, recorded.** |

### Control 3 — HR-12.2 / HR-12.3 update verification

| Question | Answer |
|---|---|
| Does it exist? | Yes. All four checks in [`release.rs`](../crates/agent-core/src/release.rs), plus the rollback path |
| Does it function? | Yes. 19 tests: wrong key, tampered body, absent from log, downgrade, equal version, cohort not reached, invalid rollout, unknown field, stale epoch, replayed epoch, wrong named bad version, non-downgrade rollback |
| Authorize or inform? | **Authorizes.** Every failure path returns `Err` and installs nothing |
| **Watched it fail?** | **Yes**, in the strong sense: 19 of these tests are themselves failure cases, each asserting a *specific* rejection reason rather than merely "not Ok" |

Two design decisions worth recording, both surfaced by writing the tests first:

- **Signature verified over bytes as received, before parsing.** `signature_is_checked_before_the_body_is_parsed` asserts garbage input returns `BadSignature`, never `Malformed` — a `Malformed` would prove the JSON parser was reached by unsigned input. Same principle as HR-2.5.
- **The Rekor proof cannot live inside the manifest.** It attests the digest *of* the manifest, so embedding it makes the digest depend on itself. Caught while writing the test that needed to construct one.

### Finding: HR-12.5 was not satisfied

**Severity: would have shipped silently.** Two consecutive clean release builds of identical source
produced **different** SHA-256 digests. Cause: MSVC `link.exe` writes wall-clock time into the PE
header's `TimeDateStamp`. Every dependency was pinned and it made no difference — the nondeterminism
was two tools downstream of anything Cargo controls.

Resolved by `-Clink-arg=/Brepro` ([`.cargo/config.toml`](../.cargo/config.toml)); same-path builds now
verify byte-identical. **Still outstanding:** path independence, needed for the "third party can
verify" half. `trim-paths` is not stabilized in Cargo 1.97.1. See
[REPRODUCIBLE-BUILDS.md](REPRODUCIBLE-BUILDS.md).

The generalisable lesson: reproducibility fails at the *last* tool in the chain as readily as the
first, and the only way this was found was by running it. It would have passed any amount of reading.

### Blocker raised

**BLK-12** — the Rekor entry body format and the log's trust root are unpinned. RFC 6962 inclusion-proof
verification is implemented and tested against synthetic trees built by an *independent* reference
implementation; a Merkle proof only proves membership in a tree with a given root, and nothing in the
spec says where a trusted root comes from. Blocks Phase 10.

---

## 4. Not yet reviewable

Listed so their absence is not mistaken for a pass. No control exists to review for: pairing and the
SAS (Phase 3), the consent gate (Phase 8 — spec §6.25, the most important finding in either round),
audit chain and truncation detection (Phase 4/8), helper authentication (Phase 7), decoder input
validation (Phase 6), TURN hardening (Phase 1), panel XSS and CSRF (Phase 4).
