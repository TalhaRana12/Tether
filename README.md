# tether

Self-hosted remote desktop for people you actually know. Windows and Linux hosts, an
Android client, and a control plane that is **structurally unable** to reach any of them.

> **Status: Phase 0 of 11. Not usable, not installable, and deliberately not released.**
> There is no working remote desktop here yet — Phase 0 builds the foundations that cannot
> be changed later. See [Status](#status).

---

## The line this project is built on

This software grants full control of a machine to a remote party. Functionally that is
indistinguishable from a Remote Access Trojan. **The entire difference is verifiable
consent and an audit trail the session cannot erase.**

Audit scope is drawn at remote-access events only. Screen content, keystrokes, applications
launched, window titles, browsing activity, files opened, and any local (non-remote) usage
are **never logged, and no code path exists** to log them.

> **If you are ever tempted to add an item from that list, that is the moment this stops
> being a remote-access tool and becomes monitoring software.**

That sentence is required to be here by the project's own rules ([HR-10.8](docs/HARD-RULES.md)),
and it is the shortest summary of what this project is trying not to become.

## Four rules everything else derives from

1. **Admin operations are monotonically restrictive.** The panel can revoke, suspend, and
   kill. It can never grant, pair, or connect. The messages that would let an admin add
   themselves to your allowlist **do not exist in the wire protocol** — not disabled, not
   permission-gated, absent.
2. **Nothing online can sign a release.** CI holds no signing credential of any kind. Only
   a human at a physical machine can ship.
3. **No secret is derivable from anything guessable.** No passphrase-derived keys anywhere,
   so there is no offline brute-force target.
4. **Pairing is not permission to connect.** A paired device may *request* a session. The
   person at the host decides, per connection, at the moment of connection.

## What it cannot do, by protocol rather than by permission

There is no endpoint to disable and no role to escalate into, because the messages do not
exist. The admin panel cannot:

start, join, or observe a session · add a key to any host's allowlist · grant or modify a
capability · read or write files, clipboard, or screen content · change host settings ·
wipe or reconfigure a host · recover or export any private key · approve a connection on
your behalf · change a device's access mode

Enforced mechanically: [`protocol_absence.rs`](crates/proto/tests/protocol_absence.rs) fails
the build if any of those names appears in the schema, and it has been mutation-tested to
prove it can actually fail.

Also deliberately absent, and permanently: no access to the Windows UAC secure desktop, the
lock screen, or the login greeter. Remote software installation on Windows largely stops
working as a result. That is the accepted price of not building a UAC-bypass primitive into
a family member's laptop.

## Status

| Phase | | |
|---|---|---|
| **0 — Foundations** | in progress | 4 of 6 exit criteria met |
| 1–10 | not started | control plane, agent, pairing, panel, video, client, input, hardening, convenience, distribution |

Phase 0 builds the things that are **one-way doors** — the wire protocol, the release
signing key, and the audit chain shape — because none of them can be changed once anything
depends on them.

**67 tests** (46 Rust, 7 Go, 14 Playwright) and 7 mutation tests. All gates pass:
`cargo fmt`, `clippy -D warnings`, `cargo deny`, `go vet`, `npm audit`, `gradle lint`.

Outstanding for Phase 0: CI has never executed (no remote yet), the real admin audit
keypair needs a browser session with two registered authenticators, a Sigstore/Rekor
round-trip, and the control-plane pin awaits Phase 1.

## Do not install this

Not modesty — two project rules:

- **HR-15.2:** the per-connection consent gate lands in **Phase 8**. Until then, any paired
  device can connect at will. That is acceptable while one person is the only user and
  unacceptable the moment anyone else installs it, *including someone who insists they do
  not mind*.
- **HR-0.2, currently deviated:** this is a zero-budget build, so the release signing key is
  sealed in a TPM rather than held on a security key with a touch policy. CI still cannot
  sign and the key still cannot leave the machine, but there is no per-signature physical
  act. Full accounting: [FREE-TIER-SUBSTITUTIONS.md](docs/FREE-TIER-SUBSTITUTIONS.md).

Reading the source is encouraged. Running it is not, yet.

## Building

```bash
cargo test --workspace          # 46 tests
go test ./...                   # 7  tests - includes the Android manifest gate
cd panel && npx playwright test # 14 tests - browser-only security properties
cd android && ./gradlew :app:lintRelease
```

Toolchain and versions: [requirements.txt](requirements.txt). Builds are reproducible —
two builds of the same commit are byte-identical, including from different source
directories: [REPRODUCIBLE-BUILDS.md](docs/REPRODUCIBLE-BUILDS.md).

## Documentation

Start here if you want to understand the project rather than run it:

| Document | What it is |
|---|---|
| [PHASE-0-EXPLAINED.md](docs/PHASE-0-EXPLAINED.md) | **Start here.** Every file in Phase 0, why it exists, and what breaks without it |
| [implementation-spec-v4.md](docs/implementation-spec-v4.md) | The design volume, including two adversarial reviews and all 35 findings |
| [HARD-RULES.md](docs/HARD-RULES.md) | Normative constraints, with stable IDs cited throughout the code |
| [THREAT-MODEL.md](docs/THREAT-MODEL.md) | T1–T34 with current implementation status |
| [SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) | The review discipline, and the record of running it |
| [FREE-TIER-SUBSTITUTIONS.md](docs/FREE-TIER-SUBSTITUTIONS.md) | Every paid item replaced with a free one, and what each substitution costs |
| [impl-specs/tether/](docs/impl-specs/tether/) | Blockers, amendments, and per-phase gate traces |

## Accepted risks

Documented rather than hidden, and repeated in the onboarding doc when there is one:

a fully compromised host OS defeats everything · a compromised Android client with an
Accessibility Service can observe the decoded desktop and inject taps · traffic metadata is
a behavioural profile over weeks · an admin can always refuse to relay · no lock screen,
greeter, or UAC access · a backup credential is a second key to the house · the host user
can decline consent and defeat their own remote access · and currently, the release signing
key has no per-signature physical touch.

## On reporting security issues

The project's own rule (HR-15.8) is that **any path by which an admin or a compromised
server reaches a host stops the project until the protocol is fixed** — not the code, the
protocol. If you find one, that is exactly the finding worth sending.

## Licence

**Not yet chosen.** This is an open item, and it matters: HR-12.5 invites third parties to
build from this source and verify the result, which is an awkward invitation to extend
without terms.
