# Threat model — tether

**Required by spec Phase 0:** *"Write `THREAT-MODEL.md` from §2."*

**This document does not restate the threats.** [implementation-spec-v4.md §2](implementation-spec-v4.md)
holds the attacker capability and mitigation for each of T1–T34, and duplicating them here would give
two copies to disagree with each other the first time one is edited — the defect WORKING-AGREEMENT §4
names. What this file adds is the part §2 cannot carry: **whether the mitigation exists in code yet,
and where.**

Read §2 for *what the threat is*. Read this for *whether anything stops it today*.

**Status vocabulary**

| Status | Meaning |
|---|---|
| `SHIPPED` | Implemented, tested, and the test has been watched to fail (HR-15.6) |
| `PARTIAL` | Some of the mitigation exists; the gap is named |
| `PLANNED` | Not started. Phase column says when |
| `BLOCKED` | Cannot proceed; blocker ID given |
| `ACCEPTED` | Documented risk, deliberately not mitigated (spec §2) |

**As of 2026-08-18, after workflow phases 0.1–0.3.** Four threats are `SHIPPED`. Most of the rest are
`PLANNED` simply because their phase has not run — this is a foundations phase, and most mitigations
live in the phases that build the features they protect.

---

## Status by threat

| # | Threat (see §2) | Phase | Status | Where / gap |
|---|---|---|---|---|
| T1 | Malicious control plane | 3 | PLANNED | Needs Noise_IK; host-side allowlist is Phase 3 |
| T2 | Network MITM | 1,3,5 | PLANNED | |
| T3 | Stolen phone | 6 | PLANNED | |
| T4 | Brute force on pairing | 3 | PLANNED | |
| T5 | Stolen release signing key | 0,10 | **SHIPPED (with a recorded downgrade)** | Full ceremony working: TPM-sealed Ed25519 seed, sign, verify, tamper and wrong-key both refused. `real_signature.rs` proves the agent accepts a signature from the real ceremony. **Cost:** no per-signature physical touch — HR-0.2 deviation |
| T6 | Poisoned auto-update | 10 | **PARTIAL** | All four HR-12.2 checks implemented and tested. End-to-end cosign/Rekor run outstanding — BLK-12 |
| T7 | Malicious paired client | 8 | PLANNED | Consent gate is Phase 8 |
| T8 | Agent abused for persistence | 2,8 | **PARTIAL** | Crate split enforces it structurally: `broker-win` and `helper-*` have **zero dependencies**, so they cannot make a network call. Behaviour is Phase 2/7 |
| T9 | Side-channel exfiltration | 9 | PLANNED | Capabilities exist in the schema, all denied by default (HR-2.4) |
| T10 | Replay of captured traffic | 3 | PLANNED | |
| T11 | Compromised admin account | 4 | **PARTIAL** | The structural half is done: grant/pair/connect **absent from the schema**, enforced by [`protocol_absence.rs`](../crates/proto/tests/protocol_absence.rs) — mutation-tested |
| T12 | Panel as covert surveillance | 4,8 | PLANNED | Audit scope not yet implemented; never-log list has no code to violate it yet |
| T13 | Server operator reading activity | 4 | PLANNED | HPKE sealing is Phase 4 |
| T14 | Admin session hijack | 4 | BLOCKED | BLK-9: WebAuthn RP ID needs the panel domain |
| T15 | Forged/deleted audit entries | 4,8 | PLANNED | |
| T16 | CI/supply-chain compromise | 0,10 | **PARTIAL** | `cargo deny` `sources` check passing: crates.io only, `unknown-git = deny`. `Cargo.lock` committed. CI holds no credential *because CI does not exist yet* — which is not the same as being safe |
| T17 | LPE via input helper | 7 | PLANNED | `helper-win` is a separate zero-dependency crate; auth layers are Phase 7 |
| T18 | XSS in admin panel | 4 | PLANNED | |
| T19 | Forged mass revoke / DoS | 2,4 | **PARTIAL** | Structural: no `wipe` in the schema, and [`RevokeDevice`](../crates/proto/proto/tether/v1/tether.proto) documents that it destroys nothing (HR-1.7) |
| T20 | QR capture during screen share | 3 | PLANNED | SAS is Phase 3 |
| T21 | TURN → SSRF → VPS takeover | 1,5 | PLANNED | `turnserver.conf` + CI test are Phase 1 |
| T22 | Offline brute force of audit key | 0, 4 | **SHIPPED** | The structural mitigation is done and **proven**: the keygen page has no passphrase input, asserted by a Playwright test that was mutation-tested (adding `<input type="password">` turns it red). §6.8's attack needs a guessable input and there is none. The recovery-secret wrap uses 256 CSPRNG bits — also mutation-tested. **All three HR-4.5 wrap paths now implemented and proven independent** — authenticator wraps tested via Chrome virtual authenticators with `prf`. No passphrase exists anywhere, mutation-tested |
| T23 | `uinput` as Wayland escape | 7 | PLANNED | HR-7.5 recorded in [`helper-linux/src/main.rs`](../crates/helper-linux/src/main.rs) so it cannot be forgotten |
| T24 | Home IP via ICE candidates | 5 | PLANNED | |
| T25 | Malicious host attacks client | 6,9 | PLANNED | Decoder caps are Phase 6 |
| T26 | Hostile pairing QR | 3 | PLANNED | `relay_hint` allowlist is Phase 3 |
| T27 | CSRF across `api.` → `admin.` | 1,4 | BLOCKED | BLK-9 — the fix *is* the second domain |
| T28 | DNS hijack / mis-issued cert | 1,2 | BLOCKED | BLK-9: SPKI pin needs the domain to pin |
| T29 | Local clock manipulation | 3,7 | PLANNED | Monotonic-clock requirement recorded in the schema comments; no expiry logic exists yet |
| T30 | Restore rolls back revocation | 1,4 | BLOCKED | BLK-8: where the revocation epoch lives |
| T31 | Protocol downgrade | 0,3 | **SHIPPED** | `MIN_PROTOCOL_VERSION` compiled in; [`version_floor.rs`](../crates/proto/tests/version_floor.rs) asserts a *well-formed* below-floor message is still refused — the no-fallback property, not just the check |
| T32 | Unattended access abused | 8 | PLANNED | `ConnectRequest`/`ConnectResponse` exist; the host-side gate is Phase 8. **See HR-15.2** |
| T33 | Credential loss → physical visits | 3,8 | PLANNED | Backup credential is Phase 3/8 |
| T34 | Bad update strands cohort | 10 | **SHIPPED** | Rollback manifest verified: fresh epoch accepted, stale rejected, replay rejected, bad version must be named. [`release_verification.rs`](../crates/agent-core/tests/release_verification.rs) |

## Accepted risks

Unchanged from spec §2 and not re-litigated here. Each must appear in the Phase 10 onboarding doc:

compromised host OS defeats everything · compromised Android client with an Accessibility Service can
observe the decoded desktop and inject taps · traffic metadata is a behavioural profile over weeks ·
an admin can always refuse to relay · no lock screen, greeter, or UAC access · the backup credential
is a second key to the house · the host user can decline consent and defeat their own remote access.

## The honest summary

**Four are `SHIPPED`** — T5 and T34 (release integrity), T31 (protocol downgrade), and T22 (offline
brute force of the audit key, where the mitigation is that there is no passphrase to attack).

Several show `PARTIAL` where the **structural** half is genuinely done: a message that does not exist
in the schema cannot be sent, and a crate with no dependencies cannot open a socket. That is stronger
than a runtime check, but it is not the whole mitigation.

**Three remain `BLOCKED` on the panel domain** (T14, T27, T28). It is free — a subdomain of a
Public-Suffix-List domain satisfies HR-9.1 — but it must be chosen before any authenticator is
registered, because that freezes the WebAuthn RP ID.

**T32 deserves the loudest note.** Its mitigation is the consent gate, which lands in Phase 8. Phases
5–7 produce a working system where any paired device can connect at will. HR-15.2: do not hand this to
a second person before Phase 8 ships — including someone who insists they do not mind.

**And T5 carries a recorded downgrade.** The release key is TPM-sealed, not on a YubiKey, so there is
no per-signature physical touch. CI still cannot sign and the key still cannot leave the machine — but
until the Phase 6 StrongBox path restores the missing property, builds must not be distributed.
