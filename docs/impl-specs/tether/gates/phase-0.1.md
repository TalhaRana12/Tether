# Gate trace — phase 0.1 — Foundations: workspace, protocol, release verification

**Spec phase:** 0 (Foundations) · **Workflow phase:** 0.1 · **Date:** 2026-08-17
**Branch:** `phase-0-foundations`

Scope of this workflow phase — the buildable subset of spec Phase 0:

- Cargo workspace with all seven crates of spec Phase 0 (+ `broker-win`)
- Wire protocol in protobuf with the HR-1.1 absences and HR-1.2 comment
- `MIN_PROTOCOL_VERSION` floor (HR-1.6)
- Release + rollback manifest verification (HR-12.2, HR-12.3)
- CI gate tooling wired and passing locally
- Reproducible-build controls (HR-12.5)
- `THREAT-MODEL.md`, `SECURITY-REVIEW.md`

**Explicitly out of scope**, and why — not deferred by preference:

| Spec Phase 0 item | Why not done |
|---|---|
| YubiKey signing ceremony, Sigstore end-to-end | No hardware. HR-12.1 forbids a software substitute |
| Admin audit keypair, triple wrap | No WebAuthn authenticators; and BLK-9 must fix the RP ID first |
| Control-plane SPKI + server identity pin | BLK-9 — no domain to pin |
| Go module (`control`, `admin`), Gradle project | Not attempted this phase; spec Phase 1/6 territory |
| CI workflow file | Gate tools verified locally; wiring to a runner needs a remote, which does not exist |

---

## Gate 0 — Status

```
Run:                    2026-08-17
Open blockers (module): 11 at entry -> BLK-1..BLK-11    (12 at exit; BLK-12 raised at gate 4)
Open amendments:        0
Last committed phase:   none (bea1198 is a pre-Phase-0 docs baseline)
This phase:             0.1 - Foundations
Spec section:           §7 Phase 0
Prerequisite phases:    none
```

Read-only; no verdict.

## Gate 1 — Order

```
Prerequisite phases committed with proof passed:   N/A - first phase
Open blockers anywhere in the module:              11
Open amendments touching this phase:               0

Verdict: HALT
```

**HALT, correctly.** Workflow §4.1: *"`impl-phase-validate` refuses to start or advance any phase
while one exists."* Eleven were open. This gate did **not** pass.

```
OVERRIDE: human instruction, 2026-08-17.
  The blocker situation was stated twice and the instruction to implement Phase 0 was
  repeated. Per WORKING-AGREEMENT §10 that is the author's decision to make.
  Recorded as an override rather than a pass: a build log that reports PASS where a
  gate halted is worse than no build log, because every later gate reads this file
  instead of remembering (workflow §4a).
  Scope limited to blocker-independent work. Everything touching BLK-9 (WebAuthn,
  SPKI pin, audit keypair) was left undone rather than guessed.
```

## Gate 2 — Reconcile

```
Spec clauses in scope:  §7 Phase 0, bullets 1-3 and 7; §6.1; §6.24; §6.27; §6.32(n/a)
Repo reality checked:   empty repo - greenfield, nothing to diverge from
Divergences found:      none (no prior implementation exists)
Hard rules in scope:    HR-0.2, HR-0.3, HR-1.1..HR-1.7, HR-2.4, HR-7.1, HR-7.3, HR-7.5,
                        HR-12.1..HR-12.5

Verdict: PASS
```

Note: **BLK-10 remains open and is load-bearing for this gate in later phases.** Reconciliation was
trivially clean only because the repo was empty. Once code exists, "which document wins on contracts"
must be answered before gate 2 can mean anything.

## Gate 3 — Red

```
Command: cargo test --workspace --no-fail-fast

Compile errors:         0     <- required; a collection/import error fails this gate
Tests red:              37
Failure kinds:          not-implemented = 37,  assertion = 0,
                        collection = 0, import = 0, syntax = 0
Freeze baseline:        gates/phase-0.1-tests.sha256 (4 files)
```

| Test target | Red | Spec ref |
|---|---|---|
| `proto/tests/version_floor.rs` | 8 | HR-1.6, §6.24, T31 |
| `agent-core/tests/rekor_inclusion.rs` | 10 | HR-12.2 check 2, §6.1 |
| `agent-core/tests/release_verification.rs` | 19 | HR-12.2, HR-12.3, §6.1, §6.27, §8 Update row |

All 37 failed with `not yet implemented`, achieved by writing the full API surface with `todo!()`
bodies before the tests. In a statically-typed language that is what "red for the right reason"
requires: a test calling a nonexistent function is a *compile* error, which would fail this gate.

### Exception — `protocol_absence.rs` reported 6 **passed** at gate 3

Those tests assert properties of the `.proto` file, which is itself the deliverable, so there was no
implementation to be missing. Under workflow §3.1 a passing test at gate 3 proves nothing, so they
were **mutation-tested** instead — the only evidence that a test has teeth:

| Mutation | Result |
|---|---|
| Added `message GrantCapability { string grant_capability = 1; }` | **RED** — `HR-1.1 violation: the wire schema declares ["grant_capability", "grantcapability"]` |
| Added a third arm to `oneof command` | **RED** — `Found 3 arms in oneof command` |
| Reverted | GREEN, 6/6; schema verified for zero mutation residue and zero non-ASCII bytes |

**Incident during the mutation test, recorded because it nearly went wrong.** The schema was untracked
at the time, so `git checkout --` could not restore it, and the PowerShell round-trip used to mutate it
also corrupted UTF-8 characters. The file was rewritten from source and verified clean (no `sneaky`
residue, exactly 2 oneof arms, 0 non-ASCII bytes). **Lesson: commit before mutating, or mutate a
copy** — a mutation test that cannot be reverted is an edit.

```
Verdict: PASS (with the documented exception above)
```

## Gate 4 — Implement

```
Manifest:
  crates/proto/src/lib.rs                  modified   check_version, decode_envelope,
                                                      has_recognised_payload
  crates/agent-core/src/rekor.rs           modified   RFC 6962 §2.1.1
  crates/agent-core/src/release.rs         modified   HR-12.2 four checks, HR-12.3 rollback
  .cargo/config.toml                       new        /Brepro (see gate 7 finding)
  Cargo.toml                               modified   reproducibility profile
  deny.toml                                modified   private/licences, wildcard paths

Files touched outside the manifest: crates/agent-core/tests/release_verification.rs
                                    -> see the freeze note at gate 5
Hard rules cited at the site:       HR-1.1, HR-1.2, HR-1.3, HR-1.4, HR-1.5, HR-1.6, HR-1.7,
                                    HR-2.1, HR-2.2, HR-2.4, HR-2.5, HR-4.9, HR-6.1, HR-7.1,
                                    HR-7.3, HR-7.5, HR-12.1..HR-12.5
Waivers:                            none

Blocker raised: BLK-12 (Rekor entry body + log trust root unpinned).
  Carries TODO(BLK-12) at crates/agent-core/src/release.rs, in the exact form gate 7 accepts.

Verdict: PASS
```

A design error was caught here by having written the tests first: the Rekor inclusion proof had been
modelled as a *field of* the manifest, which is impossible — the proof attests the digest of the
manifest, so embedding it makes the digest depend on itself. Corrected to a separate argument, matching
how Sigstore actually delivers it.

## Gate 5 — Green + aligned

### Spec alignment, clause by clause

| Spec clause | Implemented at | Complete |
|---|---|---|
| Cargo workspace with the 7 named crates + `broker-win` | `Cargo.toml`, `crates/*` | yes |
| Protobuf, explicit `v`, compiled-in `MIN_PROTOCOL_VERSION` | `tether.proto`, `proto/src/lib.rs` | yes |
| "Do not define grant, pair, wipe, elevate, or server-originated connect messages. Their absence is a security control — say so in a comment" | `tether.proto` header; `protocol_absence.rs` | yes |
| v4 clarification: `connect_request` exists, peer-to-peer; write the distinction in the comment | `tether.proto` HR-1.3 note | yes |
| "`elevate` and its capability token are deleted outright" | absent from `Capability`; `capability_enum_has_no_elevate` | yes |
| CI: clippy `-D warnings`, `cargo deny`, `cargo fmt --check`, `govulncheck` | all pass locally; govulncheck n/a (no Go module) | partial — no runner |
| "CI holds no signing credential" | trivially true; no CI and no key exists | vacuous |
| Rollback-manifest format defined now, not retrofitted | `release.rs` `RollbackManifest` + 6 tests | yes |
| Reproducible builds | `/Brepro`; see finding below | partial — path independence outstanding |
| `THREAT-MODEL.md`, `SECURITY-REVIEW.md` | `docs/` | yes |
| Offline signing / audit keypair / SPKI pin | — | **no**: hardware + BLK-9 |

### Test run

```
cargo test --workspace   ->  43 passed, 0 failed, 0 ignored
  protocol_absence      6
  version_floor         8
  rekor_inclusion      10
  release_verification 19
```

### Freeze check — BROKEN, and handled visibly

```
Result: BROKEN. 3 of 4 test files changed hash after gate 3.
Cause:  gate 7's `cargo fmt --all` reformatted them, plus one doc-comment edit in
        release_verification.rs required to clear a clippy `-D warnings` failure
        ("doc list item overindented").
Nature: formatting and doc-comment text only. No assertion, expected value, or test
        name changed. Test count identical before and after: 43.
        version_floor.rs hash UNCHANGED (29168761...) - the formatter did not touch it.
Action: re-baselined, with this note. NOT silently re-hashed.
```

Workflow §3.2 warns that a corrected specification of intent and a moved goalpost *look identical in a
diff*. That is exactly why this is written down rather than smoothed over: the mechanical check cannot
distinguish a formatter from a goalpost, so a human has to be told which it was.

**Process defect, and the fix.** Gate 3 should run `cargo fmt --all` *before* writing the freeze
baseline. Then gate 7's formatter has nothing left to change and cannot break a freeze it has no
business touching. Recommended amendment to `implementation-workflow.md` §4a.

### HR-15.6 three questions

Answered in full in [SECURITY-REVIEW.md](../../../SECURITY-REVIEW.md) §3 for all three controls added.
Summary: absences — exist / function / neither-but-stronger / **watched fail (2 mutations)**; version
floor — exist / function / authorizes / **partially** (red-then-green, not mutation-tested: gap);
update verification — exist / function / authorizes / **yes** (19 of 19 tests are failure cases).

```
Verdict: PASS on alignment and tests; freeze BROKEN and documented above.
```

## Gate 6 — Run

```
cargo run -p tether-agent-win    -> "tether-agent-win 0.1.0 · protocol v1 (floor v1)"   exit 0
cargo run -p tether-agent-linux  -> "tether-agent-linux 0.1.0 · protocol v1 (floor v1)" exit 0
cargo run -p tether-helper-win   -> "not implemented until Phase 7 (HR-7.3, HR-7.4)"    exit 1
cargo run -p tether-broker-win   -> "not implemented until Phase 2 (HR-7.1, §4.10)"     exit 1

Unit tier:        43 tests, no database, no network, no containers
Integration tier: none required this phase
```

The helpers and broker failing loudly with a non-zero exit is the intended behaviour, not an
oversight: HR-7.4 requires the helper to be **inert** outside an authorized session, and a stub that
silently succeeded would be the wrong default to establish.

### Manual exit criteria

| Criterion | Result | Note |
|---|---|---|
| "Two builds of the same commit are byte-identical" | **PASS**, same source path | after the `/Brepro` fix below |
| same, different source path | **NOT VERIFIED** | needs `--remap-path-prefix`; `trim-paths` unstable |
| "you sign one manually with the YubiKey" | **NOT DONE** | no hardware |
| "stub agent verifies signature + Rekor proof + version monotonicity, rejects a downgrade" | **PASS** | 19 tests; Rekor against synthetic trees (BLK-12) |
| "rollback manifest: stale epoch rejected, fresh accepted" | **PASS** | plus replay and wrong-named-version |
| "all three audit-key unwrap paths exercised" | **NOT DONE** | no authenticators; BLK-9 |

```
Verdict: PASS for what ran; four criteria explicitly NOT met, named above.
```

## Gate 7 — Scan

```
cargo fmt --all -- --check          exit 0
cargo clippy --workspace --all-targets -- -D warnings   exit 0
cargo deny check                    advisories ok, bans ok, licenses ok, sources ok
govulncheck                         N/A - no Go module this phase
TODO grep                           1 hit: TODO(BLK-12) - the permitted form only
Coverage                            not measured; no threshold configured yet
```

Two failures were found and fixed rather than waived: a clippy `manual_is_multiple_of` in the RFC 6962
walk, and `cargo deny` `bans` tripping on intra-workspace path dependencies (resolved with
`allow-wildcard-paths`; `wildcards = "deny"` still guards registry dependencies, which is the actual
T16 risk).

### Finding — HR-12.5 was not satisfied, and would have shipped silently

Two consecutive clean release builds of identical source produced **different** SHA-256 digests.
Cause: MSVC `link.exe` writes wall-clock time into the PE header `TimeDateStamp`. Every dependency was
pinned and it changed nothing — the nondeterminism sat two tools downstream of anything Cargo controls.

Fixed with `-Clink-arg=/Brepro`. Re-verified with build exit codes checked explicitly:

```
build 1: 7BD473CE1FE4D3AEA4E3D972042A3CBF0082A7F758BEC910BB377FEA04D9FD9B
build 2: 7BD473CE1FE4D3AEA4E3D972042A3CBF0082A7F758BEC910BB377FEA04D9FD9B  -> identical
```

**A false pass was reported before this.** An earlier run claimed the fix worked; in fact
`trim-paths = "all"` — which I had wrongly believed stable since Rust 1.81 — is a **hard error** in
Cargo 1.97.1, so those builds never ran and a stale binary was hashed twice. Corrected by removing
`trim-paths` and re-testing with `$LASTEXITCODE` and file existence asserted. The methodology lesson is
the transferable part: **comparing two hashes proves nothing unless you also prove both builds ran.**

```
Verdict: PASS
```

## Gate 8 — Commit

```
Gate 5 block present and passing:   yes (freeze break documented, not concealed)
Gate 7 block present and passing:   yes
Freeze re-verified:                 yes, against the re-baseline
Registry row updated:               yes
Blockers raised this phase:         BLK-12
Amendments applied:                 none
```

See [PHASE-REGISTRY.md](../PHASE-REGISTRY.md) for commits.

---

## Honest summary

**Delivered and verified:** the workspace, the wire protocol with mutation-tested absence enforcement,
the protocol version floor, full release and rollback verification (43 tests), the reproducibility
fix, and the two Phase 0 documents.

**Not delivered, and not deferred by preference:** the YubiKey ceremony, the audit keypair, the SPKI
pin, and CI wiring. Each needs hardware, a domain, or a remote that does not exist.

**Spec Phase 0 is NOT complete and its exit criterion is NOT met.** Three of six manual criteria are
unmet. Nothing here should be read as clearing HR-15.1 for spec Phase 1.

**Gate 1 halted and was overridden.** Twelve blockers remain open. BLK-9 alone gates five threats and
three of the undone Phase 0 items, and it is a ~$12 domain purchase.

---

# GATE RE-RUN — 2026-08-17, after all 13 blockers resolved

Appended, not rewritten. The original run above stands, including its gate 1 HALT — that
is a fact about what happened and does not become untrue because the condition later cleared.

**What changed between runs:** all 13 blockers resolved by the author; `HARD-RULES.md`
reconciled against the spec (1 contradiction, 1 internal inconsistency, 7 omissions);
`docs/engineering/{rust,go,kotlin}-hard-rules.md` created per BLK-11; workflow §8 amended;
AMD-1 and AMD-2 raised. **No test was modified.**

## Gate 0 — Status

```
Open blockers (module-wide):   0    (13 resolved)
Proposed amendments:           2    AMD-1 (spec §4.4, Phase 5), AMD-2 (spec §4.7, Phases 4/8)
This phase:                    0.1
```

Neither amendment touches a section in phase 0.1's scope. Workflow §4.2's "the phase does not
proceed" therefore binds **Phase 4 and Phase 5**, not this one — recorded so a later gate 1
does not have to rediscover it.

## Gate 1 — Order

```
Prerequisite phases:            none (first phase)
Open blockers anywhere:         0
Verdict: PASS
```

**This is the gate that halted on the first run.** It passed because the 13 questions were
answered, not because the check was loosened. The override recorded above remains in the file.

## Gate 2 — Reconcile

```
docs/engineering/rust-hard-rules.md      exists   (23 rules, RS-1..RS-23)
docs/engineering/go-hard-rules.md        exists   (16 rules, GO-1..GO-16)
docs/engineering/kotlin-hard-rules.md    exists   (16 rules, KT-1..KT-16)
workflow §8 amended: {go,python,react} -> {rust,go,kotlin}
Divergences in this phase's scope:       none
Verdict: PASS
```

One remaining match for `python,react` in the workflow is the amendment note itself, citing
what the line previously said. Historical citation, not a live binding.

## Gate 3 — Red / freeze

```
Freeze baseline: 4/4 files match. Tests untouched since the last commit.
Verdict: PASS (no new tests this run; nothing re-entered gate 3)
```

## Gate 5 — Green + aligned

```
cargo test --workspace  ->  43 passed, 0 failed
Freeze re-verified:         intact
Verdict: PASS
```

## Gate 6 — Run

```
tether-agent-win     "tether-agent-win 0.1.0 · protocol v1 (floor v1)"      exit 0
tether-agent-linux   "tether-agent-linux 0.1.0 · protocol v1 (floor v1)"    exit 0
tether-helper-win    refuses, exit 1                    (inert until Phase 7 — intended)
Reproducibility      7BD473CE1FE4D3AEA4E3D972042A3CBF...  byte-identical across clean rebuild
Verdict: PASS
```

Still not verified: byte-identity from a *different source path*. `trim-paths` is unstable in
Cargo 1.97.1; the `--remap-path-prefix` procedure is documented in REPRODUCIBLE-BUILDS.md but
not yet exercised. Unchanged from the first run and still outstanding.

## Gate 7 — Scan

```
cargo fmt --all -- --check                              exit 0
cargo clippy --workspace --all-targets -- -D warnings   exit 0
cargo deny check          advisories ok, bans ok, licenses ok, sources ok
TODO grep                 1 hit, TODO(BLK-12), the permitted form only
WAIVER grep               0
Verdict: PASS
```

`TODO(BLK-12)` was rewritten this run. It previously said the Rekor entry body "is not pinned
by the spec", which stopped being true when BLK-12 was resolved. It now records the decision
(option A), the three implementation steps Phase 10 owes, and an explicit warning not to ship
an auto-updater on the current placeholder leaf. A stale comment in security machinery is the
documentation-and-code-disagree defect WORKING-AGREEMENT §4 forbids.

## Gate 8 — Commit

Atomic commits on `phase-0-foundations`. Registry updated.

---

## ALL EIGHT GATES PASS.

**What that does and does not mean.**

It means: the process ran clean end to end, with no override, no waiver, no open question, and
43 tests behind it.

It does **not** mean spec Phase 0 is complete. Three exit criteria remain unmet, none of them
an engineering decision:

| Criterion | Blocked on |
|---|---|
| "you sign one manually with the YubiKey" | hardware, ~$75 |
| "all three audit-key unwrap paths are exercised" | 2× WebAuthn authenticators + the panel domain (BLK-9's retained precondition) |
| byte-identical builds from a *different source path* | `--remap-path-prefix` procedure not yet exercised |

HR-15.1 is therefore **not** cleared for spec Phase 1. Phase 0.2 remains blocked on purchases,
not on decisions.
