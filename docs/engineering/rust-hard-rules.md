# Rust hard rules — tether

**Binding at every gate** ([implementation-workflow.md §8](../implementation-workflow.md)). Stable IDs.
**MUST** blocks merge. **SHOULD** needs a one-line justification. The only way to break either is a
`WAIVER RS-<n>: <reason>` comment **at the site** plus the same line in the pull request.

Created 2026-08-17 per the BLK-11 resolution, option C: **seeded, not comprehensive.** Every rule below
is derived from something the spec or HARD-RULES already requires — none is invented taste. Rules get
added when a phase finds a problem for the third time, per workflow §6, not in advance.

Rust matters most here because it is where every `unsafe` block, the crypto, and the two privileged
binaries live.

---

## Memory and unsafe

**RS-1 (MUST)** Every crate carries `#![forbid(unsafe_code)]` **except** `agent-win` and `agent-linux`,
which need raw syscalls. `unsafe` anywhere else is a merge blocker, not a discussion.
*Why:* spec §3 chose Rust over C++ specifically to avoid the bug class this project exists to prevent.
An `unsafe` block in the protocol decoder gives that away for nothing.

**RS-2 (MUST)** Inside a permitted `unsafe` block: state the invariant being upheld in a comment
directly above it, and keep the block to the smallest expression that needs it. No `unsafe fn` wrappers
that make a whole function's body unchecked.

## Panics

**RS-3 (MUST)** No `.unwrap()`, `.expect()`, indexing, or arithmetic that can panic on **any value
derived from network input, IPC input, or a file the agent did not write**. Use `?`, `get()`,
`checked_*`, or an explicit match.
*Why:* HR-0.5 — every byte crossing a session is untrusted input. The worker holds all session keys
(HR-7.1), so a panic there is a remotely triggerable denial of service against the user's own access.

**RS-4 (MUST)** `.expect()` is permitted only for conditions that are impossible unless the *program*
is wrong — a compiled-in constant failing to parse, a lock poisoned by another panic. The message must
say what invariant was violated, not "should not happen".

**RS-5 (MUST)** `panic = "abort"` in release. Unwinding across an FFI boundary into Win32 or `uinput`
is undefined behaviour, and both privileged binaries sit next to one.

## Time

**RS-6 (MUST)** Local expiry uses `std::time::Instant`, never `SystemTime` or any wall clock. This
covers pairing TTL, capability-token expiry, idle timeout, consent timeout, and unattended windows.
*Why:* HR-6.1, T29. A local attacker who can move the clock must not be able to extend a grant.
`SystemTime` is permitted **only** for JWT `exp`/`nbf` (HR-6.2) and for an audit entry's `ts`, which is
explicitly not the ordering authority (HR-6.3).

**RS-7 (MUST)** Clocks are injected, never read from a global. A function that expires something takes
its time source as a parameter.
*Why:* workflow §5 requires unit tests to need nothing — no containers, no sleeping. A hardcoded
`Instant::now()` forces a timing test into the integration tier, where it becomes slow and then skipped.

## Privileged crates

**RS-8 (MUST)** `broker-win`, `helper-win`, and `helper-linux` have **zero dependencies**. Adding one is
a security change: cite HR-7.1 or HR-7.3 in the commit message and expect the line-by-line review those
rules require.
*Why:* a crate with no dependency that can open a socket cannot open a socket. The compiler enforces
what a review checklist only asks for.

**RS-9 (MUST)** Neither privileged binary may take a code path that is reachable when no authorized
session exists. HR-7.4: outside an authorized session the helper is **inert**. The escalation primitive
must not exist when nobody is connected.

## Crypto and encoding

**RS-10 (MUST)** Verify a signature over the bytes **as received**. Never re-serialise a struct and
verify that.
*Why:* two distinct messages that serialise identically is a forgery. See `release.rs`, where the
signature check deliberately precedes the JSON parser.

**RS-11 (MUST)** Ed25519 verification uses `verify_strict`, never `verify`.
*Why:* the permissive variant accepts small-order and non-canonical public keys, so one signature can be
valid under more than one key.

**RS-12 (MUST)** Every variable-length field in a hashed or signed input is **length-prefixed**. Bare
concatenation is forbidden.
*Why:* `"ab" || "c"` and `"a" || "bc"` are byte-identical. HR-10.2, and BLK-3 and BLK-13 are both
instances of this exact mistake.

**RS-13 (MUST)** No JSON serialiser — `serde_json` or otherwise — appears anywhere in a hash or
signature input path.
*Why:* HR-10.2a. `42`, `42.0`, and `4.2e1` are three legal encodings of one value and three different
hashes.

**RS-14 (MUST)** Nothing hashed, signed, or written to the audit chain may depend on `HashMap` or
`HashSet` iteration order. Sort explicitly, or use an ordered collection.
*Why:* Rust randomises hash iteration order **per process**, deliberately. An unsorted capability list
gives the same audit entry a different hash after every restart — indistinguishable from tampering.

**RS-15 (MUST)** Key material and secrets are zeroized on drop (`zeroize`), never appear in a `Debug`
impl, and are never passed to a logging macro. Derive `Debug` manually on any type holding one.
*Why:* HR-11.5 — structured logs carry no secrets and no payloads.

## Parsing untrusted input

**RS-16 (MUST)** Every decode has a compiled-in size cap applied **before** allocation. No
`read_to_end` on a socket, no length field trusted without a bound check.
*Why:* HR-8.1 requires exactly this before `MediaCodec`; the same reasoning applies to every decoder on
either side (HR-8.4).

**RS-17 (MUST)** A capability check happens **before** the gated message body is parsed, never after.
*Why:* HR-2.5, verbatim.

**RS-18 (SHOULD)** Prefer a type that cannot hold an invalid value over a validation function someone
can forget to call. A `PairingToken([u8; 16])` that can only be built by a constructor beats a
`Vec<u8>` plus a `check_token_length` helper.

## Errors

**RS-19 (MUST)** Handle every error deliberately: handle it, wrap it with context and return it, or
document why ignoring it is safe. Never `let _ =` on a `Result` without a comment giving the reason.

**RS-20 (MUST)** An error returned across a trust boundary carries no internal detail — no paths, no
key material, no host names. Log the detail locally with an identifier; return the identifier.
*Why:* WORKING-AGREEMENT §7.

**RS-21 (MUST)** Validation failures and internal failures are distinguishable error variants. "You sent
something malformed" and "we are broken" must never be the same value.

## Dependencies

**RS-22 (MUST)** `crates.io` only. No `git` dependencies, no alternate registries, no path dependencies
outside this workspace. Enforced by `cargo deny`'s `sources` check.
*Why:* T16. Code nobody audited entering a binary that runs on family members' machines.

**RS-23 (MUST)** `Cargo.lock` is committed, and the toolchain is pinned in `rust-toolchain.toml`.
*Why:* HR-12.5 — two builds of the same commit must be byte-identical.

---

## Waiver format

```rust
// WAIVER RS-3: length is a compiled-in constant, not network-derived; a panic here
// would mean the binary itself is corrupt.
let bounds = KNOWN_BOUNDS[idx];
```

The identical line goes in the pull request description. A waiver in the code without one in the PR is
not a waiver — it is an undocumented rule break, and gate 7 treats it as one.
