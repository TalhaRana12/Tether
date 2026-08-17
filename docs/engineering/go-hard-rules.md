# Go hard rules — tether

**Binding at every gate** ([implementation-workflow.md §8](../implementation-workflow.md)). Stable IDs.
**MUST** blocks merge. **SHOULD** needs a one-line justification. Break either only with a
`WAIVER GO-<n>: <reason>` comment at the site plus the same line in the pull request.

Created 2026-08-17 per the BLK-11 resolution, option C: **seeded, not comprehensive.** No Go exists yet —
the control plane is spec Phase 1 and the panel is Phase 4. This file starts near-empty on purpose: the
control plane is stdlib-shaped, and the rules that matter for it are mostly about what it must *not*
know.

The framing: **T1 assumes this code is fully compromised.** Every rule here is written for a service the
threat model already treats as hostile. That is unusual and it is the point — the control plane's job is
to relay bytes and issue tokens, and to be unable to do more.

---

## The server must not understand the session

**GO-1 (MUST)** `WS /v1/signal` treats every payload as `[]byte`. The server must not parse, inspect,
validate, log, or store the contents. No protobuf import in the signaling path.
*Why:* HR-11.2, verbatim. A parser here is a place to have a bug and a temptation to add a feature that
reads a session.

**GO-2 (MUST)** No code path exists that would let the control plane originate, approve, or observe a
session, or modify a host's allowlist or capabilities. Not disabled, not permission-gated — absent.
*Why:* HR-0.1, HR-1.1. The panel is a client of this service, and this service has no authority over any
host (HR-5.4).

**GO-3 (MUST)** Exactly two server-originated commands exist and are signed: `kill_session` and
`revoke_device`. Adding a third signed message type is a protocol change requiring the HR-1.4 review.

## Tokens

**GO-4 (MUST)** JWT verification follows HR-5.3 in order: key by `kid` from cached JWKS, **require
`alg == "EdDSA"`**, reject `alg == "none"` unconditionally, verify `iss`/`aud`/`exp`/`nbf` with ≤60s
skew, check `jti` against a replay cache, and require a live WebAuthn session for admin routes.
*Why:* rule 2 blocks the classic `alg` confusion attack, where an attacker flips to `HS256` and signs
with your **public** key as the HMAC secret. **Never read `alg` from the token to select the algorithm.**

**GO-5 (MUST)** The `role` claim grants nothing. Admin routes assert the authenticated WebAuthn
credential belongs to a registered admin; `role: admin` alone is never sufficient.
*Why:* HR-5.4, HR-9.5.

**GO-6 (MUST)** Refresh tokens are opaque 256-bit random values stored as Argon2id hashes, never JWTs,
and rotate on every use. Presenting one twice revokes the whole family and notifies the user.
*Why:* HR-5.2.

## Database and input

**GO-7 (MUST)** No SQL built by string concatenation, `fmt.Sprintf`, or template. Parameterised queries
only. Enforced by a repo grep gate.

**GO-8 (MUST)** Untrusted strings — device labels, display names, invite notes — are validated at ingest
against `^[\p{L}\p{N} _\-]{1,32}$` **server-side at write time**, and **rejected, not sanitised**.
*Why:* HR-9.7, T18. Sanitising means guessing what the attacker meant; rejecting does not.

**GO-9 (MUST)** Every request body, page size, and list response is bounded. No unbounded read, no
offset pagination on anything that can grow.

## Logging

**GO-10 (MUST)** `slog` structured output carrying **no secrets and no payloads** — no tokens, no
signaling bytes, no key material, no audit ciphertext.
*Why:* HR-11.5. Note that logs ship off-box in near-real-time (HR-11.3), so a leak here leaves the
building.

**GO-11 (MUST)** Log every security decision: who was refused what, and when. Origin and CSRF mismatches
are rejected **and logged** (HR-9.4).

## Concurrency and I/O

**GO-12 (MUST)** Every outbound call has a timeout and a `context.Context` threaded from the request. No
`context.Background()` in a request path.

**GO-13 (MUST)** No goroutine without a defined exit condition. A leaked goroutine holding a WebSocket
is a slow resource exhaustion in a service whose whole job is fan-out.

**GO-14 (MUST)** Guard shared state explicitly and run tests with `-race` in CI.

## Startup invariants

**GO-15 (MUST)** The monotonic revocation epoch is read at startup from off-box append-only storage and
compared. **A value lower than the last known epoch means refuse to serve and alert** — do not start
degraded.
*Why:* HR-5.6, T30, and the BLK-8 resolution. A restored backup that silently un-revokes devices is the
failure this exists to make loud.

## Globals

**GO-16 (MUST)** No mutable package-level state. Dependencies are passed in, so tests need no containers
and stay in workflow §5's unit tier. Enforced by a repo grep gate.

---

## Waiver format

```go
// WAIVER GO-12: startup-only migration, no request context exists yet; bounded by
// its own 30s timeout below.
ctx := context.Background()
```

The identical line goes in the pull request description.
