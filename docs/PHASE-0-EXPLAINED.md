# Phase 0, explained

A walk through everything built in Phase 0: **what each file is, why it exists, and what
would go wrong without it.** Written to be read start to finish by someone learning, not
as a status report.

If you read one thing, read §1 and §11.

---

## 1. What a "foundations" phase is actually for

The instinct with a new project is to build the exciting part first — get video on a
screen, then harden it. Phase 0 exists because for *this* project that order produces
something that cannot be fixed later.

Three of the things Phase 0 builds are **one-way doors**:

| Decision | Why it cannot be changed later |
|---|---|
| The **wire protocol** | Once two devices speak v1, every future version must handle v1 or break them |
| The **release signing key** | Agents verify against the key *compiled into the binary*. A new key only reaches them inside an update signed by the **old** one. Lose it and you cannot ship to existing installs, ever |
| The **audit chain shape** | A hash chain cannot be migrated without breaking every hash in it |

The spec's own §6.13 is the cautionary tale: the v3 design specified a Windows agent that
*could not capture the screen at all* — services run in session 0, and screen capture
needs an interactive session. Nobody noticed for a whole revision because everyone was
asking "is this mitigation strong?" instead of "does this component exist?"

**So Phase 0 builds the doors before anyone walks through them.**

---

## 2. The map

```
Cargo.toml, rust-toolchain.toml, .cargo/config.toml   build reproducibility
deny.toml                                             dependency policy
crates/proto/                     ← the wire protocol (and its absences)
crates/agent-core/                ← update verification
crates/{agent,broker,helper}-*/   ← privilege boundaries, enforced by the compiler
go.mod, control/, admin/          ← control plane and panel (stubs)
internal/cigates/                 ← Android manifest gate, no SDK needed
android/                          ← Gradle project + hardened manifest
panel/                            ← in-browser audit keypair + Playwright tests
tools/                            ← release signing ceremony
keys/                             ← public halves only
.github/workflows/ci.yml          ← the gates, automated
docs/                             ← threat model, review, blockers, gate traces
```

**67 tests. 7 mutation tests. 21 commits.**

---

## 3. `crates/proto/` — the protocol, and the security control that is an absence

### The file that matters

[`crates/proto/proto/tether/v1/tether.proto`](../crates/proto/proto/tether/v1/tether.proto)

This is a **Protocol Buffers schema** — a language for describing messages, plus a compact
binary encoding. You write the schema once and `protoc` generates matching Rust, Go, and
Kotlin code from it.

**Why that matters here:** three languages must agree byte-for-byte on every message. Three
hand-written parsers *will* disagree, and the disagreement shows up in production. One
schema, three generated parsers, no disagreement possible.

### The unusual part

Most of this file's security value is in what it **does not contain**. HR-1.1 lists
messages with *no wire representation*:

```
grant_capability · add_peer · start_session · join_session
observe_session · wipe · reset · reconfigure · elevate
```

Not disabled. Not permission-gated. **Absent.**

**Why absence rather than a permission check?** A permission check is code. Code has bugs.
A compromised admin account plus one authorization bug equals a session on someone's
laptop. A message that does not exist has no bug to find.

This is the difference between *"the admin is not allowed to do X"* and *"there is no way
to express X"*. The second is auditable by reading one file.

### The test that makes it real

[`crates/proto/tests/protocol_absence.rs`](../crates/proto/tests/protocol_absence.rs)

A comment saying "don't add these" is advice. This test is enforcement: adding
`grant_capability` to the schema **fails the build**.

**A subtlety worth understanding.** The schema legitimately *mentions* every forbidden name
— in the comments explaining why they are absent. A naive substring search would fail
against a perfectly correct file. So the test strips comments first, and then a second test
(`absence_test_can_actually_see_declarations`) proves the stripped text is not simply
empty.

> **The general lesson:** a test that passes because it is looking at nothing is worse than
> no test. Whenever you filter or strip before asserting, add a positive control that the
> filter did not eat everything.

**Watched it fail:** adding `message GrantCapability` → red. Adding a third arm to the
`ServerCommand` oneof → `Found 3 arms in oneof command`.

### The version floor

[`crates/proto/src/lib.rs`](../crates/proto/src/lib.rs) holds `MIN_PROTOCOL_VERSION`.

Every message carries a version number `v`. The build refuses anything below the floor —
**no negotiation, no fallback**.

**Why no fallback?** Versioning *without* a floor is a downgrade oracle. Suppose you fix a
flaw in v1 and ship v2. If an attacker can say "let's speak v1", your fix is optional. The
floor is what makes a fix stay fixed.

The load-bearing test is `well_formed_message_below_floor_is_still_refused_no_fallback`: a
*valid, parseable* old-version message is still refused. Asserting only that a bad version
errors would not prove there is no fallback path — and the absence of that path is the
whole control.

**Concept to learn:** *downgrade attacks*. This is the same family as TLS's POODLE.

---

## 4. `crates/agent-core/` — update verification

[`src/release.rs`](../crates/agent-core/src/release.rs) implements the four checks an agent
runs before installing an update (HR-12.2):

1. **Ed25519 signature** against the key compiled into the binary
2. **Rekor inclusion proof** — the artifact appears in a public log
3. **version > current** — downgrade refused
4. **rollout cohort** — staged 5% / 25% / 100%

### The ordering is a security property, not style

The signature is verified over the bytes **as received**, *before the JSON parser runs*.

Think about the sizes involved. An Ed25519 verify is a small, well-audited operation. A
JSON parser is thousands of lines. If you parse first and verify second, you have exposed
the large attack surface to unauthenticated input.

The test `signature_is_checked_before_the_body_is_parsed` feeds garbage with a bad
signature and requires `BadSignature` — **never** `Malformed`. A `Malformed` there would
prove the parser ran first.

> **Concept to learn:** *verify-then-parse*. Also why the signature covers bytes-as-received
> rather than a re-serialised struct: two different messages that serialise identically is
> a forgery.

### Rekor, and what a transparency log actually buys

[`src/rekor.rs`](../crates/agent-core/src/rekor.rs) implements RFC 6962 Merkle inclusion
proofs.

An ordinary signature proves *"whoever holds the key approved this"*. It cannot tell you
whether the key was **stolen**. A transparency log is an append-only public ledger of every
signature made. Combine them: a release only verifies if it also appears publicly. An
attacker who steals your key can still forge a release — but **cannot do it invisibly**.

Detection, not prevention. That distinction is worth internalising; a lot of security is
one or the other and confusing them leads to bad designs.

**The domain separation detail:** leaves hash with a `0x00` prefix, interior nodes with
`0x01`. Drop the prefixes and an attacker can present an interior node *as* a leaf — a
second-preimage attack that forges inclusion for content never logged. One byte, and
without it the whole structure is worthless.

**On the test fixtures:** the trees are built by an independent *recursive* transcription of
the RFC, while the code under test is *iterative*. Two implementations of one spec agreeing
is evidence. One implementation agreeing with itself is not.

---

## 5. The crate split — a security control the compiler enforces

Look at [`crates/helper-win/Cargo.toml`](../crates/helper-win/Cargo.toml):

```toml
[dependencies]
# intentionally empty
```

HR-7.3 requires the input helper to have **no network code**. You could write that in a
review checklist. Instead: **a crate with no dependency that can open a socket cannot open
a socket.** The compiler enforces what a checklist only requests.

Same for `broker-win` (HR-7.1: "no capture code, no input code, no session keys, no network
code").

> **The general principle: make illegal states unrepresentable.** Prefer a design where the
> wrong thing *cannot be expressed* over one that checks for it at runtime. A type that only
> permits valid values beats a validation function someone can forget to call.

`cargo-deny`'s `[bans]` list is the second layer, catching a *transitive* arrival.

---

## 6. Reproducible builds — and the bug that only appeared when measured

HR-12.5: two builds of the same commit must be byte-identical, and a third party must be
able to verify a binary against source.

**Why:** signing proves *who* built it, never *what they built from*. Reproducibility is
what lets someone who does not trust you check that the shipped binary contains nothing
that is not in the published source.

### It did not work, and reading the config would never have shown that

Two consecutive clean release builds of identical source produced **different SHA-256
digests**. Every dependency was pinned and it made no difference.

The cause was two tools downstream of anything Cargo controls: **MSVC's `link.exe` stamps
the wall-clock time into the PE header.** Fixed with `-Clink-arg=/Brepro`
([`.cargo/config.toml`](../.cargo/config.toml)), which makes that field a hash of the input
instead of a clock reading.

A second half: `rustc` bakes the *source directory path* into panic messages, so a verifier
who clones to a different folder gets different bytes. Fixed with `--remap-path-prefix`.
Verified: identical digests from two different source paths.

> **Two transferable lessons.** First, reproducibility fails at the **last** tool in the
> chain as readily as the first. Second — and this cost me two false "PASS" reports —
> **comparing two hashes proves nothing unless you also prove both builds ran.** Both times
> I hashed a stale binary from a failed build. Check exit codes.

---

## 7. `panel/` — the audit keypair, and why Playwright

### What the key is for

The admin audit key is X25519. Hosts seal their audit log entries to its **public** half
(HPKE), so the server stores ciphertext it cannot read. Only the admin's private half opens
them.

### Three independent wraps

HR-4.5 wraps that private key **three times, independently**: authenticator A,
authenticator B, and a 256-bit paper recovery secret. **Any one opens it. Losing all three
is the intended terminal failure — there is no fourth copy anywhere.**

That last sentence is a design decision, not an oversight. A fourth copy held by anyone
else is a fourth way in.

### Why there is no password anywhere

Spec §6.8 was a **high** finding: dump the database, guess passphrases offline on rented
GPUs, confirm each guess against a known ciphertext, recover every audit log.

The fix was **structural** — remove the guessable input entirely (HR-4.6). There is no
passphrase in this chain, so there is nothing to attack offline.

### Why Playwright, and not a unit test

Four properties here are **invisible to a unit test**, and they are the ones that matter:

| Property | Rule |
|---|---|
| no password/passphrase input exists anywhere in the DOM | HR-4.6 |
| the private key never reaches `localStorage`/`sessionStorage` | HR-4.7 |
| the page makes **zero** external requests | HR-9.7 (no CDN) |
| crypto comes from WebCrypto in a secure context | HR-4.1 |

These are facts about a real page in a real browser. Rust cannot see them.

[`panel/server.js`](../panel/server.js) sends the **real** CSP, so an inline script or a CDN
reference is blocked by the *browser* and fails the tests — not merely flagged in review.

### The `prf` extension

WebAuthn's `prf` extension asks an authenticator to derive bytes from a secret that **never
leaves the device**. That derived value becomes the wrapping key. So the wrapping key
cannot be extracted — only exercised on the device.

Chrome's *virtual* authenticator supports `prf`, which is why all three wrap paths are
testable with **no security keys plugged in**. That tests our derive/wrap/unwrap logic —
the half that can silently be wrong. Registering real devices is a two-minute human action.

### The wordlist, and a judgement call worth explaining

[`panel/static/wordlist.js`](../panel/static/wordlist.js) is 256 words, 8 bits each, so 32
words carry 256 bits.

The obvious choice was **BIP-39** (2048 words, 11 bits each, 24 words). It was rejected
deliberately: a wordlist I cannot verify by eye is a wordlist with a typo in it, and **one
wrong word makes a printed recovery secret unreadable** — with no fourth copy behind it.
256 words is short enough to audit by reading, and one byte per word means no bit-packing
arithmetic, which is the other place BIP-39 implementations go wrong.

Verified **by machine**, and that caught two real defects: two words shared a 4-character
prefix (`audio`/`audit`, `basil`/`basin`), which breaks recoverability from smudged
handwriting — and my own hand-count of the list was wrong.

---

## 8. `tools/` — the signing ceremony, and an assumption that turned out false

HR-0.2, one of four governing rules:

> **Nothing online can sign a release.** The release key is offline hardware requiring a
> physical touch. CI can build; only a human with the token can ship.

The attack (spec §6.1, T16): steal a CI token, trigger a release, CI signs, and every agent
auto-updates to a backdoored build **with a valid signature**.

### The assumption that was wrong

The plan was to put the key in this machine's TPM. Then I tested it:

```
CngKey.Create(ED25519, "Microsoft Platform Crypto Provider")
  -> "The requested operation is not supported."
```

**The Windows TPM cannot hold an Ed25519 key.** It offers RSA.

Two ways out:

| Option | Cost |
|---|---|
| Sign with a TPM **RSA** key | non-exportable, but breaks HR-4.1's pinned EdDSA and forces a rewrite of the tested verifier |
| Keep **Ed25519**, seal its seed under a TPM RSA key | algorithm preserved; the seed is briefly in memory while signing |

Took the second. The seed is 256 bits of CSPRNG output, encrypted at rest under a
**non-exportable** TPM key ([`tools/tpm-seal.ps1`](../tools/tpm-seal.ps1), export policy
`None`, RSA-OAEP-SHA256 — not PKCS#1 v1.5, which has a long history of decryption oracles).

### What that keeps and what it costs

| Property HR-0.2 buys | TPM substitute |
|---|---|
| CI cannot sign | ✅ **kept in full** — the property that carries the weight |
| key useless on another machine | ✅ kept — only this TPM unwraps it |
| malware running as you cannot extract it | ❌ **lost** — in memory during signing |
| physical touch per signature | ❌ **lost** |

Recorded at HR-0.2 and in HR-14.4's accepted risks, **not** quietly declared equivalent.
The consequence binds: **do not distribute builds to anyone else** until the Phase 6
Android client can hold the key in StrongBox behind a biometric, which restores the fourth
property for free.

### The most valuable test in the repo

[`crates/agent-core/tests/real_signature.rs`](../crates/agent-core/tests/real_signature.rs)

Every other test in that crate signs with a seed it defines itself. That proves the
verifier is **self-consistent** — and self-consistency is exactly what a signing pipeline
fails at. The interesting failure is not "the verifier is wrong", it is **"the signer and
the verifier disagree"**, and no self-generated signature can ever see it.

So these fixtures were **captured from the real ceremony**: keygen → TPM seal → delete
plaintext → unseal → sign. If the signer ever changes how it pads or orders anything, this
test goes red while the deterministic ones stay green.

> **Concept to learn:** *cross-implementation testing*. Any time two programs must agree,
> test them against each other, not each against itself.

---

## 9. `internal/cigates/` — a gate that keeps running

HR-8.5 requires the Android manifest to set `allowBackup="false"`,
`usesCleartextTraffic="false"`, no exported components, and no surveillance permissions.

The obvious home is `gradle lint`. **But a gate that only runs when a full Android SDK is
present is a gate that silently stops running** — on a fresh checkout, in a container, or
the day an AGP bump breaks the build for an unrelated reason.

> implementation-workflow.md §6: *"a gate that is too slow gets disabled, and a disabled
> gate is worse than no gate because everyone believes it is running."*

So the security-relevant half is a plain Go test: milliseconds, no SDK, no network.
`gradle lint` still runs for everything else.

### Two gates disagreed, and the newer one was right

My Go test required `android:debuggable="false"` in the manifest. `gradle lint` flagged
that as `HardcodedDebugMode`, **Fatal** — and lint was correct: AGP injects the value per
build type, so a hardcoded attribute can *mask* what the release build actually produced.
I was asserting a value that does not control the outcome.

Moved the check to where the value is decided. **Two tools disagreeing and the better one
winning is the review process working.**

### The permission list

`TestNoSurveillancePermissions` rejects `RECORD_AUDIO`, `CAMERA`, any `LOCATION`,
`QUERY_ALL_PACKAGES`, `BIND_ACCESSIBILITY_SERVICE`, and others.

**Why check permissions rather than code?** HR-10.7's never-logged list has *"no code
path"*. A permission is the *beginning* of a code path — the earliest visible sign that the
line is about to be crossed. HR-10.8: *"If you are ever tempted to add an item from the
second list, that is the moment this stops being a remote-access tool and becomes
monitoring software."*

---

## 10. `.github/workflows/ci.yml` — defined by what it lacks

Six jobs. The most important property is an **absence**: there is no `secrets.SIGNING_KEY`,
no cloud-KMS role, no OIDC trust that can sign a release.

Verified mechanically against the *parsed* YAML — the only secret is
`secrets.GITHUB_TOKEN`, and top-level permissions are `contents: read`. The one occurrence
of `SIGNING_KEY` is inside a comment explaining why it is absent.

**A workflow that cannot sign makes a stolen CI token worth a build log.**

The `reproducible` job is not ceremony: the default configuration was *not* reproducible,
so that job is what stops the `/Brepro` fix silently regressing.

---

## 11. The five ideas worth taking to any project

Everything above is an application of one of these.

**1. Absence beats a permission check.** A message that does not exist has no authorization
bug. Where you can delete a capability instead of guarding it, delete it.

**2. A control you have never seen fail is a control you have never seen.** Seven mutation
tests were run. Six confirmed a guard. **One proved a guard I had already written into a
gate file as evidence was worthless** — the authenticator-independence test passed even
when the wrapping key was a constant, because the second device had no credential at all
and failed before reaching decryption. Green tests are a floor, not a target.

**3. Verify before you parse; length-prefix before you hash.** Both are the same idea:
*canonicalisation ambiguity*. `"ab"+"c"` and `"a"+"bc"` are byte-identical, so two different
inputs share one hash — a forgery. This appeared **three times** in one phase: release
verification dodged it by signing bytes as received; the helper token dodges it by
length-prefixing; the audit chain had no dodge available, so it stopped using JSON for
hashing entirely.

**4. Test what a tool cannot see, with a tool that can.** Playwright is not there for
coverage. It is there because "no password field exists in the DOM" and "the key never
reaches localStorage" are facts about a browser, and no Rust test will ever observe them.

**5. Measure, do not read.** Reproducibility looked fine in the config and was broken. The
TPM looked like it would hold an Ed25519 key and could not. My own test looked like it
proved independence and did not. **Every one of those was found by running something.**

---

## 12. What Phase 0 still owes

Nothing left costs money.

| Outstanding | What it needs |
|---|---|
| CI has never executed | a `git push` to GitHub |
| Real audit keypair + key list entry | ~2 minutes in a browser registering two authenticators |
| Sigstore/Rekor end-to-end on a dummy artifact | a `cosign` round-trip against the public log |
| SPKI + server identity pin | Phase 1's deployed control plane |

And one constraint that binds before the second row: **the panel domain must be chosen
first.** Registering a WebAuthn credential freezes the RP ID, and changing it later kills
both hardware wraps, leaving only the paper secret — one copy away from the terminal
failure HR-4.5 keeps three copies to avoid.

## 13. What to read next

- **Compilation vs. linking**, and *target triples* — explains most confusing build errors
- **Canonicalisation ambiguity** — the bug class in idea 3; XML Signature has a decade of
  CVEs from it
- **Transparency logs** — Rekor, and Certificate Transparency for the same idea in TLS
- **Mutation testing** — the only real evidence a test has teeth
- **RFC 6962** §2.1 — short, readable, and the domain-separation reasoning is worth seeing
  first-hand
- **WebAuthn `prf`** — how a device derives a key it will never hand over
