# Blockers — module `tether`

**Any `OPEN` entry here halts every phase in the module**, not only the one that raised it
([implementation-workflow.md §4.1](../../implementation-workflow.md)). `impl-phase-status` reports
open blockers first; `impl-phase-validate` refuses to start or advance any phase while one exists.

The wide scope is the point: a blocker raised at phase 3 about a stored shape is a question every
later phase builds on top of, so letting phase 7 proceed only buries it deeper. An unanswered
question stops the build — that is the mechanism behind "nothing goes without being seen."

**Resolution fields are written by a human.** An agent never fills one in.

**Current state: 12 open, 0 resolved. The module is halted.**

BLK-12 was raised during workflow phase 0.1 by the work itself — the shape it asks
about was reached while implementing, which is the mechanism functioning rather than
failing.

BLK-1 through BLK-9 are [HARD-RULES.md](../../HARD-RULES.md) Appendix A transcribed into Blocker
Record form — the spec author's own list of places not to guess. BLK-10 and BLK-11 were raised by
reconciling the four documents against each other on 2026-08-17.

---

## BLK-1 — Media key derivation input is probably wrong            [OPEN]
**Spec phase:** 5   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2 (Reconcile), pre-flight
**Where:** spec §4.4 (media key schedule) · HARD-RULES A-1, HR-4.3, HR-4.3e
**The question:** what exactly is the `salt` input to `HKDF-Extract` for the media key schedule?

**What the documents say nearest to it:** spec §4.4 line 241 specifies
`base = HKDF-Extract(salt = noise_handshake_hash, ikm = "tether-media-v1")`. HR-4.3 already states it
differently — `salt = <noise session secret>` — and HR-4.3e says do not improvise it. In the Noise
specification the handshake hash `h` is explicitly **not secret**: it is computed from the protocol
name, the public keys, and the transmitted ciphertexts, all of which a passive relay observes. If `h`
is the only input, the relay derives the media keys and the "relay CANNOT decrypt" property in spec
§4.4's own diagram collapses — along with T1, T2, and the Phase 5 exit criterion that `tcpdump` on the
relay recovers no decodable frame.

**Options:**
A — `Split()` output: use the `CipherState` keys from the Noise `Split()` as the extract salt. Secret
by construction, no new primitive. Cost: pins us to whatever `snow` exposes.
B — a proper Noise exporter over the chaining key `ck`. Cleanest cryptographically and the
conventional answer. Cost: must confirm `snow` and `noise-java` both expose it identically, or write
it on both sides and test for agreement.
C — keep `h` as specified. Costs the entire end-to-end confidentiality property. Listed only to be
rejected explicitly.

**Recommendation:** B, with A as the fallback if the two libraries disagree. Note separately that
using `h` for the **SAS** (spec §4.3, HR-3.1 step 6) is *correct* and must not change — `h` is
exactly the right input there, and the fix must not "helpfully" alter it.

**If unanswered I will:** stop. No provisional stub — this is a wire-observable cryptographic
construction, and a placeholder that later ships is the failure mode this record exists to prevent.

**Resolution:** _(written by a human)_

---

## BLK-2 — `epoch` field width and byte order are unstated            [OPEN]
**Spec phase:** 5   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2 (Reconcile), pre-flight
**Where:** spec §4.4 · HARD-RULES A-2, HR-4.3
**The question:** how many bits is `epoch`, in what byte order is `epoch || ctr` concatenated, and
what is the exact frame-header wire layout?

**What the documents say nearest to it:** `nonce = salt XOR (epoch || ctr)` with a 12-byte salt and an
explicit 48-bit counter, which leaves 48 bits for `epoch` — but the width is never stated and neither
is the endianness. HR-4.3d rekeys by incrementing `epoch`, so both sides must agree bit-for-bit or
every frame after the first rekey fails authentication. The header is also the AAD (HR-4.3), so its
layout is covered by the MAC and cannot be changed later without a protocol version bump.

**Options:**
A — 48-bit epoch, big-endian, filling the salt exactly. Symmetric with the counter, no padding.
B — 32-bit epoch with 16 bits reserved zero. Smaller field to carry on the wire; reserved bits are a
future extension point.

**Recommendation:** A, big-endian (network order), and pin the frame header as an explicit
byte-offset table in the `.proto` comment rather than prose — a Rust encoder and a Kotlin decoder
written from prose will disagree exactly once, in production, on a rekey boundary.

**If unanswered I will:** stop. Wire shape, observable from outside the process.

**Resolution:** _(written by a human)_

---

## BLK-3 — Who holds `noise_session_key` for helper token verification            [OPEN]
**Spec phase:** 7   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2 (Reconcile), pre-flight
**Where:** spec §6.2, §6.9 · HARD-RULES A-3, HR-7.4
**The question:** the input helper must verify `HMAC(noise_session_key, "input" || session_id ||
expiry)`, so it needs that key or a derivation of it. Which, exactly?

**What the documents say nearest to it:** HR-7.1 says the privileged component holds **no session
keys** — "no capture code, no input code, no session keys, no network code" — and spec §4.10 repeats
it. Handing the raw `noise_session_key` to a SYSTEM process contradicts both. HARD-RULES A-3 states a
preferred resolution already: the worker derives a dedicated
`key_helper = HKDF-Expand(base, "helper-token", 32)` and hands **only that** to the helper at session
start.

**Options:**
A — dedicated `key_helper` per A-3. The helper holds a key that verifies input tokens and decrypts
nothing. Compromising it yields no session content.
B — hand over the session key. Simpler, and it puts media-decrypting key material inside a SYSTEM
process. Rejected on HR-7.1.

**Recommendation:** A. Additionally pin **length-prefixed** encoding for the HMAC input rather than
bare concatenation — `"input" || session_id || expiry` with variable-length fields is a canonical
ambiguity, and two different tuples that serialise identically is a forgery.

**If unanswered I will:** stop. This is a local IPC wire shape plus a security property.

**Resolution:** _(written by a human)_

---

## BLK-4 — Unattended access versus an unreachable lock screen            [OPEN]
**Spec phase:** 5, 8, 10   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2, pre-flight
**The question:** given that the lock screen is uncapturable, what does "unattended access" actually
deliver, and does the onboarding copy say so plainly?
**Where:** spec §4.9, §6.15 · HARD-RULES A-4, HR-2.3, HR-14.2

**What the documents say nearest to it:** HR-2.3 offers an unattended window; HR-14.2 makes the lock
screen and greeter unreachable, deliberately and permanently. A machine that is genuinely unattended
is usually locked. So unattended access resolves to *"connect to a machine that is logged in,
unlocked, and unattended"* — a much narrower feature than "unattended access" implies, and unattended
access is the honest reason most people install remote desktop software (spec §4.9).

**Options:**
A — ship it as-is and state the limitation plainly in the onboarding doc and in the mode-selection UI
at the moment the user opts in.
B — drop the unattended mode entirely, leaving "ask every time" and "always allow".

**Recommendation:** A. This is a copy and expectation-setting decision, not an engineering one, but it
must be made before the Phase 8 UI and the Phase 10 onboarding doc are written, and the wording is
what needs approving.

**If unanswered I will:** stop before writing the mode-selection UI copy. Phase 8's consent gate
itself is unaffected and can proceed.

**Resolution:** _(written by a human)_

---

## BLK-5 — Nothing rate-limits `connect_request`            [OPEN]
**Spec phase:** 8   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2, pre-flight
**Where:** spec §4.9 · HARD-RULES A-5, HR-2.1
**The question:** what limits how many consent prompts a paired device can generate?

**What the documents say nearest to it:** HR-2.1 fixes the consent sequence and makes a 60s timeout a
Deny, but nothing caps request frequency. This is the MFA-fatigue shape: the attacker's goal is not to
be allowed, it is to be annoying enough that someone taps Allow at 3am to stop the buzzing. A control
that can be worn down is HR-2.9's problem in a different costume — it satisfies the letter of
"authorization" while functioning as attrition.

**Options:**
A — per-device cooldown after a Deny (escalating), a cap on outstanding prompts, and auto-quarantine
after N consecutive denials, with the quarantine cleared only on the host.
B — cooldown only. Less state to keep, leaves the slow-drip version open.

**Recommendation:** A with N=3, escalating cooldown, and `connect_denied` already covered by
HR-10.7's logging so quarantine is visible in the audit trail. Needs the exact numbers approved since
they are user-visible behaviour.

**If unanswered I will:** stop before implementing the consent gate's request handler. Note this is
the largest single item in spec phase 8 (HR-15.4), so this blocker is on the critical path.

**Resolution:** _(written by a human)_

---

## BLK-6 — Delete-user cascade-deletes audit replicas            [OPEN]
**Spec phase:** 4   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2, pre-flight
**Where:** spec §5.1 (Delete user) · HARD-RULES A-6, HR-9.9, HR-10.1
**The question:** is a one-click admin path that destroys server-side audit history compatible with
"none is irreversible" and "nobody can silently truncate it"? If yes, under what ceremony?

**What the documents say nearest to it:** spec §5.1 gives Delete user the effect "cascade-deletes
devices, tokens, audit replicas". HR-9.9 says every admin operation reduces access and **none is
irreversible**; HR-10.1 says nobody can silently truncate the log. The host copy is authoritative and
survives (HR-10.2), which makes this defensible — but "defensible" and "silent cascade" are different
things, and HR-10.4 renders shortfalls as `TRUNCATED — N entries missing`, which a legitimate delete
would trigger indistinguishably from an attack.

**Options:**
A — separate, explicitly-audited, step-up-gated operation that writes a retention tombstone
`(device_id, max_seq, head_hash, deleted_at, admin)` so the panel renders "deleted by admin" rather
than "TRUNCATED".
B — do not delete replicas on user delete; let the 90-day retention cap (HR-10.5) expire them.

**Recommendation:** A. It keeps the operation available, keeps it reversible-in-evidence if not in
data, and stops a routine admin action from looking exactly like the attack HR-10.4 exists to detect.

**If unanswered I will:** stop before implementing `DEL /admin/users/:id`. Other panel routes proceed.

**Resolution:** _(written by a human)_

---

## BLK-7 — `file_transfer` logs the filename            [OPEN]
**Spec phase:** 9   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2, pre-flight
**Where:** spec §5.3 · HARD-RULES A-7, HR-10.7, HR-10.8
**The question:** does the `file_transfer` audit entry record the filename, or only direction and size?

**What the documents say nearest to it:** HR-10.7 logs `file_transfer` with "direction, name, size",
while the never-logged list in the same rule forbids "locally opened files". A filename is
content-adjacent metadata about a user's machine — `resignation-letter-draft.docx` tells the admin
something the never-logged list is written to keep them from knowing. HR-10.8 says the moment you add
from the second list is the moment this becomes monitoring software.

**Options:**
A — direction and size only. Loses the ability to answer "which file went out", which is the thing an
incident actually needs.
B — log the name, and justify it explicitly in the transparency panel copy (HR-10.9 already lists
exact event types to the host user) so the user knows before they transfer anything.

**Recommendation:** B *only if* the transparency panel names it in plain language; otherwise A. What
must not happen is logging the name while the panel implies content-adjacent data is never recorded —
that is the documentation-and-code-disagree defect, applied to a promise rather than a function.

**If unanswered I will:** stop before implementing the file-transfer audit entry. Spec phase 9 is
cuttable entirely under HR-15.4, so this is the lowest-urgency blocker here.

**Resolution:** _(written by a human)_

---

## BLK-8 — Where the revocation epoch lives            [OPEN]
**Spec phase:** 1   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2, pre-flight
**Where:** spec §6.23, Phase 1 · HARD-RULES A-8, HR-5.6
**The question:** HR-5.6 requires the monotonic revocation epoch be persisted "outside the main
database". Outside it *where*?

**What the documents say nearest to it:** it must be somewhere a `pg_dump` restore cannot roll back
and a compromised control plane cannot lower. Those two requirements pull apart: the control plane has
to *read* it at startup and *increment* it on every revoke, so it needs write access to whatever holds
it — and T1 assumes the control plane is fully compromised. Spec §6.30's off-box append-only object
storage under separate credentials is the nearest existing pattern in the design.

**Options:**
A — append-only object storage in the separate account from HR-11.3, write-only credentials on the
control plane, epoch = object count or highest key. Reuses infrastructure phase 1 already builds.
B — a monotonic counter in the TURN host's local state. Second machine, but the same trust domain and
the same operator — weaker than it looks.
C — offline hardware alongside the `age` and release keys (HR-11.4, HR-12.1). Strongest, and it makes
every revoke require a physical touch, which is unusable at 5–30 devices.

**Recommendation:** A. It is the only option where "cannot be lowered" is enforced by something other
than the compromised machine's own good behaviour, and phase 1 is already standing up that bucket.
Note the epoch must be checked at startup **and** the alert path tested — spec phase 1's exit
criterion requires that restoring yesterday's dump makes the control plane refuse to serve.

**If unanswered I will:** stop. This blocks the first phase that writes server code.

**Resolution:** _(written by a human)_

---

## BLK-9 — WebAuthn RP ID must be fixed before any authenticator is registered            [OPEN]
**Spec phase:** **0** (HARD-RULES A-9 says 4 — see below)   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2, pre-flight
**Where:** spec §5.4, Phase 0 · HARD-RULES A-9, HR-9.1, HR-9.2
**The question:** what is the panel's registrable domain?

**What the documents say nearest to it:** HR-9.1 requires the panel on a **separate registrable
domain**, not `admin.example.com`. Every WebAuthn credential is bound to that domain as its RP ID, so
changing it later invalidates every passkey and forces the break-glass path (HR-9.2).

**Correction to Appendix A-9, which labels this "affects Phase 4":** it blocks **phase 0**. Spec phase
0 already generates the admin audit keypair in-browser and wraps it under `prf` from *two*
authenticators (HR-4.5). That registration binds both credentials to the RP ID. Get the domain wrong
and both `prf` wraps are dead, leaving only the paper recovery secret — which HR-4.5 designates the
last of three copies with no fourth anywhere.

**Options:** A — buy the second domain now and pin it. B — defer, and register the phase-0
authenticators against a throwaway RP ID with the explicit intent of re-wrapping later. B doubles the
ceremony and adds a window where the only working unwrap path is the paper secret.

**Recommendation:** A. This is a ~$12/year purchase that the spec's own §9 calls the cheapest security
control in the document, and it is the single cheapest blocker on this list to close.

**If unanswered I will:** stop. Nothing in phase 0 that touches WebAuthn may proceed. The Cargo
workspace, protobuf schema, and CI setup are unaffected and can proceed as a separate workflow phase.

**Resolution:** _(written by a human)_

---

## BLK-10 — Two documents claim conflicting authority            [OPEN]
**Spec phase:** all   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2 (Reconcile), pre-flight
**Where:** [HARD-RULES.md](../../HARD-RULES.md) line 7 · [implementation-workflow.md](../../implementation-workflow.md) §8
**The question:** when [HARD-RULES.md](../../HARD-RULES.md) and
[implementation-spec-v4.md](../../implementation-spec-v4.md) disagree on a **contract**, which wins?

**What the documents say nearest to it:** HARD-RULES line 7 — *"Where this document and any other
document disagree, this document wins."* No carve-out. implementation-workflow.md §8 — *"the design
volume wins on contracts; the implementation spec wins on sequence; the hard rules win on how code is
written."* That confines HARD-RULES to code style. But HARD-RULES is full of contract-level content:
the §1 protocol-absence list, HR-4.3's media key schedule, HR-4.1's algorithm table. The two
statements cannot both hold.

This is not hypothetical — **BLK-1 is already an instance of it.** HR-4.3 states the media key salt
differently from spec §4.4, and which document wins decides whether that is a HARD-RULES error to
correct or a spec error requiring an Amendment Proposal. Workflow §8 itself says a genuine
contradiction between two sources is a Blocker Record and not a judgment call, which is why this is
here rather than decided.

**Options:**
A — HARD-RULES wins outright, as its own line 7 says. Simplest. Makes HARD-RULES the design volume in
practice and the spec its rationale, and means HR omissions (the 15-minute idle timeout, the
`Ctrl+Alt+Shift+K` hotkey, the 2 Mbps ceiling) become gaps to fill rather than details to look up.
B — workflow §8's split stands: spec wins on contracts, HARD-RULES on code. Requires HARD-RULES line 7
be amended to say so, and makes HR-4.3 a transcription error.
C — HARD-RULES wins, **and** any HR rule that deviates from the spec must cite the deviation
explicitly at the rule. HR-4.3e and Appendix A-1 already do exactly this for the one known case.

**Recommendation:** C. It matches how the documents were actually written — HARD-RULES already flags
its own deliberate deviation and points at Appendix A — and it keeps a single normative source without
letting a silent transcription slip become law. Under C, HR-4.3 is authoritative and BLK-1 is a
resolution to pin rather than an amendment to file.

**If unanswered I will:** stop. Every gate 2 reconciliation and every Amendment Proposal depends on
knowing which document is being reconciled against.

**Resolution — RESOLVED 2026-08-17, option C, by the author.**
HARD-RULES wins including on contracts; any deliberate deviation must be cited at the rule itself.
Applied: the Rule of Interpretation now states both halves, and HR-4.3 carries its citation inline.

A second consequence was added while applying it, because the first pass exposed it: **an omission in
HARD-RULES is not a decision.** A full diff against the spec found seven values the spec had fixed and
HARD-RULES had silently dropped — which, combined with "where this document is silent, do not infer,
stop", turned settled decisions into halts. Transcribed as HR-2.10 (session indicator), HR-2.11 (kill
switch), HR-2.12 (idle timeout), HR-4.10 (media parameters), HR-8.6 (mobile-data disclosure),
HR-9.10 (enrollment limits), HR-11.7 (firewall/SSH). No functionality changed and no security was
reduced: every value came from the spec, and each addition removes a place where an implementer would
otherwise have had to guess or stop.

---

## BLK-11 — The binding language rule files do not exist, and name the wrong languages            [OPEN]
**Spec phase:** all   **Workflow phase:** —   **Raised:** 2026-08-17   **Gate:** 2 (Reconcile), pre-flight
**Where:** [implementation-workflow.md](../../implementation-workflow.md) §8, §6 (fast gate)
**The question:** what are the binding per-language rules for **Rust** and **Kotlin**, and does
gate 7 enforce anything before they exist?

**What the documents say nearest to it:** workflow §8 makes
`docs/engineering/{go,python,react}-hard-rules.md` binding at every gate, with stable IDs, MUST
blocking merge and the only escape a `WAIVER <ID>` comment plus the same line in the PR. None of the
three files exists in this repo. Worse, the set is wrong for this stack (spec §3): the project is
**Rust + Go + Kotlin** with `templ`/htmx. Python and React are not used at all, while the two most
safety-critical surfaces have no rules file — the Rust agent, which is where every `unsafe` block and
the entire crypto implementation lives, and the Kotlin client, which per §4.12 and §6.17 must defend
itself against a hostile host.

Gate 7's fast gate is partly language-agnostic (`cargo clippy -D warnings`, `cargo deny`,
`govulncheck`, `gradle lint`, the repo greps) and spec phase 0 already specifies those, so the gate is
not empty — but the MUST/SHOULD/WAIVER mechanism has nothing to reference.

**Options:**
A — write `rust-hard-rules.md`, `go-hard-rules.md`, `kotlin-hard-rules.md` with stable IDs before
phase 0. Cost: real work up front, and the Rust one is the substantial one.
B — amend workflow §8 to name only what exists, and let gate 7 run tool-enforced checks alone. Cost:
loses the waiver mechanism, which is the part that makes a rule auditable in a PR.
C — A, but minimal: start each file with the rules the spec already implies (no `unsafe` outside named
crates, no `unwrap` on a network path, no wall-clock for local expiry per HR-6.1) and grow them as
phases surface findings.

**Recommendation:** C. A rule discovered by a phase and written down immediately is worth more than a
comprehensive document written before any code exists, and the workflow's own §6 advice — "found the
same class of problem three times? stop finding it manually" — describes exactly that growth pattern.
Seed Rust and Kotlin; Go can start near-empty since the control plane is stdlib-shaped.

**If unanswered I will:** stop before the first gate 7. Note that whichever option is chosen, this
must also decide whether `python-hard-rules.md` and `react-hard-rules.md` are removed from workflow §8
by amendment — they reference languages this project does not use, and a binding reference to a
non-existent file for a non-existent language is the documentation-and-code-disagree defect in the
process documents themselves.

**Resolution:** _(written by a human)_

---

## BLK-12 — The Rekor entry body and log trust root are unpinned            [OPEN]
**Spec phase:** 0 (verification logic), 10 (auto-updater)   **Workflow phase:** 0.1
**Raised:** 2026-08-17   **Gate:** 4 (Implement)
**Where:** `crates/agent-core/src/release.rs` (`manifest_digest`, `verify_logged`) ·
`crates/agent-core/tests/rekor_inclusion.rs` · spec §6.1 check 2, HR-12.2
**The question:** two things, both externally observable:
1. What exact bytes form the Rekor **leaf** whose inclusion is proven?
2. Where does the **root hash** a proof is checked against come from, and what attests it?

**What the documents say nearest to it:** spec §6.1 says "Sigstore/Rekor inclusion proof for that
digest" and HR-12.2 repeats it. Neither pins a byte-level format. Rekor leaves are **canonicalised
entry bodies**, not bare digests — so "for that digest" underdetermines the implementation. Separately,
a Merkle inclusion proof only proves membership in a tree with a *given root*; it says nothing about
whether that root is the real log's. Sigstore's answer is a **signed checkpoint** (signed tree head)
from the log, verified against the log's public key. Nothing in the spec mentions a checkpoint or a
pinned log key, so as written an attacker who supplies both proof and root satisfies check 2 trivially.

**Options:**
A — pin the Rekor v1 `hashedrekord` entry body as the leaf, and require a **signed checkpoint**
verified against a Rekor public key compiled into the binary alongside the release key (HR-4.9's
pattern, which already pins the server identity key this way). Highest assurance; the checkpoint key
becomes another thing that must rotate through the signed release channel, like HR-4.8's admin key list.
B — verify via `cosign verify-blob --bundle`, treating cosign as the trusted implementation and shipping
it (or its verification library) with the agent. Less code of ours to get wrong; adds a large dependency
to a binary that HR-12.1's threat model wants small and auditable.
C — offline-only verification: the human signing the release checks Rekor inclusion at signing time, and
agents verify signature + version + cohort only. Honest and much simpler, but it **deletes check 2** —
the whole detectability property of T5/T16 — so it needs saying out loud rather than arriving by
omission.

**Recommendation:** A. It matches how every other trust root in this design is handled (HR-4.9 pins the
server identity key; HR-4.8 pins an epoch-stamped admin key list), and it keeps the agent's verifier
small and reviewable. Whichever is chosen, the choice must be stated in the spec, because C is a real
reduction in the security model and must not happen silently.

**If unanswered I will:** stop before Phase 10 wires an auto-updater. RFC 6962 §2.1.1 inclusion-proof
verification is implemented and tested now — that part is unambiguous and independent of the answer —
but it is verified against **synthetic** trees built by an independent reference implementation in
`tests/rekor_inclusion.rs`, not against captured Rekor proofs. Carries `TODO(BLK-12)` at the site, in
the exact form gate 7's TODO grep accepts.

**Resolution:** _(written by a human)_

---

## BLK-13 — `canonical_json` is undefined, so the audit chain cannot verify            [OPEN]
**Spec phase:** 4 (panel verifies) and 8 (host writes)   **Workflow phase:** —
**Raised:** 2026-08-17   **Gate:** 2 (Reconcile), during the HARD-RULES/spec diff
**Where:** HR-10.2, HR-10.4 · spec §4.7 · HARD-RULES Appendix A-10
**The question:** three things, all externally observable:
1. What exactly is `canonical_json` — key ordering, number formatting, unicode escaping, whitespace,
   and how absent or null fields are treated?
2. What is the **full entry schema**? The fixed shape has no field for what HR-10.7 requires.
3. Are the entry hash and the checkpoint signature computed over the **same** canonicalisation?

**What the documents say nearest to it:** HR-10.2 and spec §4.7 both specify
`hash = BLAKE2s(prev_hash || canonical_json(entry_without_hash))`. Neither defines the function. HR-10.4
then signs `{device_id, max_seq, head_hash, ts}` — another JSON object, same silence.

**Why this is not cosmetic.** The host writes the chain in Rust; the panel verifies it in browser
JavaScript (HR-10.2, spec §4.7). If the two serialise differently in *any* respect, an intact chain
fails verification, and HR-10.4 renders that as **`TRUNCATED — N entries missing`**. So the failure mode
is the tamper alarm firing on healthy data — and an alarm that cries wolf is an alarm that gets
ignored, which is precisely how HR-10.1's "nobody can silently truncate it" dies in practice. The
inverse is worse: a lenient verifier that normalises away differences may accept a *forged* entry.

Separately, HR-10.7 requires `session_end` to record duration, bytes, and reason, and `session_start` to
record transport. The schema `{seq, ts, event, client_key_fp, client_ip, capabilities, prev_hash, hash}`
has nowhere to put them. Adding a field changes the hash input, so the shape must be pinned **before**
Phase 8 writes the first entry — a chain cannot be migrated after the fact without breaking every hash
in it.

**Options:**
A — adopt **RFC 8785 (JCS, JSON Canonicalization Scheme)** and cite it in HR-10.2. An existing
standard with implementations in both Rust and JavaScript, so the two ends agree by construction rather
than by careful reading. Add an event-specific `detail` object to the schema, with a closed set of keys
per event type.
B — abandon JSON for hashing: hash a **length-prefixed binary encoding** of the fields in a fixed
declared order, and keep JSON only for display. Removes canonicalisation as a category of bug entirely
— the same reasoning that makes BLK-3's recommendation length-prefix its HMAC input, and that made the
release verifier sign bytes-as-received rather than a re-serialised struct.
C — define our own canonical JSON in HARD-RULES. Full control; also a new cryptographic primitive
written by us, in the one component whose whole job is being trustworthy.

**Recommendation:** **B for the hash, A for the wire.** Hash a length-prefixed binary encoding, because
the audit chain is the one place in this design where "nobody can forge it" and "nobody can silently
truncate it" must both hold, and canonicalisation ambiguity attacks exactly that pair. Keep RFC 8785 for
anything genuinely JSON-shaped that must be read by a browser. Whichever is chosen, pin the complete
entry schema in the same decision — including the `detail` fields HR-10.7 already demands.

**If unanswered I will:** stop before implementing any audit entry, host-side or panel-side. Nothing in
phase 0.1 touches this, so no existing code is affected. Note that HR-12.2's release verification
deliberately avoided this whole class of problem by verifying signatures over bytes as received; the
audit chain has no equivalent escape, because the hash is computed over a structure rather than received
as one.

**Resolution:** _(written by a human)_
