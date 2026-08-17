# Amendment Proposals — module `tether`

A spec is a living document and will sometimes be wrong. But **an agent that can amend its own
specification can make any inconvenient requirement disappear, and in the log that is
indistinguishable from correct work** ([implementation-workflow.md §4.2](../../implementation-workflow.md)).

So the rule is absolute: **the agent proposes and halts. It never applies its own amendment.**

- Approval is explicit and comes from a person, written into the **Decision** field.
- The approval is recorded in the commit that applies the amendment.
- An amendment touches **this phase's spec section only**. Amending another phase's section is refused
  outright regardless of how obviously right it seems — that phase is not in motion and its context is
  not loaded.
- The phase does not proceed until the Decision field is filled in.

The workflow does not name a file for these records. This one is chosen as the parallel to
[BLOCKERS.md](BLOCKERS.md) — a mechanical decision under workflow §3.4.

**A note on what belongs here versus in BLOCKERS.md.** An amendment is for when the spec and the repo
*disagree* and the spec is wrong. A blocker is for when the spec is *silent or ambiguous* and there is
nothing to correct yet. Reaching for an amendment when the real problem is silence is how a gap
becomes a decision nobody made — file the blocker instead.

**Current state: none proposed.** Nothing has been built, so nothing can yet diverge from the spec.

Note that four of the eleven entries in [BLOCKERS.md](BLOCKERS.md) may become amendments once
resolved, since resolving them requires correcting a document rather than only answering a question:
**BLK-1** (spec §4.4's key derivation input), **BLK-9** (HARD-RULES A-9's phase attribution),
**BLK-10** (HARD-RULES line 7 or workflow §8, whichever gives way), and **BLK-11** (workflow §8's
language list). Those corrections are a human's to approve here; an agent may only propose them.

---

## Format

```markdown
## AMD-<n> — <one-line title>            [PROPOSED | APPROVED | REJECTED]
**Spec phase:** <n>   **Workflow phase:** <n>.<n>   (this phase's section only — never another's)
**Raised:** <date>   **Gate:** <which gate surfaced it>
**The spec says:** verbatim, with § reference.
**The repo shows:** verbatim, with file:line.
**Why they diverge:** …
**Minimal amendment:** the smallest change that makes them agree.
**Downstream effects:** what else this touches, or "none".

**Decision:** _(written by a human; the phase does not proceed until this is filled in)_
```

---

## Log

## AMD-1 — §4.4 derives media keys from a value that is not secret            [PROPOSED]
**Spec phase:** 5   **Workflow phase:** —   **Raised:** 2026-08-17
**Gate:** 2 (Reconcile), during the HARD-RULES/spec diff

**The spec says** (implementation-spec-v4.md §4.4, line 241, verbatim):

```
base       = HKDF-Extract(salt = noise_handshake_hash, ikm = "tether-media-v1")
```

**The repo shows:** no implementation — Phase 5 has not run. `crates/proto` deliberately omits the
media frame header pending BLK-2, so nothing has been built on the wrong construction yet. This
amendment is being raised *before* the code exists, which is the cheapest possible moment.

**Why they diverge:** in the Noise Protocol specification the handshake hash `h` is explicitly **not
secret**. It is computed from the protocol name, the static public keys, and the transmitted
ciphertexts — every one of which a passive relay observes. A relay that records a session can therefore
recompute `h`, re-derive `base`, and expand `key_h2c` / `key_c2h` for itself.

That defeats the property §4.4's own diagram asserts ("relay CANNOT decrypt"), and with it T1
(malicious control plane), T2 (network MITM), and the Phase 5 exit criterion that `tcpdump` on the relay
recovers no decodable frame. It is not a hardening gap; it is the whole end-to-end confidentiality claim.

HARD-RULES already deviates here and flags it (HR-4.3, HR-4.3e, Appendix A-1), and under the BLK-10
resolution HR-4.3 is authoritative — so **no implementation is at risk today.** This amendment exists so
that the spec stops saying something false, rather than relying on every future reader noticing the
footnote.

**Minimal amendment:** in §4.4, replace `salt = noise_handshake_hash` with secret Noise output — the
`CipherState` keys from `Split()`, or a proper Noise exporter over the chaining key `ck` — and add one
sentence stating that `h` is not secret and must never be used as key material. **Do not touch §4.3**:
using `h` for the SAS is correct there and must stay, because the SAS needs a value both ends compute
and an attacker cannot predict, not a secret one.

**Downstream effects:** none in code. Documentation only: §4.4 and the §6.21 resolution text, which
describes the schedule as pinned when its most important input is wrong. BLK-1 still has to choose
between `Split()` output and a `ck` exporter — this amendment does not pre-empt that, it only removes
the incorrect option.

**Note on scope.** Workflow §4.2 restricts an amendment to *this phase's* spec section, and §4.4 is
Phase 5's. Raised anyway rather than deferred, because the rule exists to stop an agent quietly editing
requirements it finds inconvenient, and this is the opposite case: a requirement that is inconvenient to
leave alone. If the scope rule is to be honoured strictly, the correct disposition is to hold this until
Phase 5 opens — the deviation is already documented at HR-4.3, so nothing is unsafe in the meantime.

**Decision:** _(written by a human; the phase does not proceed until this is filled in)_

---

## AMD-2 — §4.7 specifies `canonical_json`, which is never defined            [PROPOSED]
**Spec phase:** 4 (panel verifies the chain) and 8 (host writes it)   **Workflow phase:** —
**Raised:** 2026-08-17   **Gate:** 2 (Reconcile)

**The spec says** (implementation-spec-v4.md §4.7, verbatim):

> Entry: `{seq, ts, event, client_key_fp, client_ip, capabilities, prev_hash, hash}` with
> `hash = BLAKE2s(prev_hash || canonical_json(entry_without_hash))`.

**The repo shows:** no implementation — the audit chain is Phase 8. Nothing is built on it yet.

**Why they diverge:** `canonical_json` is not defined anywhere in the spec, and JSON has no canonical
form. Key ordering, whitespace, number formatting (`42` vs `42.0` vs `4.2e1`), and unicode escaping are
each left open, and each produces a different hash for the same logical entry. The host writes the chain
in Rust; the panel verifies it in browser JavaScript. Any disagreement makes an **intact** chain fail
verification, which HR-10.4 renders as `TRUNCATED — N entries missing` — the tamper alarm firing on
healthy data, which is how an alarm comes to be ignored, and therefore how HR-10.1's "nobody can silently
truncate it" fails in practice rather than in theory. A verifier made lenient to quiet that noise would
accept a *forged* entry instead.

Separately, the entry schema as given has **no field** for what §5.3 requires: `session_end`'s duration,
bytes, and reason, or `session_start`'s transport.

**Minimal amendment:** in §4.7, replace the `hash = BLAKE2s(prev_hash || canonical_json(...))` line with
the length-prefixed binary encoding now pinned at **HR-10.2**, and add `detail` to the stored entry
schema. Keep `audit.jsonl` as JSON for display — the change is only to what gets *hashed*. Add one
sentence stating that no JSON serialiser may appear in a hash path (HR-10.2a).

**Downstream effects:** none in code — Phase 8 has not run, so there is no chain to migrate. Documentation
only: §4.7, and §6.7's resolution text, which describes truncation detection as closed while its hash
input is undefined. Note that a chain **cannot** be migrated afterwards without breaking every hash in
it, which is why this is worth settling before Phase 4 rather than during Phase 8.

**Note on scope.** As with AMD-1, workflow §4.2 restricts an amendment to this phase's section and §4.7
belongs to Phases 4 and 8. Raised anyway: the deviation is recorded at HR-10.2 and under the BLK-10
resolution HARD-RULES is authoritative, so nothing is unsafe in the meantime. If the scope rule is
honoured strictly, hold this until Phase 4 opens.

**Decision:** _(written by a human; the phase does not proceed until this is filled in)_
