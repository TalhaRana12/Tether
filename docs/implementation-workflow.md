# The implementation workflow — how a spec becomes code

**Status: v1.0.** Binding engineering practice for any module built from an implementation spec in
`docs/impl-specs/`. Written to be generic: it names no module, no phase count, and no product.
The `impl-phase-*` skills in `.claude/skills/` execute it.

---

## 1. Why this exists

Software built by agents fails in ways human-built software does not, and the failures look like
success. An agent writing code and tests together will unconsciously write tests that mirror its
implementation — bugs included — and then the tests certify the mistake. An agent facing a failing
test will edit the test. An agent asked for a feature will write the smallest stub that makes the
assertion pass and call it done. An agent that hits an ambiguity will resolve it from general
knowledge of how such systems are *usually* built, which is exactly how a designed system quietly
becomes an undesigned one.

None of those are laziness; they are what optimising for "make it green" produces. So this workflow
does not ask anyone to be careful. It sequences the work so that carelessness cannot pass, and so
that the things which must be seen by a human physically stop the build until they are.

**One phase, one session.** A phase is small enough to hold in one working context. If a session
must end mid-phase, the agent writes a handoff prompt for the next one (`impl-phase-status`).
Working state lives in context; *completed* state lives in git and the phase registry.

---

## 2. The gates

Eight gates, in order, per phase. Each has a skill. A gate that fails does not get worked around —
it halts, and the halt is recorded where a human will see it.

| # | Gate | Skill | Passes only when |
|---|---|---|---|
| 0 | **Status** | `impl-phase-status` | — (read-only; tells you where you are) |
| 1 | **Order** | `impl-phase-validate` | Every prerequisite phase is committed with its proof passed, and no blocker is open anywhere in the module |
| 2 | **Reconcile** | `impl-phase-validate` | This phase's spec matches repo reality, or an Amendment Proposal is approved by a human |
| 3 | **Red** | `impl-phase-generate-tdd` | Every spec'd test exists, and every one fails *for the right reason* |
| 4 | **Implement** | `impl-phase-implement` | Code completes the specification. Tests are frozen |
| 5 | **Green + aligned** | `impl-phase-implement` | All tests green **and** implementation matches the spec — both, not either |
| 6 | **Run** | `impl-phase-test-and-scan` | The environment comes up and the thing actually works — unit and integration |
| 7 | **Scan** | `impl-phase-test-and-scan` | Fast-gate static analysis, vulnerability scan and coverage thresholds are clean |
| 8 | **Commit** | `impl-phase-commit` | Atomic commits exist and the phase registry is updated |

`impl-final-audit` runs once, after the last phase, for the deep gate.

---

## 3. The four rules that make it work

Everything else is mechanics. These four are the workflow.

### 3.1 Tests come from the spec, before the code, and they must be red

Tests are written from the specification, never from the implementation — because the implementation
does not exist yet. That is the point: a test written after the code tends to encode what the code
*does*; a test written from the spec encodes what the code *must do*.

**Red is not enough — it must be red for the right reason.** A test that fails because of a compile
error, a missing import, or a typo in the test proves nothing; it would have failed against perfect
code too. Every test must fail with an **assertion failure** or an explicit *not implemented*
error. A collection error, an import error or a syntax error fails the gate.

**And the tests must cover the spec.** Three trivial tests going red, then green, is a phase that
looks complete and is not. Every test the spec names must exist, by name. This is checked
mechanically, not by judgment.

### 3.2 Tests are frozen during implementation

Once gate 3 passes, **the tests do not change** until the phase is committed. Not to fix a failure,
not to adjust an assertion, not to "clarify intent."

If a test is wrong, that is a defect in gate 3, and the fix is to go *back* to gate 3 — deliberately,
visibly, with the reason recorded — not to edit it in place while implementing. The difference
matters: one is a corrected specification of intent, the other is moving the goalposts, and in a diff
they look identical.

### 3.3 Implement the specification, not the assertions

Green tests are a floor, not a target. The completion check at gate 5 is **spec alignment first,
tests green second** — in that order, deliberately. A phase whose tests pass but whose implementation
omits half of what the spec describes is not complete; it is a phase that will be discovered as
incomplete much later, by someone else.

Running tests while implementing is fine and normal. Declaring done because they went green is not.
Before declaring a phase complete, re-read the spec section and check it clause by clause.

### 3.4 Nothing ambiguous proceeds unseen

When the spec does not answer something, there are exactly two possibilities and they are handled
differently:

- **It is mechanical** — a variable name, a loop shape, which stdlib helper. *Decide it.* Follow the
  hard rules. No escalation.
- **It is observable from outside your process** — a stored shape, a wire shape, a security property,
  a dependency, another team's code. **Halt.** Write a Blocker Record. It stays open until a human
  resolves it, and no phase advances while it is open.

The test is one question: *is this observable from outside my process?* When uncertain, treat it as
observable. The cost of an unnecessary escalation is a message; the cost of a wrong silent decision
is found in production.

---

## 4. Halts, blockers, and amendments

### 4.1 The Blocker Record

Every halt writes an entry to `docs/impl-specs/<module>/BLOCKERS.md`, in the repo, versioned, and
visible in any pull request. Fixed shape:

```markdown
## BLK-<n> — <one-line title>            [OPEN | RESOLVED]
**Phase:** <n>   **Raised:** <date>   **Gate:** <which gate halted>
**Where:** file / spec section
**The question:** the exact thing that has no answer.
**What the documents say nearest to it:** cited by section. (Half of blockers dissolve here.)
**Options:** A — … (cost, which principle it serves) · B — …
**Recommendation:** … 
**If unanswered I will:** stop. (A provisional stub is allowed ONLY in a file this phase's manifest
does not name, must fail loudly, and must carry `TODO(BLK-<n>)` — which gate 7's TODO grep accepts
only in that exact form. It never counts as progress on this phase.)

**Resolution:** _(written by a human)_
```

**Enforcement, not etiquette — and the scope is deliberately wide.** **Any `OPEN` blocker anywhere
in the module halts every phase**, not only the one that raised it. `impl-phase-status` reports open
blockers first; `impl-phase-validate` refuses to start or advance any phase while one exists. The
wide scope is the point: a blocker raised at phase 3 about a stored shape is a question every later
phase builds on top of, so letting phase 7 proceed only buries it deeper. An unanswered question
stops the build — that is the mechanism behind "nothing goes without being seen."

### 4.2 The Amendment Proposal

A spec is a living document and will sometimes be wrong. But an agent that can amend its own
specification can make any inconvenient requirement disappear, and in the log that is
indistinguishable from correct work.

So: the agent **proposes and halts**. It never applies its own amendment.

```markdown
## AMD-<n> — <one-line title>            [PROPOSED | APPROVED | REJECTED]
**Phase:** <n>  (amendments touch THIS phase's section only — never another's)
**The spec says:** verbatim.
**The repo shows:** verbatim.
**Why they diverge:** …
**Minimal amendment:** the smallest change that makes them agree.
**Downstream effects:** what else this touches, or "none".

**Decision:** _(written by a human; the phase does not proceed until this is filled in)_
```

Approval is explicit and from a person. The approval is recorded in the commit that applies it.
Amending another phase's section is refused outright, regardless of how obviously right it seems —
that phase is not in motion and its context is not loaded.

---

## 4a. Every gate leaves a trace

A gate that reports only to the chat cannot be verified by the next gate. After a context compaction
or a session break, an agent asked "did gate 5 pass?" has nothing to consult but its own memory —
which is precisely what this workflow exists not to trust. So **every gate appends its output block
to `docs/impl-specs/<module>/gates/phase-<n>.md`**, and later gates read it rather than remembering.

That file is the phase's proof-of-work. `impl-phase-commit` requires the gate 5 and gate 7 blocks to
be present and passing before it will commit, and commits the file along with the phase.

**The freeze baseline.** Rule 3.2 (tests frozen) needs something to compare against, and a `git diff`
cannot provide it: in a greenfield phase the test files are *untracked*, so a diff shows nothing and
prints a pass no matter what was edited. Instead, at the end of gate 3 the TDD skill writes
`gates/phase-<n>-tests.sha256` — one hash per test file. Gates 5 and 8 re-hash and compare. A changed
hash is a broken freeze, and that is a mechanical fact rather than a recollection.

## 5. Test tiers — keep the environment light

An agent will happily start a full container stack to run a unit test. That makes the suite slow,
which makes it get skipped, which removes the safety net. Three tiers, and every test belongs to
exactly one:

| Tier | Needs | Rule |
|---|---|---|
| **Unit** | **Nothing.** No database, no network, no containers | Pure logic with injected fakes. If a unit test needs a container, either the test is misfiled or the code has a seam missing — both are findings |
| **Integration** | **Exactly one** real dependency | A real database (ephemeral container or one compose service), or a real HTTP server — not both, not the whole stack |
| **Acceptance** | Everything | The full environment, once, at the end. This is the only tier allowed to be slow |

The design's determinism seams — an injected clock, id generator and randomness source — exist
precisely so that tier 1 stays at tier 1. Use them.

---

## 6. The two scan tiers

A gate that is too slow gets disabled, and a disabled gate is worse than no gate because everyone
believes it is running.

**Fast gate — every phase, seconds:** formatting and vet (`gofmt`/`go vet`/`staticcheck`, `ruff`,
`eslint`+`prettier`), dependency vulnerabilities (`govulncheck`, `pip-audit`, `npm audit`), the repo
grep gates (string-built SQL, secrets in source, forbidden imports, mutable globals), and coverage
thresholds.

**Deep gate — before a pull request, minutes:** full SAST (semgrep or CodeQL), the mutation check on
security tests, and the complete acceptance run.

**Coverage thresholds:** 80% on the logic that matters — the domain and the use cases. **No
threshold on adapters, handlers or wiring**, where a coverage number measures how much boilerplate
you wrapped in a test rather than whether anything is correct. A threshold applied where it is
meaningless teaches people to write meaningless tests.

**The mutation check** (deep gate, security tests only): delete the protection, confirm the test
goes red, restore it. It is the only real evidence a test has teeth. Too expensive for every test;
essential for the ones guarding an attack.

---

## 7. The phase registry

`docs/impl-specs/<module>/PHASE-REGISTRY.md` is the module's build record: one row per phase, filled
in by `impl-phase-commit` when that phase completes, showing what was delivered, which proof passed,
the commits, and any amendments or blockers raised along the way.

**Completing the registry is a precondition for opening a pull request.** It is how a reviewer sees,
in one place, that the phases ran in order, what was decided along the way, and what is still open —
without reconstructing it from a commit log.

---

## 8. What is always in scope, every phase

These are loaded and honored at every gate, not consulted when someone remembers:

- **The language hard rules** (`docs/engineering/{rust,go,kotlin}-hard-rules.md`) — binding, with
  stable IDs. MUST blocks merge; SHOULD needs a one-line justification; the only way to break one is
  a `WAIVER <ID>: <reason>` comment at the site plus the same line in the pull request.

  *Amended 2026-08-17 per the BLK-11 resolution.* This previously read `{go,python,react}`, which bound
  the project to two languages it does not use while omitting the two carrying the most risk — Rust,
  which holds every `unsafe` block, the crypto, and both privileged binaries, and Kotlin, which per
  §4.12 of the design volume must defend itself against a hostile host. All three files now exist,
  seeded rather than comprehensive: a rule is added when a phase finds the same problem a third time
  (§6), not in advance.
- **The module's design intent** (`docs/impl-specs/<module>/DESIGN-INTENT.md`) — the reasoning behind
  the design, so an uncovered gap is resolved the way this system is designed rather than the way
  such systems are usually built.
- **The design volume** — authoritative for every contract. When code and volume disagree, that is a
  finding to surface, never to resolve silently.

**Order of authority when sources differ:** the design volume wins on contracts; the implementation
spec wins on sequence; the hard rules win on how code is written. A genuine contradiction between
any two is a Blocker Record, not a judgment call.
