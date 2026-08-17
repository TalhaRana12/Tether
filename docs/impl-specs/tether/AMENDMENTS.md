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

_(empty)_
