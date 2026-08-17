# Phase registry — module `tether`

The module's build record. One row per **workflow** phase, filled in by `impl-phase-commit` when that
phase completes ([implementation-workflow.md §7](../../implementation-workflow.md)).

**Completing this registry is a precondition for opening a pull request.** It is how a reviewer sees,
in one place, that the phases ran in order, what was decided along the way, and what is still open —
without reconstructing it from a commit log.

**Current state: nothing started.** No code exists in the repo, and
[BLOCKERS.md](BLOCKERS.md) has 11 open entries, so under workflow §4.1 no phase may start.

---

## Spec phases — the outer plan

From [implementation-spec-v4.md §7](../../implementation-spec-v4.md), effort from §10. Each carries a
**hard exit criterion**, and HR-15.1 forbids starting the next phase until it is met — the criterion
is a test that runs, not a judgement.

| Spec phase | Title | Effort | Workflow phases | Status | Exit criterion met |
|---|---|---|---|---|---|
| 0 | Foundations | 2 wk | not decomposed | NOT STARTED | — |
| 1 | Control plane | 3 wk | not decomposed | NOT STARTED | — |
| 2 | Host agent skeleton | 3–3.5 wk | not decomposed | NOT STARTED | — |
| 3 | Pairing, Noise, and the SAS | 3 wk | not decomposed | NOT STARTED | — |
| 4 | Admin panel | 4 wk | not decomposed | NOT STARTED | — |
| 5 | Video pipeline | 4–6 wk | not decomposed | NOT STARTED | — |
| 6 | Android client | 3.5–4.5 wk | not decomposed | NOT STARTED | — |
| 7 | Input injection (helper-isolated) | 2.5 wk | not decomposed | NOT STARTED | — |
| 8 | Hardening — **the consent gate** | 4–5 wk | not decomposed | NOT STARTED | — |
| 9 | Convenience features | 2–3 wk | not decomposed | NOT STARTED | — |
| 10 | Distribution | 2–2.5 wk | not decomposed | NOT STARTED | — |

Ordering constraints that are not negotiable:

- **HR-15.2** — do not hand this to a second person before spec phase 8 ships. Phases 5–7 produce a
  working system in which any paired device can connect at will, because the consent gate lands in 8.
  Fine while you are the only user; unacceptable the moment anyone else installs it, *including someone
  who insists they do not mind*.
- **HR-15.4** — if schedule pressure arrives, cut spec phase 9 entirely before touching phase 8.
- **HR-15.3** — run it as a daily driver for a full month before handing it to anyone.
- **HR-15.8** — any successful adversarial test stops the project until the **protocol** is fixed. Not
  the code: the protocol.

## Workflow phases — the build record

One row per one-session slice, appended by `impl-phase-commit`. Spec phases are 2–6 weeks and must be
decomposed into these before work starts; the decomposition is recorded here as it is decided.

| # | Spec phase | Delivered | Proof (gate file) | Commits | BLK raised | AMD applied | Date |
|---|---|---|---|---|---|---|---|
| _(none yet)_ | | | | | | | |

**Proof** links the phase's `gates/phase-<n>.md`, whose gate 5 and gate 7 blocks must be present and
passing before `impl-phase-commit` will commit — see [gates/_TEMPLATE.md](gates/_TEMPLATE.md).

## Final audit

`impl-final-audit` runs **once**, after the last phase, for the deep gate: full SAST, the mutation
check on security tests, and the complete acceptance run.

It is not a substitute for the per-phase review HR-15.6 requires, and spec §6.37 is explicit about
why: an adversarial reviewer asks "can I break this mitigation?", a question that presupposes the
mitigation exists and does what its name suggests. Both spec reviews were thorough; only the second
asked whether the pieces were real. So at the end of every phase, for every control:

> 1. Does it exist?
> 2. Does it function?
> 3. Does it authorize, or does it merely inform?

And build a demo of each control failing. **A control you have never seen fail is a control you have
never seen.**

| Audit | Status | Date | Findings |
|---|---|---|---|
| `impl-final-audit` | NOT RUN | — | — |
| Spec phase 8 self-review — every row in §2, every finding in §6 and §6A | NOT RUN | — | — |
