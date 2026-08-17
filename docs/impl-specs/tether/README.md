# impl-specs / tether

The build record for module **`tether`**. Created 2026-08-17 to satisfy
[implementation-workflow.md](../../implementation-workflow.md), which requires this directory at
every gate but did not previously exist in the repo.

Nothing here contains a design decision. Every claim is cited to
[implementation-spec-v4.md](../../implementation-spec-v4.md) or [HARD-RULES.md](../../HARD-RULES.md).
Where those documents do not answer something, it is a Blocker Record — not a guess.

---

## What is in here

| File | Required by | Purpose |
|---|---|---|
| [DESIGN-INTENT.md](DESIGN-INTENT.md) | workflow §8 | The reasoning behind the design, so an uncovered gap is resolved the way *this* system is designed rather than the way such systems are usually built |
| [BLOCKERS.md](BLOCKERS.md) | workflow §4.1 | Every halt. **Any `OPEN` entry halts every phase in the module** |
| [AMENDMENTS.md](AMENDMENTS.md) | workflow §4.2 | Proposed spec corrections. The agent proposes and halts; it never applies its own |
| [PHASE-REGISTRY.md](PHASE-REGISTRY.md) | workflow §7 | One row per phase. Completing it is a precondition for opening a pull request |
| [gates/_TEMPLATE.md](gates/_TEMPLATE.md) | workflow §4a | The nine gate output blocks. Copy per phase into `gates/phase-<n>.md` |

The workflow does not name a file for Amendment Proposals. `AMENDMENTS.md` is chosen as the obvious
parallel to `BLOCKERS.md`; that is a mechanical decision under workflow §3.4.

## Where the spec lives

The workflow refers to "an implementation spec in `docs/impl-specs/`". Tether's spec is at
[docs/implementation-spec-v4.md](../../implementation-spec-v4.md) and **has not been moved** — moving
a document nobody asked to move is out of scope. Read the mapping as:

| Workflow term | This module |
|---|---|
| the design volume — authoritative for every contract | [implementation-spec-v4.md](../../implementation-spec-v4.md) |
| the implementation spec — authoritative for sequence | the same file, §7 (Phased build plan) |
| the language hard rules — authoritative for how code is written | [HARD-RULES.md](../../HARD-RULES.md), plus per-language files that **do not exist** — see BLK-11 |

That one document plays two of the three roles is why the authority-order question in **BLK-10** is
open rather than academic.

## Phase numbering

Two documents number things and mean different things by it. Resolved here as a naming convention:

| Term | Range | Source |
|---|---|---|
| **Spec phase** | 0–10 | spec §7. The unit an HR-15.1 hard exit criterion attaches to. 2–6 weeks each |
| **Workflow phase** | `<spec>.<step>` | a one-session slice of a spec phase, per workflow §1 ("one phase, one session") |
| **Gate** | 0–8 | workflow §2. Runs nine times per *workflow* phase |

So the trace file for the second slice of spec phase 3 is `gates/phase-3.2.md`, and its freeze
baseline is `gates/phase-3.2-tests.sha256`. Blocker and Amendment records carry **Spec phase** and
**Workflow phase** as separate fields so `Phase: 3` can never be read two ways.

Spec phases are not yet decomposed into workflow phases. That decomposition is the first task of
gate 0 for any phase, and the result is recorded in [PHASE-REGISTRY.md](PHASE-REGISTRY.md).

## Current state — 2026-08-17

**Module halted. 11 open blockers.** Zero phases started; zero code exists in the repo.

Nine of the eleven are [HARD-RULES.md](../../HARD-RULES.md) Appendix A verbatim — the spec author's
own list of things not to guess at. Two were raised by document reconciliation. Under workflow §4.1
an open blocker anywhere halts every phase, so **no phase may start until these are resolved**, and
that is the mechanism working as designed rather than a problem with it.

Resolve in this order — the first two gate the ones after:

1. **BLK-9** — the panel domain. Blocks spec phase **0**, not 4 as Appendix A states. Registering the
   two `prf` authenticators binds them to the RP ID; choosing the domain later invalidates both
   passkeys. It is a domain purchase, not an engineering decision.
2. **BLK-10** — which document wins on contracts. Every later reconciliation depends on the answer.
3. **BLK-11** — the per-language rule files, which gate 7 is supposed to enforce against.
4. **BLK-8** (spec phase 1), then **BLK-1** and **BLK-2** (spec phase 5), then **BLK-3** (spec phase 7).
5. **BLK-4** through **BLK-7** — real questions, none of them blocking the immediate next phase.
