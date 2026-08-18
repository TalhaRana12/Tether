# Phase registry — module `tether`

The module's build record. One row per **workflow** phase, filled in by `impl-phase-commit` when that
phase completes ([implementation-workflow.md §7](../../implementation-workflow.md)).

**Completing this registry is a precondition for opening a pull request.** It is how a reviewer sees,
in one place, that the phases ran in order, what was decided along the way, and what is still open —
without reconstructing it from a commit log.

**Current state: workflow phase 0.1 complete on branch `phase-0-foundations`, and all eight gates pass
on a clean re-run** — no override, no waiver, no open blocker. See the gate re-run section at the end of
[gates/phase-0.1.md](gates/phase-0.1.md).

**Spec phase 0 is still NOT complete.** Three exit criteria are unmet and none is an engineering
decision: the YubiKey signing ceremony (~$75 of hardware), the three-way audit-key wrap (2× WebAuthn
authenticators plus the panel domain), and byte-identical builds from a *different* source path
(`--remap-path-prefix` procedure documented but not exercised). HR-15.1 is **not** cleared for spec
phase 1.

[BLOCKERS.md](BLOCKERS.md): **13 raised, 13 resolved, 0 open.** Twelve resolved by author decision on
2026-08-17; BLK-9 descoped with its constraint retained as a hard precondition on Phase 0.2 and Phase 4.

[AMENDMENTS.md](AMENDMENTS.md): **2 proposed, 0 decided.** AMD-1 (spec §4.4) and AMD-2 (spec §4.7). Under
workflow §4.2 these block **Phase 5** and **Phase 4** respectively, not phase 0.1 — both correct
behaviour is already recorded in HARD-RULES, so nothing is unsafe in the meantime.

---

## Spec phases — the outer plan

From [implementation-spec-v4.md §7](../../implementation-spec-v4.md), effort from §10. Each carries a
**hard exit criterion**, and HR-15.1 forbids starting the next phase until it is met — the criterion
is a test that runs, not a judgement.

| Spec phase | Title | Effort | Workflow phases | Status | Exit criterion met |
|---|---|---|---|---|---|
| 0 | Foundations | 2 wk | 0.1, 0.2, 0.3 done | **NEARLY COMPLETE** | **4 of 6** — rest needs a push, a browser session, and Phase 1 |
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
| 0.1 | 0 | Workspace (8 crates) · wire protocol v1 with HR-1.1 absences enforced · HR-1.6 version floor · HR-12.2/12.3 release + rollback verification · reproducibility fix · THREAT-MODEL, SECURITY-REVIEW | [phase-0.1.md](gates/phase-0.1.md) — 43 tests | see `git log phase-0-foundations` | **BLK-12**, **BLK-13** | none | 2026-08-17 |
| 0.3 | 0 | TPM-backed signing ceremony · WebAuthn prf wraps (all 3 paths) · Go module · Gradle project + `gradle lint` clean · CI workflow · Android manifest gate | [phase-0.3.md](gates/phase-0.3.md) — 67 tests, 3 mutations | see `git log` | none | none | 2026-08-18 |
| 0.2 | 0 | In-browser audit keypair · HR-4.5 recovery-secret wrap (1 of 3) · 256-word recovery scheme · Playwright suite + CSP-enforcing test server | [phase-0.2.md](gates/phase-0.2.md) — 10 tests, 4 mutations | see `git log phase-0-foundations` | none | none | 2026-08-17 |

**Totals: 67 tests — 46 Rust, 7 Go, 14 Playwright. 7 mutation tests run; 6 confirmed a guard and ONE exposed a guard with no teeth (phase 0.3, gate 3).**

**Phase 0.3 — blocked on purchases, not decisions.** The remainder of spec phase 0:

| Item | Blocked on |
|---|---|
| YubiKey signing ceremony, Sigstore end-to-end on a dummy artifact | YubiKey with touch policy `always`, ~$50 |
| Audit-key wraps 2 and 3 (authenticator A and B) | 2× WebAuthn authenticators, ~$50, **and** the panel domain first — BLK-9's retained precondition freezes the RP ID at first registration |
| Public half committed to the epoch-stamped admin key list | follows from the above |
| Control-plane SPKI + server identity pin | a deployed control plane (spec Phase 1) |
| Go module (`control`, `admin`) and Gradle project (`android`) | not attempted; Phase 1 and Phase 6 territory |
| CI workflow file, `gradle lint`, Android manifest lint gate | a remote and the Gradle project |

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
