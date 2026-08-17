# Gate trace — phase `<spec>.<step>` — `<title>`

Copy this file to `gates/phase-<spec>.<step>.md` at gate 0 and **append** each block as its gate
runs. Never rewrite an earlier block; a gate that ran and failed stays in the file above the retry.

Why this file exists ([implementation-workflow.md §4a](../../../implementation-workflow.md)): a gate
that reports only to the chat cannot be verified by the next gate. After a context compaction an
agent asked "did gate 5 pass?" has nothing but its own memory, which is precisely what this workflow
exists not to trust. Later gates **read this file** rather than remembering.

`impl-phase-commit` refuses to commit unless the **gate 5** and **gate 7** blocks are present and
passing. Commit this file with the phase.

Every block ends in `Verdict: PASS | HALT`. `HALT` writes a Blocker Record and stops — a halt is
never worked around (workflow §2).

---

## Gate 0 — Status  ·  `impl-phase-status`  ·  read-only

```
Run:                    <date>
Open blockers (module): <n>   → <BLK ids, or "none">
Open amendments:        <n>   → <AMD ids, or "none">
Last committed phase:   <n>   → <commit sha>
This phase:             <spec>.<step> — <title>
Spec section:           <§ref>
Prerequisite phases:    <list>
Decomposition:          this workflow phase covers <which clauses of the spec phase>
```

Reports open blockers **first**. Read-only: it has no verdict and cannot halt.

## Gate 1 — Order  ·  `impl-phase-validate`

```
Prerequisite phases committed with proof passed:   YES | NO  → <evidence: registry rows + shas>
Open blockers anywhere in the module:              <n>
Open amendments touching this phase:               <n>
Verdict: PASS | HALT — <reason>
```

**HALT if** any prerequisite is uncommitted or its proof did not pass, **or if any blocker is open
anywhere in the module** — not only one raised by this phase. The wide scope is deliberate (workflow
§4.1): a blocker raised at phase 3 about a stored shape is a question every later phase builds on,
so letting phase 7 proceed only buries it deeper.

## Gate 2 — Reconcile  ·  `impl-phase-validate`

```
Spec clauses in scope:  <enumerate, by § and clause>
Repo reality checked:   <files / interfaces / stored shapes inspected>

Divergences found:
  1. spec says <verbatim> | repo shows <verbatim> | → AMD-<n> PROPOSED | → no divergence
  ...

Hard rules in scope:    <HR ids this phase must satisfy>
Verdict: PASS | HALT — <reason>
```

**HALT if** any divergence lacks an **APPROVED** Amendment Proposal. The agent never applies its own
amendment (workflow §4.2), and an amendment may touch **this phase's spec section only**.

## Gate 3 — Red  ·  `impl-phase-generate-tdd`

Tests are written **from the specification**, never from the implementation — which does not exist
yet. That is the point.

```
Spec-named tests — every one the spec names must exist, by name:
  | spec ref | test name | file | runs? | fails? | failure kind          |
  |----------|-----------|------|-------|--------|-----------------------|
  | §<x>     | <name>    | <f>  | yes   | yes    | assertion | unimplemented |

Coverage of spec clauses:   <n>/<n> clauses have at least one test
Failure kinds present:      assertion=<n>  unimplemented=<n>  collection=<n>  import=<n>  syntax=<n>
Tier assignment:            unit=<n>  integration=<n>  acceptance=<n>
Manual exit criteria:       <spec exit criteria that cannot be automated — see note below>

Freeze baseline written:    gates/phase-<spec>.<step>-tests.sha256   (<n> files hashed)
Verdict: PASS | HALT — <reason>
```

**HALT if** any test fails for the wrong reason. A collection error, import error, or syntax error
fails this gate: that test would have failed against perfect code too, so it proves nothing. Only an
**assertion failure** or an explicit *not implemented* error counts as red.

**HALT if** any spec-named test is missing. Three trivial tests going red then green is a phase that
looks complete and is not. Checked mechanically, not by judgment.

**Tier discipline** (workflow §5): unit needs *nothing* — no database, no network, no containers. A
unit test that needs a container means either the test is misfiled or the code is missing a seam;
both are findings. Use the injected clock, id generator, and randomness source — they exist so tier 1
stays tier 1, and HR-6.1's monotonic-clock rule needs them to be testable at all.

**Manual exit criteria.** Several spec exit criteria are irreducibly human-in-the-loop — a human
comparing six SAS digits *is* the control (HR-3.1 step 7), and "take the session over via RDP" or
"72 hours continuous" cannot be a red assertion. List them in the block above with an owner, and
record the observed result in the gate 6 block. They are not exempt from proof; they are exempt from
automation.

## Gate 4 — Implement  ·  `impl-phase-implement`

```
Manifest — files this phase may create or modify:
  <path>   <new | modified>
  ...
Files touched outside the manifest:   <list, or "none">   → any entry is a finding
Freeze check:                         hashes match gate 3 baseline?  YES | NO
Hard rules cited at the site:          <HR ids → file:line>
Waivers:                               <WAIVER <ID>: <reason> → file:line, or "none">
Verdict: PASS | HALT — <reason>
```

**Tests are frozen from the moment gate 3 passed** (workflow §3.2). Not to fix a failure, not to
adjust an assertion, not to clarify intent. If a test is wrong that is a defect in gate 3, and the
fix is to go *back* to gate 3 — visibly, with the reason recorded in this file — not to edit it in
place. In a diff, a corrected specification of intent and a moved goalpost look identical; the
difference is which gate you were standing in.

A provisional stub is allowed **only** under the conditions in workflow §4.1: in a file this
manifest does not name, failing loudly, carrying `TODO(BLK-<n>)`. It never counts as progress.

## Gate 5 — Green + aligned  ·  `impl-phase-implement`

Spec alignment **first**, tests green **second** — in that order, deliberately.

```
Spec alignment — clause by clause, re-read from the spec:
  | spec ref | clause (verbatim or close) | implemented at | complete? |
  |----------|---------------------------|----------------|-----------|

Clauses complete:       <n>/<n>
Test run:               <command>  → <n> passed, <n> failed, <n> skipped
Full output:            <paste or path>
Freeze check:           hashes match gate 3 baseline?  YES | NO
Verdict: PASS | HALT — <reason>
```

**HALT if** any spec clause in scope is unimplemented, **even with every test green.** Green tests
are a floor, not a target. A phase whose tests pass but whose implementation omits half of what the
spec describes is not complete; it is a phase that gets discovered as incomplete much later, by
someone else.

**HALT if** any freeze hash changed. That is a broken freeze, and it is a mechanical fact rather than
a recollection.

For any control this phase adds, answer HR-15.6's three questions out loud and record the answers:

```
Control: <name>
  1. Does it exist?                                  <answer + evidence>
  2. Does it function?                               <answer + evidence>
  3. Does it authorize, or does it merely inform?    <answer>
  Watched it fail?                                   <how, or NO → it is untested>
```

Question 3 is the one that is easy to skip and expensive to get wrong — it is the question v3's
entire review failed to ask (spec §6.25, §6.37).

## Gate 6 — Run  ·  `impl-phase-test-and-scan`

The environment comes up and the thing actually works.

```
Environment:            <command>  → up?  YES | NO
Unit tier:              <command>  → <result>
Integration tier:       <command>  → <result>        (exactly ONE real dependency)
Manual exit criteria from gate 3:
  | criterion | spec ref | observed result | who ran it | date |
Verdict: PASS | HALT — <reason>
```

## Gate 7 — Scan  ·  `impl-phase-test-and-scan`

Fast gate only — seconds, every phase. A gate too slow gets disabled, and a disabled gate is worse
than no gate because everyone believes it is running.

```
Format / vet:           <cargo fmt --check · clippy -D warnings · go vet · staticcheck · gradle lint>
Dependency vulns:       <cargo deny check · govulncheck · npm audit>   → fail on any advisory
Repo grep gates:        string-built SQL · secrets in source · forbidden imports · mutable globals
TODO grep:              only TODO(BLK-<n>) accepted, in that exact form  → <n> found
Coverage:               domain <n>%  use-cases <n>%   (threshold 80%)
                        adapters / handlers / wiring: NO THRESHOLD — deliberately
Verdict: PASS | HALT — <reason>
```

No coverage threshold on adapters, handlers, or wiring: there a coverage number measures how much
boilerplate you wrapped in a test rather than whether anything is correct, and a threshold applied
where it is meaningless teaches people to write meaningless tests.

**Deep gate — before a pull request, minutes, not per phase:** full SAST (semgrep or CodeQL), the
complete acceptance run, and the **mutation check on security tests** — delete the protection,
confirm the test goes red, restore it. That is the only real evidence a test has teeth, and it is the
mechanical form of HR-15.6's "build a demo of each control failing."

## Gate 8 — Commit  ·  `impl-phase-commit`

```
Gate 5 block present and passing:   YES | NO
Gate 7 block present and passing:   YES | NO
Freeze re-verified:                 YES | NO
Commits (atomic):
  <sha>  <subject>   → HR ids cited: <list>
Registry row updated:               YES | NO   → PHASE-REGISTRY.md
Blockers raised this phase:         <BLK ids, or "none">
Amendments applied this phase:      <AMD ids + approval recorded in commit, or "none">
This gate file committed with the phase:   YES | NO
Verdict: PASS | HALT — <reason>
```

**HALT if** gate 5 or gate 7 is absent or not passing. This is the check that makes the whole file
load-bearing rather than decorative.

Commit messages and PR descriptions cite the `HR-<n>.<n>` ID behind any decision a hard rule drove
([HARD-RULES.md](../../../HARD-RULES.md) preamble). Before opening a PR, run Appendix B — the
ten-question pre-merge self-check — against the diff.
