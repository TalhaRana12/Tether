# Gate trace — phase 0.2 — in-browser audit keypair (recovery-secret wrap)

**Spec phase:** 0 (Foundations) · **Workflow phase:** 0.2 · **Date:** 2026-08-17
**Branch:** `phase-0-foundations`

Closes the one part of spec Phase 0's audit-keypair bullet that needs no hardware.

HR-4.5 wraps the X25519 audit key **three independent ways**: authenticator A, authenticator B,
and `HKDF(recovery_secret)` over 256 CSPRNG bits kept on paper. The first two need physical
WebAuthn authenticators. **The third does not.** Phase 0.1's gate file reported that whole exit
criterion as hardware-blocked, which was wrong — corrected here.

## Gate 0 — Status

```
Open blockers (module-wide):  0
Proposed amendments:          2   AMD-1 (spec §4.4, Phase 5), AMD-2 (spec §4.7, Phases 4/8)
Last committed phase:         0.1
This phase:                   0.2
```

## Gate 1 — Order

```
Prerequisite 0.1 committed with proof passed:   yes (gates/phase-0.1.md, re-run all pass)
Open blockers anywhere:                         0
Verdict: PASS
```

## Gate 2 — Reconcile

```
Spec clause:  "Generate the admin audit keypair in-browser, random, wrapped three ways —
               authenticator A, authenticator B, and a 256-bit paper recovery secret"
Repo reality: nothing existed. Greenfield.
Divergences:  none
Hard rules:   HR-0.3, HR-4.1, HR-4.5, HR-4.6, HR-4.7, HR-9.7
Verdict: PASS
```

## Gate 3 — Red

```
First run: 6 failed on assertions ("unexpected value empty"), 4 passed, 0 collection errors
Stub:      static/audit-keygen.js did nothing; DOM structure present, so tests fail on
           ASSERTIONS rather than on a 404 — the browser equivalent of todo!()
```

### Gate 3 was re-entered TWICE, deliberately, before implementing

Recorded rather than quietly edited: workflow §3.2 warns that a corrected specification of
intent and a moved goalpost look identical in a diff.

**Pass 2 — a real defect in the test.** The original asserted `words.length === 24`. That number
is not arbitrary: 24 words carrying 256 bits implies ~10.67 bits per word, so a 2048-word list,
so BIP-39. Embedding a BIP-39 list that cannot be verified byte-for-byte is guessing at a shape
(WORKING-AGREEMENT §4), and **one wrong word makes a printed recovery secret unreadable** — with
no fourth copy behind it (HR-4.5).

The deeper defect: word count is an *encoding detail*; the security property is **256 bits of
entropy**. The test over-specified the first and never asserted the second. Rewritten to assert
the property and derive the count from the scheme the page publishes.

**Pass 3 — mechanical.** `page.evaluate(() => fn)` cannot serialise a function across the
Playwright boundary, so the check arrived as `undefined` and failed against a working page.
Assertion intent unchanged; only the mechanism was wrong.

```
Verdict: PASS
```

## Gate 4 — Implement

```
Manifest:
  panel/static/audit-keygen.html   new   ASCII-only (see the incident below)
  panel/static/audit-keygen.js     new   X25519 generate, HKDF -> AES-GCM wrap/unwrap
  panel/static/wordlist.js         new   256 words, 8 bits each, 32 words per secret
  panel/static/audit-keygen.css    new
  panel/server.js                  new   Node stdlib static server, sends the real CSP
  panel/playwright.config.js       new
Hard rules cited at the site: HR-0.3, HR-4.1, HR-4.5, HR-4.6, HR-4.7, HR-9.7
Waivers: none
Verdict: PASS
```

**Wordlist: BIP-39 rejected deliberately.** 256 words, one byte each, 32 words for 256 bits — no
bit-packing and no checksum arithmetic, which is the other place BIP-39 implementations go wrong.
Verified by machine: exactly 256 entries, no duplicates, unique at four characters so smudged
handwriting stays recoverable, all 3–7 characters. **Two 4-character collisions were found and
fixed** (`audio`/`audit`, `basil`/`basin`), and my hand-count of the list was also wrong — which
is precisely why it is checked by machine rather than by reading. The list is frozen: reordering
any entry invalidates every secret ever printed.

**Wrapped blob = `nonce || AES-GCM(d || x)`** — fixed 64 bytes, no JSON, nothing to canonicalise.
BLK-13's lesson applied pre-emptively rather than after the fact. The public half rides along so
an unwrap proves it recovered *this* keypair rather than 32 plausible bytes. Unwrap failure
deliberately does not distinguish wrong-secret from tampered-blob.

**Incident, recorded because I repeated a mistake I had already written down.** A PowerShell
string round-trip re-encoded the HTML's UTF-8 punctuation as mojibake — the same failure that hit
`tether.proto` at phase 0.1 gate 3, after which I recorded *"commit before mutating, or mutate a
copy"*. I then did it again, on an uncommitted file. Fixed by rewriting the file ASCII-only and
committing **before** the mutation tests below, so `git checkout --` could restore. A lesson only
counts once it changes behaviour.

## Gate 5 — Green + aligned

```
npx playwright test      ->  10 passed, 0 failed
cargo test --workspace   ->  43 passed (unaffected)
```

| Spec / rule clause | Where | Complete |
|---|---|---|
| keypair generated **in-browser**, random | `audit-keygen.js`, WebCrypto X25519 | yes |
| wrapped under a **256-bit paper recovery secret** | HKDF-SHA256 → AES-256-GCM | yes |
| wrapped under authenticator A / B (`prf`) | — | **no** — hardware + BLK-9 precondition |
| **three unwrap paths proven independent** | 1 of 3 proven | **partial** |
| public half committed to the epoch-stamped admin key list | — | **no** — no real key generated yet |
| HR-4.6 no passphrase anywhere | asserted, mutation-tested | yes |
| HR-4.7 memory-only, cleared on navigation | asserted, mutation-tested | yes |
| HR-9.7 no CDN, CSP `self` | asserted, mutation-tested | yes |

### HR-15.6 — the three questions

**Control: the recovery-secret wrap.** *Exists* — yes. *Functions* — yes, 10 tests including
wrong-secret and tampered-blob rejection. *Authorizes or informs* — **authorizes**: a wrong secret
returns nothing at all, because AES-GCM is authenticated.

**Watched it fail — yes, four mutations.** These four tests passed at gate 3 against a page that
did nothing, so they were vacuous until proven otherwise:

| Mutation | Guard | Result |
|---|---|---|
| Added `<input type="password">` | HR-4.6 no passphrase | **RED** |
| `localStorage.setItem("audit_priv", hex(d))` | HR-4.7 memory-only | **RED** |
| Added `<script src="https://cdn.example.com/x.js">` | HR-9.7 no CDN | **RED** |
| Replaced `crypto.getRandomValues` with a constant | HR-0.3 CSPRNG | **RED** |

All four reverted via `git checkout --`; suite green and tree clean afterwards.

## Gate 6 — Run

```
node server.js       serves 127.0.0.1:4173 with the real HR-9.7 CSP
Playwright chromium  10/10 against a real http:// origin
Tier                 integration (workflow §5) — exactly one real dependency, a browser
retries              0, deliberately: a flaky security test teaches people to re-run
                     until green
```

The server sends the real CSP rather than none, so an inline script or CDN reference is blocked by
the **browser** and fails the tests — not merely flagged in review. It also gives a real origin, so
the HR-4.7 storage assertions are meaningful; `file://` has no usable origin and they would have
passed vacuously.

## Gate 7 — Scan

```
npm audit --audit-level=low     found 0 vulnerabilities
cargo fmt / clippy / deny       unchanged and clean
TODO grep                       1, TODO(BLK-12), the permitted form
Playwright                      3 packages, devDependencies only
```

**New dependency surface, stated plainly.** Playwright adds a Node toolchain the spec did not plan
for — spec §3 rejected a React SPA specifically to avoid "a second build pipeline". This is
test-only and ships nothing (HR-9.7 requires panel assets vendored and served locally), but
`npm audit` should join the CI gate list alongside `cargo deny` and `govulncheck`.

## Gate 8 — Commit

Committed on `phase-0-foundations`. Registry updated.

---

## Verdict

**All gates pass.** Spec Phase 0's audit-keypair bullet moves from *not started* to *one of three
wraps implemented and proven*.

The remaining two wraps need physical authenticators, and **BLK-9's retained precondition still
binds**: registering a credential freezes the WebAuthn RP ID, so the panel domain must be chosen
first — otherwise both hardware wraps die on a later domain change and only this paper wrap is
left, which is the terminal-failure-adjacent state HR-4.5 exists to keep three copies away from.
