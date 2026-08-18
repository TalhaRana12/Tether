# Gate trace — phase 0.3 — signing ceremony, authenticator wraps, Go/Android/CI

**Spec phase:** 0 · **Workflow phase:** 0.3 · **Date:** 2026-08-18
**Branch:** `phase-0-foundations`

Closes every remaining spec Phase 0 item that does not require buying hardware, under the
zero-budget substitutions recorded in [FREE-TIER-SUBSTITUTIONS.md](../../../FREE-TIER-SUBSTITUTIONS.md).

## Gate 0/1 — Status and Order

```
Open blockers (module-wide):  0
Prerequisite phases:          0.1, 0.2 committed with proofs passing
Verdict: PASS
```

## Gate 2 — Reconcile

One divergence found, and it was found by a **tool disagreeing with a test I had written**:

| | |
|---|---|
| My gate said | the manifest must set `android:debuggable="false"` |
| `gradle lint` said | `HardcodedDebugMode`, severity **Fatal** |
| Who was right | **lint**. AGP injects the value per build type, so a hardcoded manifest attribute can mask what the release build actually produced |

The assertion was checking a value that does not control the outcome. HR-8.5's *property*
is unchanged; the check moved to `TestReleaseBuildTypeIsNotDebuggable`, plus its inverse.

```
Verdict: PASS
```

## Gate 3 — Red

```
Android manifest gate   5 tests red on a missing artifact, 0 compile errors
Authenticator wraps     4 tests red on missing #wrap-authenticator, 0 collection errors
```

### Gate 3 re-entered once, and the reason is the most useful finding in this phase

`an authenticator with its OWN credential still cannot open another wrap` was originally
written as *"a different authenticator cannot open another authenticator wrap"* — and it
**passed against two mutations that should have destroyed it**:

| Mutation | Expected | First version |
|---|---|---|
| prf output replaced by a constant | RED | **passed** |
| prf output overwritten after derivation | RED | **passed** |

The cause: the second virtual authenticator held **no credential at all**, so
`navigator.credentials.get()` threw before any decryption was attempted. The test asserted
*"a device with no credential cannot produce an assertion"* — true, trivial, and not the
property HR-4.5 needs.

Rewritten so authenticator B registers its own working credential, and the test
sanity-checks that B opens **its own** wrap before asserting it cannot open A's. The
failure must now come from the AES-GCM tag check. Both mutations now go **RED**.

This is the single clearest example so far of why HR-15.6 exists. Green tests are a floor,
not a target — and this guard had already been written into a gate file as evidence.

## Gate 4 — Implement

```
tools/sign-release/          new   Ed25519 keygen / sign / verify (outside the workspace)
tools/tpm-seal.ps1           new   seal the seed under a non-exportable TPM RSA key
keys/                        new   public halves + epoch-stamped admin key list
crates/agent-core/tests/real_signature.rs + fixtures/   new
go.mod, control/, admin/     new   Go module
internal/cigates/            new   Android manifest gate, no SDK needed
android/                     new   Gradle project, wrapper pinned + checksummed
.github/workflows/ci.yml     new   six jobs, no signing credential
panel/static/audit-keygen.*  mod   WebAuthn prf wraps
```

**A fact that shaped the design, verified rather than assumed:** the Windows TPM **cannot
hold an Ed25519 key**. `CngKey.Create(ED25519, "Microsoft Platform Crypto Provider")`
returns *"The requested operation is not supported."* It offers RSA. Rather than switch
algorithms — which would break HR-4.1's pinned EdDSA and force a rewrite of the tested
verifier — the Ed25519 **seed** is sealed under a non-exportable TPM RSA key.

Three bugs found while testing, each worth remembering:

- PowerShell prepends a **UTF-8 BOM** when piping to a native command, and Rust does not
  treat `U+FEFF` as whitespace — so the seed failed to parse with a confusing "odd number
  of digits" a long way from its cause.
- The sealed-blob path resolved against the **caller's** working directory, not the repo
  root, so a ceremony run from the wrong folder failed obscurely.
- `curl` without `-L` returned an **HTML redirect page**, which was written into the Gradle
  `distributionSha256Sum` field because nothing validated the shape before writing.

## Gate 5 — Green + aligned

```
rust        46 tests
go           7 tests
playwright  14 tests
TOTAL       67
```

### HR-15.6 — the three questions

**Control: TPM-backed release signing.** *Exists* — yes. *Functions* — yes, end to end:
genuine manifest verifies, tampered manifest refused, wrong key refused. *Authorizes or
informs* — **authorizes**; nothing installs without a valid signature. *Watched it fail* —
yes, tamper and wrong-key both rejected, and one flipped bit yields `BadSignature`.

**Control: three independent audit-key wraps.** *Exists* — yes, all three. *Functions* —
yes; the authenticator path and the paper path both recover the **same** public key.
*Authorizes or informs* — **authorizes**; a wrong secret returns nothing, because AES-GCM
is authenticated. *Watched it fail* — yes, and **the first version of that test was
worthless**, which is recorded above.

**Control: Android manifest gate.** *Exists* — yes, 7 tests. *Functions* — yes.
*Authorizes or informs* — it **blocks a build**, so it authorizes. *Watched it fail* — yes,
it went red on the missing manifest, and `gradle lint` independently corrected one of its
assertions.

### The most valuable test added this phase

`crates/agent-core/tests/real_signature.rs`. Every other test in that crate signs with a
seed it defines itself, which proves the verifier is **self-consistent** — and
self-consistency is exactly what a signing pipeline fails at. The interesting failure is
not "the verifier is wrong", it is "**the signer and the verifier disagree**", and no
self-generated signature can ever see it. Its fixtures were captured from the real TPM
ceremony.

## Gate 6 — Run

```
signing ceremony   keygen -> TPM seal -> unseal -> sign -> verify   ok
                   tampered manifest -> refused;  wrong key -> refused
gradle lint        exit 0, ZERO issues
binaries           agents report the protocol floor; helper/broker exit 1 (inert)
reproducibility    byte-identical, and byte-identical from a DIFFERENT source path
```

## Gate 7 — Scan

```
cargo fmt --check ................ PASS
cargo clippy -D warnings ......... PASS
cargo deny check ................. advisories ok, bans ok, licenses ok, sources ok
go vet ........................... PASS
npm audit --audit-level=low ...... 0 vulnerabilities
gradle lint ...................... PASS, 0 issues
TODO grep ........................ 1, TODO(BLK-12), permitted form
```

## Gate 8 — Commit

Atomic commits on `phase-0-foundations`, all authored `TalhaRana12`.

---

## Spec Phase 0 — final status

| Requirement | Status |
|---|---|
| Cargo workspace + Go module + Gradle project | ✅ |
| Wire protocol, version floor, absences, `elevate` deleted | ✅ |
| CI: clippy, deny, fmt, govulncheck, gradle lint, manifest gate, no signing credential | ✅ **written**, never executed — needs a remote |
| Offline release signing, public half committed, rollback format | ✅ **with a documented downgrade** (HR-0.2) |
| Sigstore/cosign tested end-to-end on a dummy artifact | ❌ **not done** — see below |
| Admin audit keypair, wrapped three ways | ✅ implemented and proven; the **real** key still needs a human to register two authenticators |
| Public half in the epoch-stamped admin key list | ❌ empty, follows from the above |
| Pin control-plane SPKI + server identity key | ❌ needs a deployed control plane (Phase 1) |
| `THREAT-MODEL.md`, `SECURITY-REVIEW.md` | ✅ |

**Exit criteria: 4 of 6 met.**

| Criterion | Verdict |
|---|---|
| stub agent rejects a downgraded build | ✅ |
| rollback: stale epoch rejected, fresh accepted | ✅ |
| two builds byte-identical | ✅ including from a different source path |
| sign one manually with the offline key | ✅ **TPM substitute**, cost recorded at HR-0.2 |
| CI produces reproducible unsigned artifacts | ❌ CI has never run |
| all three unwrap paths exercised and independent | ✅ **in test**; the real key awaits a human |

**Phase 0 is not formally complete.** What remains needs a `git push`, a browser session of
about two minutes, a Rekor round-trip, and Phase 1's control plane. **None of it costs
money and none of it is an engineering decision.** HR-15.1 is therefore not cleared for
spec Phase 1 — but nothing blocking is technical.
