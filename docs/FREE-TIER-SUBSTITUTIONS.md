# Zero-budget substitutions

**Context:** the author is a university student and is not buying hardware. This document
replaces every paid item in the spec with a free one, and — the part that matters — states
**exactly which security property each substitution keeps and which it gives up.**

**The rule this document obeys.** Under the BLK-10 resolution, HARD-RULES wins and any
deliberate deviation must be cited at the rule. Substituting for hardware named in HR-0.2,
HR-0.3, and HR-9.2 is a deviation, so each one below is cited at its rule and listed under
accepted risks. A substitution recorded as an equal is a lie; a substitution recorded with
its cost is engineering.

**Summary: three of four are complete substitutions with no security loss. One is not.**

| Spec item | Cost | Free substitute | Property lost |
|---|---|---|---|
| 2× WebAuthn authenticators | ~$50 | **Windows Hello + Android phone** | none material |
| Panel domain | ~$12/yr | **PSL-listed free subdomain**, or GitHub Student Pack | none |
| CI runner | — | **GitHub Actions free tier** | none |
| **YubiKey for release signing** | ~$50 | **TPM-backed non-exportable key** | **air-gap, and touch-per-signature** |

---

## 1. WebAuthn authenticators — complete substitution

### What the hardware was for

HR-9.2 makes WebAuthn mandatory for the admin panel with **no password, TOTP, or magic-link
fallback in any environment**, and requires **at least two** authenticators registered.
HR-4.5 additionally uses each one's WebAuthn `prf` extension output to independently wrap
the X25519 audit key.

Two, not one, because a single authenticator is a single point of failure for an account
that cannot fall back to a password.

### The free substitute

**Authenticator A: Windows Hello.** Backed by this machine's TPM 2.0, which is present and
enabled (verified). It is a genuine WebAuthn *platform authenticator* — the credential is
generated in and never leaves the TPM.

**Authenticator B: your Android phone**, via passkeys over the hybrid transport. Backed by
StrongBox or the TEE.

### Why this loses nothing material

HR-9.2's own wording is *"Register at least two authenticators (phone + hardware key)"* — a
phone was already contemplated. Both substitutes are hardware-backed, both are
phishing-resistant and origin-bound, and both are real WebAuthn authenticators as far as
the protocol is concerned. The `prf` extension is supported by Windows Hello in
Chrome/Edge and by Android passkeys.

### The two caveats worth knowing

- **Device binding.** Windows Hello is bound to this laptop. Lose the laptop and
  authenticator A is gone. That is precisely why HR-4.5 has a **third** wrap — the printed
  256-bit recovery secret, which is already implemented and free.
- **Passkey sync.** Android passkeys sync through Google Password Manager by default, so
  the credential may exist in more than one place. For a `prf`-derived key that widens
  custody beyond one device. Prefer a device-bound credential where the platform offers
  the choice, and treat the phone as the weaker of the two.

**Verdict: no material loss.** Register both, and keep the paper secret.

---

## 2. Panel domain — complete substitution, if you get one detail right

### What the paid domain was for

HR-9.1 requires the panel on a **separate registrable domain**, not `admin.example.com`.
The reason is precise: `SameSite` and cookie scope operate on the **registrable domain**, so
`admin.example.com` and `api.example.com` are the *same site*, and an XSS or open redirect
on the API can drive authenticated panel requests (spec §6.16, T27).

### The detail that makes free work

A free subdomain only satisfies HR-9.1 **if its parent is on the Public Suffix List.** The
PSL is the browser's own list of "these are effectively TLDs", and it is exactly what
`SameSite` consults. So:

- `foo.pages.dev` and `bar.pages.dev` **are** different sites — `pages.dev` is on the PSL
- `foo.myserver.com` and `bar.myserver.com` **are not** — same registrable domain

Free and PSL-listed: `*.pages.dev` and `*.workers.dev` (Cloudflare), `*.vercel.app`,
`*.netlify.app`, `*.github.io`, `*.duckdns.org`.

**Also worth having as a student:** the **GitHub Student Developer Pack** includes a free
real domain from Namecheap for a year, plus free SSL. That is the nicest option, and it is
free specifically because you are at university.

### The constraint that still binds

BLK-9 is descoped but its constraint is retained, and it is unchanged by going free:

> The name must be fixed **before any WebAuthn authenticator is registered.** Registration
> binds every credential to that name as the RP ID. Change it later and **both** `prf`
> wraps of the audit key die, leaving only the paper secret — the last of three, with no
> fourth anywhere (HR-4.5).

A free subdomain makes this *easier* to get wrong, not harder: it costs nothing to pick one
casually. Pick it deliberately.

**Verdict: no loss.**

---

## 3. CI — complete substitution

GitHub Actions is free for public repositories. [ci.yml](../.github/workflows/ci.yml) is
already written for it.

The property spec §6.1 cares about is unaffected and is *free by construction*:
**CI holds no signing credential of any kind.** Verified — the only secret in the parsed
workflow is `secrets.GITHUB_TOKEN`, and top-level permissions are `contents: read`.

**Verdict: no loss.**

---

## 4. Release signing — the one that is NOT a clean substitution

Read this part carefully. It is the only place where free costs something real.

### What the YubiKey was for

HR-0.2, one of the four governing rules:

> **Nothing online can sign a release.** The release key is offline hardware requiring a
> physical touch. CI can build; only a human with the token can ship.

Spec §6.1 names the attack: steal a GitHub Actions token, trigger a release workflow, CI
signs, and every agent auto-updates to a backdoored build with a **valid signature**. Spec
§0 calls this "the control that separates you from the AnyDesk incident."

That rule is doing three separate jobs:

| # | Property | Why it matters |
|---|---|---|
| 1 | **CI cannot sign** | a stolen Actions token is worth a build log, not a fleet |
| 2 | **The key cannot be copied off the signing machine** | malware on your laptop cannot become a release key |
| 3 | **Each signature needs a deliberate physical act** | a compromised process cannot sign silently in the background |

### The free substitute: a TPM-backed non-exportable key

Your machine has **TPM 2.0, enabled** (verified). Windows CNG can generate an Ed25519 key
inside it via `NCRYPT_PLATFORM_KEY_STORAGE_PROVIDER` — the same mechanism HR-4.4 already
specifies for the host device key. The private key is generated in the TPM and **cannot be
exported**, by hardware.

### What it keeps and what it costs — stated plainly

- **Property 1 — kept, completely.** The key exists only on your machine. CI has no access
  to it and no code path to it. The AnyDesk attack is closed for free. This is the property
  that carries most of the weight.
- **Property 2 — kept.** The TPM will not export the key. Malware on your laptop can *use*
  it while running as you, but cannot *take* it. This is the same guarantee a YubiKey gives,
  and it is the reason to prefer the TPM over the obvious alternative of a key file on a USB
  stick, which loses it entirely.
- **Property 3 — REDUCED.** This is the real cost. A YubiKey with touch policy `always`
  requires a finger on metal for every single signature. A TPM key requires only that a
  process runs as you. **Malware on this machine, at the moment you are signing, can sign
  additional things you did not intend.**

Mitigate as far as free allows, and no further: require a **TPM PIN** on the key
(`NCRYPT_PIN_PROPERTY`), so signing needs a deliberate human entry rather than a silent API
call. That is a human-in-the-loop step. It is **not** the same as a physical touch — a PIN
can be captured by a keylogger and replayed; a touch cannot.

### The honest accounting

**Substituting the TPM for a YubiKey keeps two of three properties and weakens the third.**
This is a genuine reduction in the security model and is recorded as such — in HR-14.4's
accepted risks and at HR-0.2 itself — rather than quietly declared equivalent.

### The upgrade path, also free

Once the Android client exists in Phase 6, your **phone's StrongBox** with
`setUserAuthenticationRequired(true)` gives back property 3: the key is non-exportable
*and* every use requires a biometric, which is a physical act a keylogger cannot replay.
That is functionally a YubiKey you already own. It costs a small signing app, not money.

Until then: **do not distribute builds to anyone else.** HR-15.2 already forbids handing
this to a second person before Phase 8, and the weakened signing property is a second,
independent reason to hold that line.

---

## 5. Infrastructure, for when Phase 1 arrives

Not needed yet; recorded here so it is not a surprise. Everything runs in **Docker**.

| Need | Free option | Note |
|---|---|---|
| Control plane + Postgres VM | Oracle Cloud **Always Free** — 4 ARM cores, 24 GB | genuinely free indefinitely, not a trial |
| **Separate** TURN host | second Always Free VM | **HR-11.1 requires TURN not share a host with the control plane** — the free tier gives two VMs, so this is satisfiable |
| Off-box append-only log storage (HR-11.3, BLK-8) | Cloudflare R2 free tier / B2 | must be a **separate account with its own credentials**, or it is not off-box in the sense that matters |
| TLS | Let's Encrypt via Caddy | already the spec's choice (§3) |

The one thing to watch: HR-11.1 and BLK-8 both depend on *separation* — a separate host, a
separate cloud account. Free tiers tempt you to put everything in one account because it is
one signup. That collapses exactly the property those rules buy.

---

## What none of this changes

Free substitution does not touch the parts of the model that were never about money:

- the absent wire messages (HR-1.1) — free, and already enforced by tests
- the host-side consent gate (HR-2.1) — free, Phase 8
- the audit chain and its length-prefixed hash (HR-10.2) — free
- monotonic clocks (HR-6.1), the protocol version floor (HR-1.6), the privilege split
  (HR-7.1, HR-7.3) — all free, all structural

**The expensive parts of this design were never the hardware.** They were the decisions to
delete messages rather than gate them, and to make the person being watched the one who
decides. Those cost nothing and are already done.
