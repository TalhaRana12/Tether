# Design intent — module `tether`

**Purpose** ([implementation-workflow.md §8](../../implementation-workflow.md)): the reasoning behind
the design, loaded at every gate, so that **an uncovered gap is resolved the way this system is
designed rather than the way such systems are usually built.**

That distinction is the whole reason this file exists. An agent that hits an ambiguity and resolves it
from general knowledge of how remote-desktop software normally works will produce something reasonable
and wrong, because nearly every convention in this product category is the opposite of what is
specified here. Commercial remote desktop tools have unattended access by default, admin-initiated
sessions, server-side pairing, and vendor-held signing keys. Every one of those is forbidden here.

**This file contains no decisions.** Everything below is cited to
[implementation-spec-v4.md](../../implementation-spec-v4.md) or
[HARD-RULES.md](../../HARD-RULES.md). Where those are silent, the answer is a Blocker Record, not
inference from this document.

---

## 1. The intent in one sentence

> The server operator and the admin — both of whom are the same person — must be **unable** to view or
> inject into any session on a machine they do not own. (spec §0)

Not "must be prevented by policy." Not "must be logged if they do." **Unable**, as a property of the
protocol, verifiable by reading the `.proto` file.

## 2. Why the bar is set here and not lower

This software grants full control of a machine to a remote party. **Functionally it is
indistinguishable from a Remote Access Trojan** (spec §0). The entire difference is:

1. verifiable consent, and
2. an audit trail the session cannot erase.

HR-0.6 states the consequence: **any change that weakens either erases the difference.** That is the
test to apply to a design question this document does not cover — not "is this secure enough", but
"does this still distinguish us from a RAT."

Spec §13 names what is actually being managed: family and friends will say yes because they trust you,
not because they have evaluated the threat model. Every restriction exists so that trust is
**justified rather than merely given** — "and especially when nobody would notice."

## 3. The four governing rules, and what each one killed

Each of these killed a real attack found in the §6 reviews. They are the rules from which most others
derive; a change that violates one is wrong regardless of how convenient it is (HR-0.1–0.4).

| Rule | Killed |
|---|---|
| **Admin operations are monotonically restrictive** — revoke, suspend, kill; never grant, pair, connect | T11: a compromised admin account reaching a host |
| **Nothing online can sign a release** — offline hardware, physical touch per release | §6.1 / T16: a stolen CI token shipping a backdoor to every agent |
| **No secret is derivable from anything guessable** — no passphrase-derived keys, anywhere | §6.8 / T22: offline GPU brute force of the audit key |
| **Pairing is not permission to connect** — the host user decides per connection | §6.25: a paired device watching someone's screen at 2am while they get a toast |

Two more that carry the same weight:

- **HR-0.5 — the trust boundary runs in both directions.** Every byte crossing a session, either
  direction, is untrusted input to whoever receives it. A compromised host attacking the phone is as
  much a threat as the reverse (§6.17).
- **HR-2.9 — notification is not authorization.** The border, tray icon, and toast are necessary and
  **not sufficient.** If a control only informs the host user after the fact, it satisfies nothing.

## 4. Absence as a security control

The design's most unusual move: certain messages **do not exist in the wire protocol** — not disabled,
not feature-flagged, not permission-gated. Absent (HR-1.1).

`grant_capability` · `add_peer` · server-originated `start_session`/`join_session`/`observe_session` ·
`wipe`/`reset`/`reconfigure` · `elevate` · anything that approves a connection on a user's behalf,
sets a device's access mode, sets a backup credential, or signs a release.

**Why absence rather than a permission check:** a permission check is code, code has bugs, and a
compromised admin account plus one authorization bug equals a session on someone's laptop. A message
that does not exist has no bug. HR-1.2 requires saying so in a comment in the `.proto` file, naming the
rule, **so that a future contributor does not helpfully add them back** — the whole control is one
plausible pull request away from evaporating, and the comment is what stops it.

The distinction to keep straight (HR-1.3): `connect_request` **does** exist. It travels peer-to-peer
and is answered by the host user. What does not exist is any message by which the *server or admin*
initiates, approves, or observes a session.

`elevate` is the model case of how this design handles an unbuildable feature. It was not gated or
deferred — it was **deleted**, because delivering it required exactly the SYSTEM-session input
primitive that §6.2's helper design exists to deny (§6.14). The stated cost: remote software
installation on Windows largely stops working. The design pays it.

## 5. Where authority lives

> **The JWT authorizes you to the control plane. It does not authorize you to a host.** (spec §4, HR-5.4)

A compromised server can forge any JWT it likes and still cannot connect to your laptop, because your
laptop has never been told to trust JWTs. `role` is **advisory only** — a forged `role: admin` gets the
panel, not a desktop.

Hosts decide locally, against a table (`$DATA/peers.db`, `0600`) that the server and panel cannot read
or modify. Revocation is enforced **solely by the server declining to relay** (HR-1.7) — it needs no
host cooperation, hosts keep their keys, and reversing a revocation resumes everything automatically.
There is no self-wipe, because §6.4 found that forged mass revocation would otherwise force everyone to
be physically at their laptop, which is the outcome the design most wants to avoid.

The agent obeys exactly **two** server-originated commands: `kill_session` and `revoke_device`. Both
strictly restrictive, both reversible, both signed by the pinned Ed25519 server identity key. **No
other message type is signed, and therefore no other message type is obeyed** (HR-1.4). The
consequence is stated openly rather than hidden: a fully compromised control plane can kill sessions and
refuse to relay. That is an accepted denial of service, acceptable *because* both commands only reduce
access.

## 6. The human is load-bearing, deliberately

Several controls terminate in a person, and that is the design rather than a gap in it:

- **The 6-digit SAS** (HR-3.1 step 6) derives from the **live handshake**, not the QR. An attacker who
  screenshots the QR runs a *different* handshake and gets a *different* code. QR suppression is
  defence in depth; the SAS is the actual control, and it works whether or not the QR leaked (HR-3.2).
  Six decimal digits at 48px because people actually compare those, unlike 16 hex characters.
- **The consent prompt** (HR-2.1). Deny by default, 60s timeout is a Deny, and the label shown is the
  **locally-stored pairing name** — never the peer-supplied one, which is not displayed in the prompt at
  all (HR-2.2).
- **Pairing requires a human physically at the machine** or the registered backup credential (HR-3.6).
  There is no server-side path to add a key to a host allowlist. This is why you can never reach a
  friend's laptop, and it is a feature.

Because these controls rest on human perception, **accessibility is a security requirement, not a
polish item** (HR-13.1): *a control nobody can perceive is a control that gets clicked through.* Hence
digit-by-digit screen-reader announcement, audio SAS on both devices, icon-plus-text warnings never
colour alone, and a consent prompt that never auto-focuses Allow.

## 7. Honesty as a design property

The spec repeatedly chooses stating a limitation over engineering around it, and an agent resolving a
gap should make the same choice:

- **Capture-active detection is best-effort** — on Wayland the portal model prevents enumerating other
  capturers. Where the compositor exposes nothing, **the UI says so** rather than implying a check
  happened. HR-3.4 forbids presenting it as a guarantee in copy, docs, *or* code comments.
- **"Nothing but metadata" undersells it** (§6.11) — session times, durations, and byte counts over
  weeks are a behavioural profile: when someone is home, when they work, when they travel. The
  onboarding doc says so.
- **No lock screen, greeter, or UAC access** (HR-14.2) is stated as a hard limitation. There is no
  Ctrl+Alt+Del button because it cannot work; the host sends an explanatory overlay, never a black or
  frozen frame (HR-14.3).
- **The backup credential is a second key to the house** (HR-4.7, §6.26) — a genuine widening of the
  attack surface, listed under accepted risks. The alternative was a design whose recovery path is
  "drive to Islamabad", which people route around by never revoking anything, which is worse.
- **Losing all three audit-key wraps is the intended terminal failure.** There is no fourth copy
  anywhere (HR-4.5).

WORKING-AGREEMENT §4 has the general form of this: **never let documentation and code disagree
silently.** Here it is stronger, because the documentation is a promise made to people who installed
this on trust.

## 8. What the audit log is and is not

Four properties must hold **simultaneously** (HR-10.1): the admin can read it, the server cannot,
nobody can forge it, and nobody can silently truncate it. The fourth is the one §6.7 found missing — a
hash chain cannot see what was cut from the end, hence device-signed head checkpoints every 30s and the
panel rendering any shortfall as `TRUNCATED — N entries missing`.

Scope is drawn at **remote-access events only** (HR-10.7). The never-logged list — screen content,
keystrokes, applications launched, window titles, browsing activity, locally opened files, any local
non-remote usage — has **no code path**, and HR-10.8 is the standing instruction:

> If you are ever tempted to add an item from the second list, **that is the moment this stops being a
> remote-access tool and becomes monitoring software.**

The host copy is authoritative and kept forever; the server's is a replica capped at 90 days. Opting
out of sharing appears in the panel as `audit: opted-out`, **never as silence** (HR-10.9).

## 9. Privileged components hold nothing

The privilege model is a single idea applied twice: **the thing with the framebuffer and the socket is
never the thing with privilege.**

- Windows: a SYSTEM **broker** with no capture code, no input code, no session keys, no network code —
  it launches and supervises an unprivileged per-session worker, which holds all session keys and dies
  with the session (HR-7.1). The broker exists because Desktop Duplication cannot work from session 0
  (§6.13); it is "the smallest thing that could possibly work" and is reviewed line-by-line.
- Input injection: a separate binary, **under 500 lines, no network code**, behind four independent
  authentication layers, and **inert outside an authorized session** — the escalation primitive must not
  exist when nobody is connected (HR-7.4).
- **No udev rule ever grants `/dev/uinput` to the login user** (HR-7.5). That is the Wayland sandbox
  escape the helper exists to prevent.

## 10. How to resolve a gap this document does not cover

The operative section. Workflow §3.4 gives the test — *is this observable from outside my process?* —
and when uncertain, treat it as observable. The cost of an unnecessary escalation is a message; the
cost of a wrong silent decision is found in production.

Beyond that, in order:

1. **Run Appendix B**, HARD-RULES' ten-question pre-merge self-check. Six of its ten questions are
   full stops, and they catch most gaps mechanically.
2. **Ask HR-0.6's question:** does this still distinguish us from a RAT?
3. **Ask HR-15.6's third question:** is the thing I am about to build an *authorization*, or a
   *notification wearing an authorization's name*? This is the question that v3's entire review failed
   to ask, and §6.25 is what it cost.
4. **Prefer absence to a check.** If the safe version of a feature is one where a message does not
   exist, that is the design, not a limitation of it.
5. **Prefer deny to allow.** HR-2.4 sets `connect`, `clipboard_read`, `clipboard_write`, and
   `file_transfer` all denied by default; new capabilities start closed, and absence of a rule means no.
6. **Prefer a stated limitation to a worked-around one** — §7 above.
7. **Enforce before parsing.** Capability checks happen *before* parsing a gated message body, never
   after (HR-2.5).
8. **Monotonic clocks for every local expiry**, wall-clock only for JWT `exp`/`nbf` (HR-6.1, HR-6.2).
   This is the single easiest rule to break by accident and the one with an injected-seam remedy already
   required by workflow §5.
9. **Weight review effort toward security machinery.** Eight of eleven first-round findings and the
   three worst second-round findings sat in components added to *protect* the system (HR-15.7).
   Security machinery is privileged by definition, so bugs there are worth more than bugs in feature
   code.

## 11. What this design deliberately gives up

Listing these so an agent does not "fix" one. Each is a decision, not an oversight (HR-14.1, HR-14.2,
spec §1):

multi-tenancy, billing, teams · attended support for strangers · iOS client, macOS host · low-latency
gaming · Wake-on-LAN, remote printing, session recording · **a web client for sessions** — the panel is
administration only and never renders a remote desktop · **activity monitoring of any kind** ·
host-side remote wipe or remote configuration · **lock screen, login greeter, and UAC secure desktop
access** · unattended-by-default access.

And the accepted risks, documented rather than hidden (spec §2): a fully compromised host OS defeats
everything · a compromised Android client with an Accessibility Service can observe the decoded desktop
and inject taps · traffic metadata is a behavioural profile over weeks · an admin can always refuse to
relay · the backup credential is a second key to the house · **the host user can decline consent and
defeat their own remote access** — correct behaviour, occasional support call.
