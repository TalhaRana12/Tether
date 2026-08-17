# Implementation Spec — Self-Hosted Remote Desktop

**Project codename:** `tether`
**Hosts:** Windows 10/11 + Linux (X11 and Wayland)
**Client:** Android (native)
**Admin:** Web panel, invite-only user management
**Audience:** Personal use for you, family, and friends — invite-only, roughly 5–30 devices
**Spec revision:** v4 — incorporates the v3 review (§6.1–6.12) and the second adversarial review (§6.13–6.36)
**Primary design constraint:** the server operator and the admin (both of whom are you) must be *unable* to view or inject into any session on a machine they do not own

---

## 0. Read this first

You are building software that grants full control of a machine to a remote party. Functionally that is indistinguishable from a Remote Access Trojan. The entire difference is **verifiable consent** and **an audit trail the session cannot erase**.

Four governing rules, each of which killed a real attack in the §6 reviews:

> **1. Admin operations are monotonically restrictive.** The panel can revoke, suspend, and kill. It can never grant, pair, or connect. The messages that would let an admin add themselves to someone's allowlist do not exist in the wire protocol — not disabled, not permission-gated, absent.

> **2. Nothing online can sign a release.** The release key is offline hardware requiring a physical touch. CI can build; only a human with the token can ship. This is the control that separates you from the AnyDesk incident.

> **3. No secret is ever derivable from something guessable.** No passphrase-derived keys, anywhere. Every long-term secret lives in hardware — TPM, StrongBox, or a security key — so there is no offline brute-force target.

> **4. Pairing is not permission to connect.** *(new in v4, §6.25)* A paired device may *request* a session. The host user decides, per connection, at the moment of connection. Unattended access exists, but it is a deliberate opt-in the host user makes for a named device — never a side effect of having paired once. v3 had notification where it needed authorization.

Three consequences shape everything below:

- **Antivirus vendors will flag your binaries.** Screen capture + input injection + network beacon is the behavioural signature of a RAT. Code signing, reproducible builds, and vendor allowlist submissions are the only mitigations. Budget for this.
- **Your relay server is a high-value target.** Design so that compromising it yields *nothing but metadata* — and be honest that metadata is not nothing (§6.11).
- **The trust boundary runs in both directions.** *(new in v4, §6.17)* v3 modelled only "someone attacks the host." A compromised host feeds attacker-chosen H.264 into the phone's vendor `MediaCodec` — historically one of the most productive Android RCE surfaces there is. Every byte crossing the session, in either direction, is untrusted input to whoever receives it.

---

## 1. Non-goals

- Multi-tenancy, billing, org/team management
- Attended support flows (one-time codes for helping strangers)
- iOS client; macOS host
- Low-latency gaming (that is Sunshine/Moonlight's problem)
- Wake-on-LAN, remote printing, session recording
- Web client for *sessions* — the panel is administration only and never renders a remote desktop
- **Activity monitoring of any kind** (§5.3)
- **Host-side remote wipe or remote configuration** — deliberately removed in v3 (§6.4)
- **Access to the Windows secure desktop (UAC prompts) or the Winlogon desktop** — removed in v4 (§6.14). The `elevate` capability is gone with it.
- **Access to the lock screen or login/greeter screen on either OS** — v4 states this as a hard limitation (§6.15). Reboot a host remotely and you wait for a human. Design around it; do not paper over it.
- **Unattended-by-default access** — v4 makes attended the default and unattended an explicit per-device opt-in (§6.25)

---

## 2. Threat model

| # | Threat | Attacker capability | Mitigation | Phase |
|---|---|---|---|---|
| T1 | Malicious/compromised control plane | Full DB + code exec on VPS | Noise_IK inside DTLS; host authorizes from local allowlist only | 3 |
| T2 | Network MITM | Passive + active on the wire | TLS 1.3; DTLS 1.3; Noise_IK end-to-end | 1, 3, 5 |
| T3 | Stolen phone | Physical possession | Keystore + StrongBox, `setUserAuthenticationRequired(true)`, biometric per session | 6 |
| T4 | Brute force on pairing | Unlimited online attempts | 128-bit tokens, 90s TTL, single-use, backoff, rate limits | 3 |
| T5 | Stolen release signing key | Can sign malware as you | **Offline hardware key, physical touch per release**; Sigstore transparency; monotonic versions | 0, 10 |
| T6 | Poisoned auto-update | Controls CDN or release bucket | Signature verified against key compiled into the binary; Rekor inclusion proof; staged rollout | 10 |
| T7 | Malicious paired client | Valid credentials | Per-key capabilities; host-side revocation; hash-chained audit log | 8 |
| T8 | Agent abused for persistence | Local code exec on host | Worker unprivileged; broker holds no keys and only launches (§4.10); no elevation capability exists (§6.14) | 2, 8 |
| T9 | Silent exfiltration via side channels | Active session | Clipboard/file transfer off by default, per-session opt-in, logged | 9 |
| T10 | Replay of captured traffic | Recorded ciphertext | Noise forward secrecy; per-session ephemeral keys | 3 |
| T11 | Compromised admin account | Full panel access | Grant/pair/connect absent from protocol; host ignores server authorization claims; admin actions audited | 4 |
| T12 | Panel as covert surveillance | Legitimate admin access | Audit scope hard-limited (§5.3); host transparency panel; revocable by the user | 4, 8 |
| T13 | Server operator reading activity | DB dump | HPKE-sealed to admin key held in **hardware**, not derived from a passphrase | 4 |
| T14 | Admin session hijack | Stolen browser cookie | WebAuthn mandatory; step-up per destructive op; 30-min TTL; IP/UA binding | 4 |
| T15 | Forged or deleted audit entries | DB write access | BLAKE2s chain + **signed head checkpoints** so tail truncation is detectable | 4, 8 |
| **T16** | **CI/supply-chain release compromise** | GitHub token or maintainer account | Offline signing; CI cannot reach the key; Sigstore makes rogue signatures publicly visible | **0, 10** |
| **T17** | **Local privilege escalation via the input helper** | Any local process on the host | SDDL/`SO_PEERCRED` peer verification, image-path + signature check, PID-reuse guard (§6.31), session-bound capability token; scope reduced further by removing `elevate` (§6.14) | **7** |
| **T18** | **XSS in admin panel** | Attacker-controlled device label | Strict ingest allowlist, text-node-only rendering, `allowEval=false`, CSP; audit key unextractable so XSS cannot steal it | **4** |
| **T19** | **Forged mass revoke / denial of service** | Compromised server | Self-wipe removed; revocation = server declines to relay; hosts retain keys and recover automatically | **2, 4** |
| **T20** | **QR pairing capture during screen share** | Screenshot of the pairing screen | **Short authenticated string** derived from the handshake hash; QR suppressed while any capture is active | **3** |
| **T21** | **TURN relay abuse → SSRF → VPS takeover** | Valid TURN credentials | `denied-peer-ip` for all private/link-local ranges; no-multicast; quotas; TURN on a separate host | **1, 5** |
| **T22** | **Offline brute force of audit key** | DB dump | WebAuthn `prf`-wrapped key — no passphrase exists to guess | **4** |
| **T23** | **`uinput` as a Wayland sandbox escape** | Any process as the same user | Input injection isolated into a privileged helper behind a peer-credential-checked socket | **7** |
| **T24** | **Home IP disclosure via ICE candidates** | Any paired peer | mDNS candidate obfuscation; TURN-only mode for peers not marked trusted | **5** |
| **T25** | **Malicious host attacks the client** | Compromised or hostile host | Decoder input validation before `MediaCodec`; inbound clipboard/file treated as untrusted; dimension and NAL caps | **6, 9** |
| **T26** | **Hostile pairing QR** | Can show a QR to a user | `relay_hint` validated against compiled-in allowlist; phone-side "pair with new host?" confirmation before handshake | **3** |
| **T27** | **CSRF across `api.` → `admin.`** | XSS or open redirect on the API vhost | Panel on a **separate registrable domain**; `__Host-` cookie prefix; per-request CSRF tokens | **1, 4** |
| **T28** | **DNS hijack / mis-issued TLS cert** | Control of DNS or a CA | SPKI pinning plus a pinned Ed25519 server identity key in the agent binary | **1, 2** |
| **T29** | **Local clock manipulation** | Local code exec on the host | All local expiries on monotonic clocks; wall-clock only for JWT `exp` | **3, 7** |
| **T30** | **Backup restore rolls back revocation** | DB restore, benign or hostile | Monotonic revocation epoch checked at startup; `age` key on offline hardware | **1, 4** |
| **T31** | **Protocol downgrade to superseded semantics** | Active MITM or hostile peer | Compiled-in minimum `v`; refuse below floor, no negotiation | **0, 3** |
| **T32** | **Unattended access abused by a paired device** | Valid pairing, no host user present | Per-connection consent gate; unattended is per-device opt-in with a scheduled window | **8** |
| **T33** | **Credential loss forces physical visits** | Lost phone, biometric re-enrolment, TPM clear | Host-registered backup credential re-pairs without physical presence, SAS-confirmed and audited | **3, 8** |
| **T34** | **Bad update strands the rollout cohort** | Your own signing mistake | Signed rollback manifest with its own epoch, so downgrade protection stays intact | **10** |

**Accepted risks** — documented, not mitigated, and stated in the onboarding doc:

- A fully compromised **host OS** defeats everything. The agent cannot defend a machine that is already owned.
- A fully compromised **Android client** — specifically, malware holding an Accessibility Service — can observe the decoded desktop and inject taps. StrongBox protects the key, not the rendered session. There is no fix at this layer.
- **Traffic metadata** reveals session timing, duration, and volume to the relay operator. Over weeks this is a behavioural profile (§6.11).
- An admin can always **refuse to relay**, a denial of service inherent to running the infrastructure.
- **No access to the lock screen, login greeter, or UAC secure desktop** (§6.14, §6.15). This is a real capability loss, not a technicality: a remote reboot ends your session until someone is physically present. Accepted deliberately, because every workaround requires the SYSTEM-session input primitive that §6.2 exists to deny.
- **The backup credential of §6.26 is a second key to the house.** It removes the physical-visit trap of T33 at the cost of one more thing that can be stolen. Mitigated by SAS confirmation, audit, and the per-connection consent gate — but it is a genuine widening, and the onboarding doc says so.
- **The host user can decline the consent prompt and defeat their own remote access.** Correct behaviour, occasional support call.

---

## 3. Technology choices

| Component | Choice | Why this and not the alternative |
|---|---|---|
| Host agent | **Rust** (edition 2021) | Raw Win32/Linux syscalls, zero-copy frames, long-running memory safety. Go's GC hurts frame pacing; C++ hands you the bugs this project exists to avoid. |
| Control plane | **Go 1.22+** | I/O-bound WebSocket fan-out. Stdlib + single-binary deploy makes this a weekend. Also isolates the agent's `unsafe` surface. |
| Admin panel | **Go + `templ` + htmx + Tailwind**, served by the control plane | A React SPA means a second build pipeline, second auth surface, CORS, and a token in browser storage. Server-rendered + htmx gives a live panel with none of that. |
| Android client | **Kotlin + Jetpack Compose** | You need `MediaCodec` decode, `SurfaceView`, and Keystore. Flutter's WebRTC plugin sits between you and all three. |
| Transport | **WebRTC** (`webrtc-rs` / Google WebRTC SDK) | ICE, STUN, TURN, DTLS, congestion control for free. Rolling your own NAT traversal is a six-month detour. |
| E2E crypto | **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** (`snow`) | IK fits exactly: after pairing the initiator knows the responder's static key. Mutual auth + forward secrecy + KCI resistance in one handshake. |
| Audit encryption | **HPKE** (RFC 9180), X25519 + ChaCha20-Poly1305 | Anonymous-mode HPKE seals each entry to the admin public key. The host holds no admin secret. |
| **Audit key custody** | **WebAuthn `prf` extension** → HKDF → AES-GCM key wrap | Replaces passphrase derivation. The unwrap key never exists outside the security key, so there is no offline guessing target and XSS cannot exfiltrate a reusable secret. |
| Admin authentication | **WebAuthn / passkeys** (`go-webauthn`) | Phishing-resistant, origin-bound. A password here is the weakest link in the system. |
| **Release signing** | **Offline YubiKey (PIV / OpenPGP) + Sigstore** | CI must be unable to sign. Physical touch per release. Rekor gives public detectability. |
| Screen capture (Win) | **DXGI Desktop Duplication** (`windows`) | Only sanctioned zero-copy path. GDI is slow and misses composited windows. |
| Screen capture (Linux) | **PipeWire + `xdg-desktop-portal`** | Only thing that works on Wayland. X11 `XShm` fallback behind a feature flag. |
| **Windows process model** | **SYSTEM service broker + per-session unprivileged worker** | *(v4, §6.13)* Desktop Duplication does not work from session 0. The broker owns no capture or input code; it exists only to launch a worker into the active console session via `CreateProcessAsUser` and to handle `WTS_SESSION_*`. |
| Video encode | **H.264 Main profile**, hardware first, `openh264` fallback | Universal Android hardware decode. AV1 decode on mid-range Android is still patchy. *(v4: Main rather than Baseline — CABAC is worth 10–15% bitrate at a 2 Mbps ceiling and every Android hardware decoder made this decade handles it, §6.36.)* |
| Input injection | **Privileged helper** — `SendInput` (Win) / `uinput` (Linux) | Isolated behind an authenticated local socket (§6.2, §6.9). Never a blanket device grant. |
| Token signing | **EdDSA (Ed25519)** via JWKS | Small keys, fast verify, no curve-choice footguns. |
| Database | **PostgreSQL 16** | Real transactions for token rotation. SQLite will hurt at the first concurrent refresh. |
| TURN | **coturn, hardened, separate host** | See §6.6 — a default install is an SSRF gateway into your own infrastructure. |
| Reverse proxy | **Caddy** | Automatic Let's Encrypt, sane defaults, one config file. |
| **Panel origin** | **Separate registrable domain**, not a subdomain | *(v4, §6.16)* `SameSite` and cookie scope operate on the registrable domain. `admin.example.com` and `api.example.com` are the same site, so an API-side XSS reaches the panel session. A second domain makes them genuinely cross-site. |
| **Log shipping** | **Off-box, near-real-time** (`vector` or `journald` → object storage) | *(v4, §6.30)* T1 assumes the server is compromised. Logs stored on that server are erased by the same event they would have evidenced. |

---

## 4. Security architecture

> **The JWT authorizes you to the control plane. It does *not* authorize you to a host.**
> The host makes its own authorization decision, locally, against a list only it can modify.

A compromised server can forge any JWT it likes and still cannot connect to your laptop, because your laptop has never been told to trust JWTs. The admin panel inherits this: it is a client of the control plane, and the control plane has no authority over hosts.

### 4.1 Control-plane identity (JWTs + JWKS)

- **Access token:** JWT, `EdDSA`/Ed25519, TTL **10 minutes**. Claims: `sub`, `did`, `aud` (`tether-control`), `role` (`user`|`admin`), `iss`, `exp`, `iat`, `jti`.
- **Refresh token:** *opaque* 256-bit random, never a JWT. Stored as an Argon2id hash. **Rotating** — each refresh issues a new one and invalidates the old.
- **Reuse detection:** presenting a refresh token twice revokes the whole family and notifies the user. A stolen refresh token becomes a one-shot that trips an alarm.
- **JWKS:** `GET /.well-known/jwks.json`, `Cache-Control: max-age=3600`, Ed25519 JWKs with `kid`.
- **Rotation:** new signing key every 90 days. Publish in JWKS **before** signing with it (overlap ≥ 2× max token TTL), retire the old key once its tokens have expired.
- **`role` is advisory only.** It gates admin *panel* endpoints and grants nothing on any host. A forged `role: admin` gets you the panel, not a desktop.

**Verification rules — non-negotiable:**

```
1. Fetch key by `kid` from cached JWKS. Unknown `kid` → refetch once, then reject.
2. Require alg == "EdDSA". NEVER read alg from the token header to select the algorithm.
3. Reject alg == "none" unconditionally.
4. Verify iss, aud, exp, nbf with ≤60s clock skew.
5. Check jti against a replay cache for the token's remaining TTL.
6. Admin endpoints additionally require a live WebAuthn session (§4.6).
```

Rule 2 blocks the classic `alg` confusion attack, where the attacker flips to `HS256` and signs using your *public* key as the HMAC secret.

**Server identity pinning (v4, closes §6.20).** Agents do not rely on the public CA system to reach the control plane. Two layers:

- **SPKI pin** on the control-plane certificate, with a backup pin for the next rotation, both compiled into the agent.
- **Pinned Ed25519 server identity key.** Every control-plane response the agent acts on — JWKS, `kill_session`, `revoke_device`, update manifests — is signed with this key, verified against the copy in the binary. TLS becomes a transport convenience rather than a trust anchor.

Session confidentiality never depended on this (Noise handles that), but without it a DNS hijack or a single mis-issued certificate yields tokens, device metadata, and the ability to serve a hostile JWKS.

**Command signing (v4, closes §6.19).** v3 said "signed kill command" without saying signed *by what*. It is this same pinned server identity key. The consequence is stated plainly rather than hidden: **a fully compromised control plane can kill sessions and refuse to relay.** That is acceptable precisely because both commands are restrictive and reversible per rule 1 — it is the same denial of service already accepted in §2. It is not acceptable for any *other* message type, which is why no other message type is signed or obeyed.

**Protocol version floor (v4, closes §6.24).** The wire protocol carries an explicit `v`. Each build also compiles in `MIN_PROTOCOL_VERSION` and **refuses anything below it, with no negotiation and no fallback path.** Versioning without a floor lets an attacker re-select the semantics you already fixed.

### 4.2 Device identity (hardware-backed keys)

Every host and phone holds a long-lived Ed25519 identity keypair. **Private keys never leave the device.**

- **Windows host:** CNG key, TPM 2.0-backed via `NCRYPT_PLATFORM_KEY_STORAGE_PROVIDER` when a TPM exists. Fallback: DPAPI-protected file, `CurrentUser` scope, plus an entropy blob.
- **Linux host:** `systemd-creds` (TPM2-sealed) where available, else a `0600` file under `$XDG_DATA_HOME/tether/` encrypted with a kernel-keyring key.
- **Android client:** Keystore with **StrongBox** (`setIsStrongBoxBacked(true)`), TEE fallback; `setUserAuthenticationRequired(true)` with `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)`; `setInvalidatedByBiometricEnrollment(true)` so a coerced new fingerprint destroys the key rather than unlocking it.

### 4.3 Pairing — QR plus short authenticated string

**Revised in v3.** The QR alone is no longer sufficient; a screenshot of it does not get an attacker paired (§6.5).

```
1. Host checks: is any screen capture active, or any tether session live?
   If yes → REFUSE to display the QR, explain why.  (See the Wayland
   caveat below — this check is best-effort, not a guarantee.)
2. Host displays a QR:
   { v:1, host_id, host_pubkey (32B), pairing_token (16B), relay_hint }
3. Phone scans it. The camera is the out-of-band channel.
3b. Phone VALIDATES relay_hint against a compiled-in allowlist of your
    own relays, and shows an explicit confirmation naming the host
    before any handshake begins.  Anyone can print a QR (§6.18).
4. Phone opens Noise_IK using the scanned host_pubkey as the remote
   static key. The server only relays bytes.
5. BOTH devices compute:
      sas = BLAKE2s(handshake_hash || "tether-sas-v1")
      code = first 20 bits of sas, rendered as 6 decimal digits
   and display it in large type.
6. Host UI, in this order of prominence:
      ┌────────────────────────────────┐
      │        4 7 2  9 1 5            │  ← 48px
      │  Does this match your phone?   │
      │                                │
      │  Device claims to be:          │  ← 12px, muted
      │  "Ali's Pixel" (unverified)    │
      └────────────────────────────────┘
7. Human confirms ON THE HOST. Both sides persist the peer key.
   Pairing token is burned.
```

The SAS derives from the *live handshake*, not from the QR. An attacker who screenshots the QR and races the victim runs a **different handshake**, producing a **different code**, and the mismatch is visible to a human comparing six digits — which people actually do, unlike comparing 16 hex characters.

The device label is explicitly marked unverified and rendered small, so it cannot impersonate the expected device more convincingly than the code it cannot forge.

**Step 7 is why you can never reach a friend's laptop.** Pairing requires a human physically at that machine, or a pre-registered backup credential (§4.11). There is no server-side path to add a key. Tokens: 128-bit CSPRNG, 90-second TTL, single use, max 5 attempts per host per hour. Expiry is measured on a **monotonic clock** (§6.22).

**Honest caveat on step 1 (v4, §6.19 review).** Capture-active detection is reliable on Windows and on X11. **On Wayland it is not** — the portal model deliberately prevents you from enumerating who else is capturing, so you can only ever see your own session. Do not present this check as a guarantee. It is defence in depth; **the SAS in step 5 is the actual control**, and it works whether or not the QR leaked. Where the compositor exposes nothing, the host says so in the UI rather than implying a check happened.

**Pairing lifetime (v4, §6.28).** A paired key is not immortal. Optional per-pairing expiry at creation, and any key unused for 90 days is flagged in the host UI for reconfirmation before its next session. Pairings accumulate silently otherwise, and a key nobody remembers granting is a key nobody will think to revoke.

### 4.4 Session channel (defence in depth)

```
┌──────────────────────────────────────────────┐
│ Noise_IK  ← mutual auth, forward secrecy     │  ← relay CANNOT decrypt
│  ┌────────────────────────────────────────┐  │
│  │ DTLS 1.3 / SRTP  ← WebRTC's own layer  │  │  ← relay could MITM this alone
│  │  ┌──────────────────────────────────┐  │  │
│  │  │ H.264 frames + input events      │  │  │
│  │  └──────────────────────────────────┘  │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

DTLS alone is insufficient because certificate fingerprints are exchanged *through your signaling server*; a compromised server swaps them and MITMs the session. Noise inside DTLS closes that hole — its keys come from out-of-band pairing, not from anything the server touched.

Input and control travel over an `RTCDataChannel` with Noise transport state applied. Video uses **SFrame-style per-frame encryption**, preserving RTP pacing and congestion control while keeping the relay blind.

**Media key schedule (v4, closes §6.21).** v3 specified this as "HKDF-BLAKE2s over the Noise session hash," which is not enough to implement safely. RTP guarantees reordering and loss, and ChaCha20-Poly1305 nonce reuse is catastrophic, so the construction is pinned down here:

```
base       = HKDF-Extract(salt = noise_handshake_hash, ikm = "tether-media-v1")
key_h2c    = HKDF-Expand(base, "host-to-client-key",   32)   # separate per direction
key_c2h    = HKDF-Expand(base, "client-to-host-key",   32)
salt_h2c   = HKDF-Expand(base, "host-to-client-salt",  12)
salt_c2h   = HKDF-Expand(base, "client-to-host-salt",  12)

per frame:  ctr    = explicit 48-bit counter, carried in the frame header
            nonce  = salt XOR (epoch || ctr)     # never reused, never derived
                                                 # from a timestamp or sequence
                                                 # number the relay can influence
            aad    = frame header (epoch, ctr, keyframe flag)
```

- **Directional separation is mandatory.** One key in both directions plus a relay that can loop a packet back is nonce reuse by construction.
- **Receiver keeps a replay window** (RFC 3711-style, 64 frames) and drops anything outside it or already seen.
- **Rekey at 2^32 frames or every 12 hours, whichever comes first**, by incrementing `epoch` and re-expanding from `base`. At a 60fps ceiling 2^48 is unreachable, but the epoch field means exhaustion is handled rather than assumed away.
- The counter is **explicit in the header, not inferred** from the RTP sequence number — the relay controls RTP sequencing and must not be able to steer nonce selection.

**ICE privacy (v3):** enable mDNS candidate obfuscation so host-local IPs are not published. Peers not explicitly marked *trusted* on the host get **TURN-only** ICE, hiding the home IP at the cost of latency. Default trusted: none.

### 4.5 Authorization (capabilities, host-side)

| Capability | Default | Requires |
|---|---|---|
| `connect` | **denied** | per-connection consent on host, or a standing unattended grant (§4.9) |
| `view` | granted at pairing | an approved `connect` |
| `control` (mouse/keyboard) | granted at pairing | an approved `connect` |
| `clipboard_read` | **denied** | per-session opt-in on host |
| `clipboard_write` | **denied** | per-session opt-in on host |
| `file_transfer` | **denied** | per-session opt-in on host |
| ~~`elevate` (UAC/polkit)~~ | **removed in v4** | — see §6.14 |

**`elevate` is gone.** Not denied by default, not permission-gated — removed from the protocol, following rule 1's own logic. The reason is in §6.14: UAC renders on the secure desktop, which Desktop Duplication cannot capture and a user-session `SendInput` cannot reach. Delivering it would have required exactly the SYSTEM-session input primitive that §6.2 was written to eliminate. The remote user sees a black screen and an explanatory overlay when a UAC prompt appears, and someone physically present clicks it.

**`connect` is new** and is the v4 structural change. Pairing establishes *identity*; it no longer establishes *access*. See §4.9.

Revocation is immediate and local: delete the row, kill any live session bound to that key. The server and panel cannot read or modify this table.

### 4.6 Admin authentication

- **WebAuthn/passkey mandatory.** No password, TOTP, or magic-link fallback. Register **at least two** authenticators (phone + hardware key).
- Session cookie: `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite=Strict`, **30-minute** TTL, bound to a server-side record, invalidated on IP or User-Agent change. The `__Host-` prefix forces host-only scope with no `Domain` attribute, so the cookie cannot be scoped across vhosts.
- **CSRF tokens on every state-changing request (v4, closes §6.16).** v3 leaned on `SameSite=Strict` alone, which does not help when the panel and the API are the same registrable domain. Per-session, per-request tokens delivered via `hx-headers`, verified in middleware. Combined with moving the panel to a **separate registrable domain** (§3), API-side XSS is genuinely cross-site rather than nominally so.
- **The WebAuthn session is the authority, not the `role` claim.** Middleware asserts that the authenticated WebAuthn credential belongs to a registered admin, and never trusts `role: admin` in a JWT on its own. §4.1 already calls `role` advisory; this is where that is enforced.
- **Step-up reauth** — a fresh WebAuthn assertion — for every destructive operation.
- Break-glass: a randomly generated 256-bit recovery secret (**not** a passphrase), rendered as mnemonic words, printed and stored physically. Use is audited and emails you.
- CSP `default-src 'self'`, no inline scripts, SRI on every asset, htmx and Tailwind served locally. `htmx.config.allowEval = false`.

### 4.7 Audit log architecture

Four properties must hold: the admin can read it, the server cannot, nobody can forge it, **and nobody can silently truncate it**.

**On the host (authoritative):**
- Append-only `$DATA/audit.jsonl`. Entry: `{seq, ts, event, client_key_fp, client_ip, capabilities, prev_hash, hash}` with `hash = BLAKE2s(prev_hash || canonical_json(entry_without_hash))`.
- Filesystem enforcement: `chattr +a` on Linux; ACL denying `DELETE` and `WRITE_DATA` on Windows.
- The host keeps full plaintext forever. This copy is authoritative; the server's is a replica.

**Uploaded to the server:**
- Each entry sealed with **HPKE** to the admin X25519 public key, pinned into host config at enrollment. The host holds no admin secret.
- Batched every 60s; immediate for `session_start`, `session_end`, `capability_granted`.
- Server stores `(device_id, seq, prev_hash, hash, ciphertext)`. Hashes are plaintext so the chain verifies without decryption; everything meaningful is inside the ciphertext.

**Truncation detection (v3, closes §6.7):**
- Every heartbeat (30s) carries a **signed checkpoint**: `sign_devicekey({device_id, max_seq, head_hash, ts})`.
- The server stores the latest checkpoint separately from the entries.
- The panel compares `max_seq` in the checkpoint against the highest stored `seq`. Any shortfall renders as **`TRUNCATED — N entries missing`** in red at the top of the view.
- Checkpoints are signed by the device key the server does not hold, so the server cannot fabricate a lower `max_seq` to hide a deletion.

**Key custody (v3, closes §6.8):**
- The admin X25519 private key is generated **randomly** — never derived from a passphrase.
- It is stored wrapped: `AES-GCM(HKDF(webauthn_prf_output), x25519_priv)`. The wrapped blob may sit in the database; it is useless without the security key.
- Decryption flow: WebAuthn assertion with the `prf` extension and a fixed salt → 32 bytes → HKDF → unwrap → HPKE open, all in browser memory, cleared on navigation.
- **There is no passphrase, so there is nothing to brute-force offline.** A database dump yields ciphertext and a wrapped key that no amount of GPU time will open.
- Register the same `prf` salt on both authenticators.

**Recovery, stated unambiguously (v4, closes §6.34).** v3 said "export the wrapped key plus the 256-bit recovery secret to paper" without saying whether that secret *opens* anything. It does, and the design is explicit:

> The X25519 private key is wrapped **independently, three times**: once under `HKDF(prf)` from authenticator A, once from authenticator B, and once under `HKDF(recovery_secret)` where `recovery_secret` is 256 random bits rendered as mnemonic words and stored on paper offline. Any one of the three opens it. Losing all three means every audit log is permanently unreadable, and that is the intended failure mode — there is no fourth copy anywhere.

Because the recovery secret is 256 bits of CSPRNG output and never typed into anything online, it is not a brute-force target in the §6.8 sense. It is a physical-custody target, which is a threat you can reason about.

**Admin key rotation (v4, closes §6.33).** The admin X25519 *public* key is pinned into agent builds at enrollment, so v3 had no way to change it — a lost or compromised admin keypair meant every future audit entry was sealed to a key you no longer controlled, with remote reconfiguration removed by §6.4. Resolution: agents pin a **list** of accepted admin public keys with an epoch, updated only through the signed release channel (§6.1). Rotation therefore requires the offline YubiKey and a staged rollout — slow and deliberate, which is correct for a key this privileged. Hosts seal to the highest-epoch key they know and keep the previous key valid for one release cycle.

**In the panel:**
- Chain verified before display; `seq` gaps, hash mismatches, and checkpoint shortfalls all flagged prominently.
- Reading a device's audit log is itself an audited admin action.

### 4.8 Non-negotiable consent controls

Everything in this subsection is *notification*. Notification is necessary and not sufficient — see §4.9 for the *authorization* gate that v3 was missing.

- **Persistent on-screen indicator** during any session: 3px accent border on all monitors, tray icon, and an OS notification at session start naming the connecting device.
- **Kill switch:** tray item and global hotkey `Ctrl+Alt+Shift+K` — terminates all sessions and requires confirmation to resume.
- **Idle timeout:** 15 minutes without input ends the session; resuming requires fresh biometric auth.
- **Transparency panel on the host:** a settings tab stating plainly *"This device reports remote-access events to admin `<name>`"*, listing exact event types uploaded, showing the last 50 entries in plaintext, and offering one-click **stop sharing** that severs upload without breaking the user's own access. Opting out shows as `audit: opted-out` in the panel, never as silence.

### 4.9 Connection consent and unattended access *(new in v4, closes §6.25)*

The gap this closes: in v3, pairing granted `view` and `control` permanently, and every control in §4.8 was a *notification* after the fact. "My phone can watch my mother's screen at 2am and she gets a toast" satisfied v3 as written. §13 says the goal is trust that is *justified rather than merely given*; a system where the remote party decides when to look does not clear that bar.

**Every session begins with a host-side decision.**

```
1. Paired device sends connect_request { device_label, capabilities_wanted }
2. Host raises a consent prompt on the host, showing:
      - the VERIFIED pairing name (set locally at pairing, not sent by the peer)
      - the peer's key fingerprint, short form
      - what is being requested
      - Allow once  /  Allow and remember  /  Deny  /  Deny and revoke
3. No response within 60s → treated as Deny, logged as consent_timeout.
4. Only on Allow does the media path start.
```

Three access modes per paired device, chosen by the host user and stored only on the host:

| Mode | Behaviour | Default |
|---|---|---|
| **Ask every time** | Consent prompt per connection | **yes** |
| **Unattended window** | No prompt within a schedule the host user sets (e.g. weekdays 09:00–18:00); prompt outside it | opt-in |
| **Always allow** | No prompt. Indicator, notification, and audit still mandatory | opt-in, discouraged in the onboarding doc |

- The mode is set **on the host, by its owner**, and appears in the transparency panel. There is no wire message that sets it, for the same reason there is no `grant_capability` — see rule 1.
- **The device label in the prompt is the locally-stored pairing name**, never the peer-supplied one. This closes the §6.5 impersonation shape at connect time rather than only at pairing time.
- Unattended access is the honest reason most people install remote desktop software, so it exists. It is a decision the host user makes knowingly, once, for a named device — which is the whole difference.

### 4.10 Windows session architecture *(new in v4, closes §6.13)*

v3 specified a Windows Service running unprivileged. **That configuration cannot capture the screen**: services run in session 0, and DXGI Desktop Duplication requires a process in the interactive session with an open desktop handle. The spec as written did not describe a working program.

```
┌── tether-broker  (SYSTEM service, session 0) ────────────────┐
│  • no capture code, no input code, no session keys           │
│  • CreateProcessAsUser → launch worker into active console   │
│  • handles WTS_SESSION_LOGON / LOGOFF / LOCK / UNLOCK,        │
│    fast user switching, RDP takeover, worker crash restart    │
└───────────────────────────────────────────────────────────────┘
                              │  named pipe, SDDL-restricted
┌── tether-worker  (user session, UNPRIVILEGED) ───────────────┐
│  • DXGI capture, encode, WebRTC, Noise, consent UI            │
│  • holds all session keys; dies with the session              │
└───────────────────────────────────────────────────────────────┘
```

- **The broker is the smallest thing that could possibly work**: launch, supervise, relay session events. It holds no cryptographic material and terminates the worker on logoff. Reviewed line-by-line like the §6.2 helper.
- **The worker stays unprivileged**, preserving T8's intent. The privileged component simply is not the one touching the network or the framebuffer.
- Session-change handling is where the bugs will be: fast user switching, RDP takeover, and lock/unlock each invalidate the duplication interface. Budget for it in Phase 5 alongside `DXGI_ERROR_ACCESS_LOST`.
- On Linux the equivalent constraint is milder — the agent is a systemd **user** unit and dies with the session — but the greeter is still out of reach (§6.15).

### 4.11 Recovery and credential loss *(new in v4, closes §6.26)*

§6.4 removed self-wipe because "everyone must be physically at their laptop" was an outcome to avoid. v3 then produced that outcome routinely through three ordinary events: a lost or broken phone, `setInvalidatedByBiometricEnrollment(true)` firing when a family member adds a fingerprint, and a TPM clear or motherboard replacement on the host.

**At pairing time, the host also registers a backup credential**, chosen by the host user:

- a **second paired device** (the common case — a tablet, a partner's phone), or
- a **printed 256-bit recovery key**, sealed into the host allowlist and stored physically.

Re-pairing via backup credential runs the **same Noise_IK handshake and the same 6-digit SAS confirmation**, with two additions: a mandatory 24-hour delay before the new key becomes usable, and an alert on every other paired device and in the transparency panel during that window. A thief who has the recovery key still cannot get a silent session.

This is a genuine widening of the attack surface and is listed under accepted risks rather than hidden. The alternative — a design whose recovery path is "drive to Islamabad" — is one people will route around by never revoking anything, which is worse.

### 4.12 Inbound data is untrusted, in both directions *(new in v4, closes §6.17)*

v3 modelled attacks on the host and never the reverse. The client must defend itself:

- **Before `MediaCodec`:** enforce a compiled-in maximum resolution and a maximum NAL unit size; reject SPS/PPS declaring dimensions outside the negotiated bounds; reject frames whose declared length exceeds the received buffer. Vendor decoders are a long-standing Android RCE surface and they are not your code.
- **Decode in a separate process** where practical, so a decoder crash is a reconnect rather than a compromise of the app holding the Keystore-backed identity.
- **Inbound clipboard:** text only, size-capped, no rich-text or image payloads (a decompression-bomb and parser vector in both directions).
- **Inbound files:** confined destination directory, path-traversal validated, size-capped, and on Windows written with **Mark-of-the-Web** so SmartScreen treats them as downloaded. On Linux, no execute bit, ever.
- **Symmetrically**, the host applies the same validation to input events and clipboard arriving from the client. Rate cap and monotonic sequence numbers are already in Phase 7; the parser hardening is the other half.

### 4.13 Time, clocks, and expiry *(new in v4, closes §6.22)*

Pairing TTL, capability-token expiry, idle timeout, consent timeout, and the unattended window are all expiries a local attacker would love to extend by moving the system clock.

- **All local expiries use a monotonic clock** (`Instant` in Rust, `SystemClock.elapsedRealtime()` on Android). Never wall-clock.
- **Wall-clock is used only for JWT `exp`/`nbf`**, where it is unavoidable, and there with the ≤60s skew allowance already in §4.1.
- Audit entry timestamps are wall-clock by necessity, so **`seq` and the hash chain — not `ts` — are what establish ordering**. The panel orders by `seq` and flags any entry whose `ts` moves backwards relative to its predecessor.

---

## 5. Admin panel

### 5.1 What it can do

| Operation | Effect | Step-up |
|---|---|---|
| Generate invite code | Single-use, 7-day TTL, optional device cap | no |
| List / search users | Status, device count, last seen | no |
| Suspend user | Tokens revoked, signaling refused; pairings untouched | **yes** |
| Reactivate user | Restores signaling | **yes** |
| Delete user | Cascade-deletes devices, tokens, audit replicas | **yes** |
| List devices per user | OS, agent version, online state, P2P vs TURN | no |
| **Revoke device** | Server refuses to relay. **Host keeps its keys** (§6.4) | **yes** |
| **Kill live session** | Signed kill command; host tears down and logs it | **yes** |
| View audit log | WebAuthn-gated client-side decrypt + chain + checkpoint verification | **yes** |
| Rotate JWKS key | Adds new `kid`, schedules retirement | **yes** |
| View TURN bandwidth | Per-user and total, for cost control | no |
| Set per-user device limit | Default 3 | no |
| View admin action log | Admin's own actions, hash-chained | no |
| Set minimum agent version | Older agents refused relay (no forced install) | **yes** |
| **Publish rollback manifest** | Signed, epoch-stamped downgrade for a named bad version (§6.27). Requires the offline key — the panel only *stages* it | **yes** |
| **View revocation epoch** | Current epoch and last increment, so a DB restore is visible (§6.23) | no |

### 5.2 What it cannot do — by protocol, not by permission

No wire representation exists for any of these. There is no endpoint to disable, no flag to flip, no role to escalate into.

- Start, join, or observe a session on any host
- Add a key to any host's allowlist
- Grant or modify any capability (and `elevate` no longer exists to grant — §6.14)
- Read or write files, clipboard, or screen content
- Change host-side settings
- **Wipe, reset, or reconfigure a host** (removed in v3 — see §6.4)
- Recover or export any private key
- Read audit entries the admin's own hardware key cannot unwrap
- **Approve a connection on a user's behalf, or change any device's access mode** (v4 — the consent decision of §4.9 exists only on the host, and no wire message carries it)
- **Set or clear a backup credential** (v4 — §4.11 is host-local, registered in person at pairing)
- **Sign a rollback or release manifest** (v4 — the panel stages; only the offline key signs, per rule 2)

The agent must **reject any inbound message type it does not recognise and must never accept an authorization decision from the control plane.** Write this as an explicit test: feed the agent a forged, validly-signed server message asserting `grant_capability` and assert it is dropped and logged.

**Every admin operation reduces access. None expands it, and none is irreversible.** A compromised admin account can lock people out temporarily; it cannot get into anyone's machine, and it cannot force anyone to physically visit a laptop to recover.

### 5.3 Audit scope

Scope is drawn at **remote-access events only.**

**Logged and uploaded:** `session_start` (client fingerprint, IP, transport, capabilities) · `session_end` (duration, bytes, reason) · `auth_failure` · `pairing_attempt` / `pairing_success` · `capability_granted` / `capability_denied` · `file_transfer` (direction, name, size) · `killswitch_triggered` · `agent_start` / `agent_stop` / `agent_update` · `audit_sharing_disabled`

**Added in v4:** `connect_requested` / `consent_granted` / `consent_denied` / `consent_timeout` · `access_mode_changed` (which mode, set locally) · `unattended_session_start` (flagged distinctly from an attended one) · `backup_credential_registered` / `backup_credential_used` · `repair_delay_started` (the 24h window of §4.11) · `helper_auth_failure` (a local process tried to drive a helper, §6.2) · `decoder_input_rejected` (client-side, §4.12)

*(`elevation_requested` / `elevation_granted` are removed with the `elevate` capability, §6.14.)*

**Never logged; no code path exists:** screen content or screenshots · keystrokes or keystroke counts · applications launched, window titles, focus history · browsing activity, URLs, locally opened files · any local (non-remote) computer usage · location beyond the routing IP · microphone, camera, or filesystem contents

If you are ever tempted to add an item from the second list, that is the moment this stops being a remote-access tool and becomes monitoring software. Put that sentence in the README.

### 5.4 Panel routes

```
GET  /admin                          dashboard: online devices, live sessions, alerts
GET  /admin/users                    list + search
POST /admin/users/invite             generate invite code
POST /admin/users/:id/suspend        step-up
POST /admin/users/:id/reactivate     step-up
DEL  /admin/users/:id                step-up
GET  /admin/users/:id/devices        device list
POST /admin/devices/:id/revoke       step-up
GET  /admin/devices/:id/audit        ciphertext + chain + checkpoint (decrypted in browser)
GET  /admin/sessions                 live sessions (metadata only)
POST /admin/sessions/:id/kill        step-up
POST /admin/keys/rotate              step-up
GET  /admin/usage                    TURN bandwidth
GET  /admin/actions                  admin's own action log
```

Every route requires a **live WebAuthn session belonging to a registered admin** — the `role` claim alone is never sufficient (§4.6) — plus a valid CSRF token on every non-`GET`.

**Serve the panel on a separate registrable domain, not `admin.example.com` (v4, §6.16).** v3's subdomain shares a registrable domain with the API, so `SameSite=Strict` does not treat them as different sites and an API-side XSS or open redirect can drive authenticated panel requests. A distinct domain, its own Caddy block, `__Host-` cookies, and IP-allowlisting available later without touching the API.

### 5.5 Untrusted input handling (closes §6.3)

Device labels, user display names, and invite notes are **attacker-controlled** and reach a browser tab that can unwrap audit keys.

- **Ingest allowlist:** `^[\p{L}\p{N} _\-]{1,32}$`, applied server-side at write time. Reject, do not sanitise.
- **Render as text nodes only.** Never inside an HTML attribute, never adjacent to an `hx-*` directive, never in a `hx-vals` payload.
- `htmx.config.allowEval = false` and `htmx.config.allowScriptTags = false`, set before htmx initialises.
- CSP: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`.
- CSRF token required on every state-changing request; `Origin` header checked server-side and mismatches rejected and logged (v4, §6.16).
- Even if all of the above fails, the `prf`-wrapped audit key means XSS steals a session, not a durable decryption capability.

**Accessibility of security-critical UI (v4, §6.35).** The 6-digit SAS, the consent prompt, and the `TRUNCATED` warning are all single-channel in v3 — large type and the colour red. A control nobody can perceive is a control that gets clicked through. The SAS is announced to screen readers digit by digit and available as audio on both devices; tamper and truncation warnings carry an icon and explicit text, never colour alone; the consent prompt is keyboard-reachable and never auto-focuses its Allow button.

---

## 6. Security review — findings and resolutions

An adversarial read of spec v2 produced 11 findings (§6.1–6.12), all resolved in v3. A **second review, of v3 itself**, produced 24 more (§6.13–6.36). Every finding is resolved, accepted, or downgraded to a documented limitation below, and folded into the phases.

The second round found a different *class* of problem than the first. Round one found flaws in security machinery. Round two found three things round one could not have: **components that do not work at all** (§6.13, §6.14), **a threat direction never modelled** (§6.17), and **a control that was notification pretending to be authorization** (§6.25). Worth remembering when you review the code — an adversarial reader checking whether a mitigation is *strong* will not notice that it is *absent*.

### 6.1 CI could sign a release *(critical → resolved)*

**Attack:** steal a GitHub Actions token → trigger a release workflow → CI calls cloud KMS to sign → every agent auto-updates to a backdoored build, signature valid.

**Resolution:** release signing moves **offline**. CI builds and produces artifacts plus a digest manifest; it has no signing credential of any kind. You sign the manifest on an air-gapped-ish workstation with a **YubiKey requiring physical touch**, then publish. Agents verify:

```
1. Ed25519 signature over the manifest, against the key compiled into the binary
2. Sigstore/Rekor inclusion proof for that digest (rogue signatures become public)
3. version > current_version  (downgrade refused)
4. rollout_cohort gate — staged 5% / 25% / 100% over 24h
```

All four must pass. Cloud KMS keeps its role for *TLS and token* keys only.

### 6.2 Elevation helper as a local privilege-escalation primitive *(critical → resolved)*

**Attack:** the Windows helper runs as SYSTEM behind a named pipe with default ACLs. Any local process — a sandboxed browser renderer, low-privilege malware — connects and injects synthetic input into the secure desktop to click "Yes" on a UAC prompt. This is exploitable with nobody connected remotely.

**Resolution:** the helper is authenticated at three layers.

- **Pipe ACL:** explicit SDDL granting only the agent's SID. `D:(A;;GA;;;<agent-sid>)(D;;GA;;;WD)`.
- **Peer verification:** `GetNamedPipeClientProcessId` → resolve image path → verify Authenticode chain to your signing certificate. Reject anything else.
- **Session binding:** the helper accepts input only while holding a capability token = `HMAC(noise_session_key, "input" || session_id || expiry)`, expiry measured on a monotonic clock (§4.13), handed over at session start and expiring with the session. **Outside an authorized session the helper is inert** — the escalation primitive does not exist when nobody is connected.
- Helper is a separate binary, under 500 lines, with no network code, reviewed line-by-line.

### 6.3 XSS in the panel steals the audit key *(critical → resolved)*

**Attack:** a paired user sets a device label to an htmx injection payload → admin opens the device list → payload reads the X25519 key sitting in JS memory → decrypts every user's audit log from the database.

**Resolution:** §5.5 in full, plus the structural fix in §6.8 — with `prf`-wrapped custody, JS memory never holds anything that survives the tab.

### 6.4 Forged mass revoke forces physical visits *(high → resolved)*

**Attack:** server compromise → forge `revoke_device` to every agent → each self-wipes → everyone must be physically at their laptop to re-enroll, which is exactly the outcome you said you never want.

**Resolution:** **self-wipe is removed from the protocol entirely.** Revocation is enforced purely by the server declining to relay, which needs no host cooperation. Hosts retain their keys and pairings; if a revocation is reversed, everything resumes automatically. `kill_session` remains — it is transient and self-healing.

### 6.5 QR screenshot during screen share *(high → resolved)*

**Attack:** victim opens the pairing QR while on a Zoom call or an existing remote session → attacker screenshots it, completes the handshake within 90s, labels the device "Ali's Pixel", and the victim confirms a device they were expecting.

**Resolution:** §4.3's short authenticated string, derived from the live handshake hash rather than the QR, plus refusal to display the QR while any capture source or session is active, plus demoting the attacker-controlled label beneath the six digits it cannot forge.

### 6.6 TURN → SSRF → VPS takeover *(high → resolved)*

**Attack:** valid TURN credentials → allocate a relay to `169.254.169.254` → read cloud instance metadata → IAM credentials → own the VPS, which is also the control plane and database.

**Resolution:** hardened `turnserver.conf`, verified by a test in CI:

```
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
no-multicast-peers
user-quota=6
total-quota=60
```

Plus: TURN on a **separate host** from the control plane, cloud metadata service set to IMDSv2-required (or disabled), and short-lived HMAC credentials issued per session by the control plane.

### 6.7 Audit tail truncation *(high → resolved)*

**Attack:** delete the last N rows for a device. The remaining chain verifies perfectly, because a hash chain cannot see what was cut from the end.

**Resolution:** signed head checkpoints in every heartbeat (§4.7). The panel compares the device-signed `max_seq` against stored entries and reports the shortfall.

### 6.8 Offline brute force of the audit passphrase *(high → resolved)*

**Attack:** dump the DB → guess passphrases → derive candidate keys via browser-grade Argon2 parameters → HPKE-open a known ciphertext to confirm → recover all logs offline on rented GPUs.

**Resolution:** the passphrase is gone. The X25519 key is random and wrapped by a key produced by the **WebAuthn `prf` extension** (§4.7). There is no guessable input anywhere in the chain, so the offline oracle has no target.

### 6.9 `uinput` as a Wayland sandbox escape *(medium → resolved)*

**Attack:** granting the user write access to `/dev/uinput` lets *any* process running as that user — a Flatpak app, a compromised browser — synthesize keystrokes, defeating Wayland's input isolation on a machine where tether is merely installed.

**Resolution:** mirror the Windows design. Input injection moves into a small **privileged systemd system unit** running as a dedicated `tether-input` user, with `DeviceAllow=/dev/uinput rw` and no other capabilities. The agent talks to it over a Unix socket; the helper checks `SO_PEERCRED`, verifies the peer's executable path via `/proc/<pid>/exe`, and requires the same session-bound capability token as §6.2. **No udev rule grants `/dev/uinput` to your login user.**

### 6.10 Compromised Android client *(accepted)*

Malware with an Accessibility Service can observe the decoded desktop and inject taps. StrongBox protects the key, not the rendering. Mitigations are partial — `FLAG_SECURE` on the session surface raises the bar against screenshots but not against Accessibility. Documented as an accepted risk and stated in the onboarding doc.

### 6.11 "Nothing but metadata" undersells it *(honesty fix)*

Session start/end times, durations, IPs, and byte counts across weeks form a behavioural profile: when someone is home, when they work, when they travel. Given §5.3's stance on not surveilling people, the onboarding doc says this plainly rather than implying metadata is harmless. Retention is capped: **90 days** for audit replicas on the server, after which the ciphertext is deleted. The host keeps its own copy as long as its owner wants.

### 6.12 Pattern worth noticing

Eight of eleven findings sat in components added to *protect* the system: the update channel, the elevation helper, the panel, the revoke command, the audit log, the audit encryption. Security machinery is privileged by definition, so bugs there are worth more than bugs in feature code. **Re-run this review at the end of every phase, against the code rather than the spec.**

---

## 6A. Second review — v3 findings and resolutions

### 6.13 The Windows agent as specified cannot capture the screen *(critical → resolved)*

**Finding:** Phase 2 says "Windows Service via `windows-service`" and "run unprivileged." Services run in session 0; DXGI Desktop Duplication requires a process in the interactive session with an open desktop handle. Session 0 duplication returns nothing. This is not a weakness — the specified program does not function.

**Resolution:** the broker/worker split in §4.10. A minimal SYSTEM broker launches an unprivileged per-session worker via `CreateProcessAsUser` and handles `WTS_SESSION_*` events. The privileged component holds no keys and touches no network. T8's intent survives: the thing with the framebuffer and the socket is still unprivileged.

### 6.14 The `elevate` capability is unimplementable *(critical → capability removed)*

**Finding:** §4.5 lists `elevate`, and §6.2 builds an entire authenticated helper around it. But UAC renders on the **secure desktop**, which Desktop Duplication cannot capture and which a user-session `SendInput` cannot reach. The remote user would see a black screen at precisely the moment they need to click Yes. Reaching it requires SYSTEM plus `SetThreadDesktop(OpenInputDesktop())` — the exact primitive §6.2 exists to deny.

**Resolution:** **`elevate` is removed from the protocol**, consistent with rule 1 and with the v3 pattern of deleting capability rather than gating it. When a UAC prompt appears the worker detects the desktop switch, and the remote user gets an explanatory overlay instead of a black rectangle. Someone physically present clicks it. The §6.2 helper remains for ordinary input injection, now with a strictly smaller job.

Note what this costs: remote software installation on Windows largely stops working. That is the honest price of not building a UAC-bypass primitive into family members' laptops.

### 6.15 Lock screen and login greeter are unreachable *(high → documented limitation)*

**Finding:** the Winlogon desktop is uncapturable from a user-session process; on Linux the GDM/SDDM greeter is a separate compositor no portal session can touch. So a remote reboot ends access until a human is present — and the Android action bar in Phase 6 has a Ctrl+Alt+Del button that can never work.

**Resolution:** stated as a hard limitation in §1 and in the onboarding doc rather than worked around, because every workaround is §6.14 again. Ctrl+Alt+Del is removed from the client UI. The agent shows "waiting for local sign-in" rather than a frozen frame, and reconnects automatically once a session exists.

### 6.16 `api.` and `admin.` are the same site *(critical → resolved)*

**Finding:** `SameSite` and cookie scoping operate on the **registrable domain**. `admin.example.com` and `api.example.com` are same-site, so an XSS or open redirect on the API vhost can issue cookie-bearing state-changing requests to the panel. §4.6 relied on `SameSite=Strict` as the CSRF control and specified no CSRF tokens at all.

**Resolution:** three layers — the panel moves to a **separate registrable domain**; cookies gain the `__Host-` prefix; and per-session CSRF tokens plus server-side `Origin` verification apply to every non-`GET`. §4.6, §5.4, §5.5.

### 6.17 A malicious host attacks the client *(high → resolved)*

**Finding:** the entire v3 threat model runs one direction. Nothing considers a hostile or compromised **host** attacking the **phone**. But the host chooses every byte of H.264 fed to the phone's vendor `MediaCodec`, which is among the most productive Android RCE surfaces of the last decade, and it chooses inbound clipboard and file content too.

**Resolution:** T25 and §4.12 — dimension and NAL caps enforced before the decoder, SPS/PPS bounds checking, out-of-process decode where practical, text-only size-capped clipboard, confined and MotW-marked file writes. The host applies symmetric validation to everything arriving from the client.

### 6.18 Hostile pairing QR *(high → resolved)*

**Finding:** `relay_hint` is attacker-controlled and unvalidated. Anyone can print a QR; a user who scans one is pointed at an attacker-chosen relay and hands over their device public key before any human check occurs.

**Resolution:** §4.3 step 3b — `relay_hint` validated against a compiled-in allowlist of your own relays, and an explicit phone-side confirmation naming the host before the handshake starts.

### 6.19 The signing key for server-originated commands was never defined *(high → resolved)*

**Finding:** §5.1 says "signed kill command" and Phase 4 calls `kill_session` and `revoke_device` the only two commands the agent obeys — without stating which key signs them, where it lives, or how it rotates. This is a hole in the one place the agent *does* accept server instruction.

**Resolution:** §4.1 — the pinned Ed25519 server identity key, with the consequence stated openly: a compromised control plane can kill sessions and refuse to relay, which is the denial of service §2 already accepts. No other message type is signed, and therefore no other message type is obeyed.

### 6.20 No pinning of the control plane's TLS identity *(medium → resolved)*

**Finding:** agents trusted the public CA system. A DNS hijack or one mis-issued certificate yields tokens, device metadata, and a hostile JWKS. Noise protects session content, so this is not catastrophic — but it is free to fix.

**Resolution:** SPKI pinning with a backup pin, plus the pinned server identity key above. §4.1.

### 6.21 The SFrame key schedule invites nonce reuse *(critical → resolved)*

**Finding:** "HKDF-BLAKE2s over the Noise session hash" is one line where five are needed. No per-direction keys, no nonce construction, no replay window, no rekey trigger. RTP guarantees reordering and loss, and ChaCha20-Poly1305 nonce reuse loses confidentiality *and* authenticity. A single key used in both directions plus a relay that can loop a packet is nonce reuse by construction.

**Resolution:** the full schedule in §4.4 — separate keys and salts per direction, explicit 48-bit counter in the frame header rather than inferred from relay-controlled RTP sequencing, 64-frame replay window, epoch-based rekey at 2^32 frames or 12 hours.

### 6.22 Wall-clock expiry is locally manipulable *(medium → resolved)*

**Finding:** pairing TTL, capability tokens, idle timeout, and consent timeout are all clock-dependent. A local attacker who moves the system clock extends the §6.2 capability token past the session that authorized it.

**Resolution:** §4.13 — monotonic clocks for every local expiry, wall-clock only for JWT verification, `seq` rather than `ts` as the audit ordering authority.

### 6.23 Backup restore silently rolls back revocation *(medium → resolved)*

**Finding:** the daily `pg_dump` restore reinstates revoked devices, unrevoked refresh-token families, and un-suspended users, with no signal that it happened. Also, v3 never says where the `age` encryption key lives.

**Resolution:** a **monotonic revocation epoch**, incremented on every revoke or suspend, checked at control-plane startup against a value stored outside the main database. A restore that lowers the epoch refuses to serve and alerts. The `age` key lives on the same offline hardware as the release key.

### 6.24 No protocol version floor *(medium → resolved)*

**Finding:** the wire protocol is versioned with `v`, but nothing prevents negotiating down to v1 semantics after a v2 fix. Versioning without a floor is a downgrade oracle.

**Resolution:** compiled-in `MIN_PROTOCOL_VERSION`, refuse below it, no negotiation path. §4.1.

### 6.25 Access was unattended by default — notification masquerading as consent *(high → resolved)*

**Finding, and the most important one in this round:** in v3, pairing granted `view` and `control` permanently. Every control in §4.8 — the border, the tray icon, the toast — is a *notification*. None is an *authorization*. A paired device could connect at any time, to anyone, and the host user's only recourse was to notice and hit the kill switch afterwards.

§13 states the goal as trust that is *justified rather than merely given*. A design where the remote party unilaterally decides when to look does not meet that standard, and the gap survived the entire v3 review because every individual control was well built. The question "is this control strong?" was asked repeatedly. "Is this control the right *kind* of control?" was not.

**Resolution:** §4.9 and the new `connect` capability — per-connection consent on the host by default, with unattended access available as an explicit per-device opt-in with an optional schedule, set locally and settable by no wire message. Rule 4 in §0.

### 6.26 Credential loss forces exactly the physical visits §6.4 prevents *(high → resolved)*

**Finding:** three ordinary events — lost phone, biometric re-enrolment invalidating the Keystore key, TPM clear or motherboard replacement — each leave the user with no recovery path except physical presence at every host. §6.4 removed self-wipe specifically to avoid that outcome, then the design reintroduced it through the front door.

**Resolution:** §4.11 — a host-registered backup credential (second device or printed 256-bit key), re-pairing through the same SAS flow, with a 24-hour delay and alerts on every other paired device during the window. Listed under accepted risks, because it is a real widening and pretending otherwise would be the dishonest choice.

### 6.27 No rollback path for a bad update *(medium → resolved)*

**Finding:** version monotonicity plus no remote reconfiguration plus staged rollout means a broken build reaching the 5% cohort strands those machines until someone reinstalls by hand. The safety property and the recovery property collide.

**Resolution:** a **signed rollback manifest** carrying its own epoch, naming the bad version explicitly. Agents accept a lower version number only when it arrives inside a rollback manifest with an epoch above the last one seen. Downgrade protection is preserved against replay, because a stale manifest fails the epoch check. Signing still requires the offline key — the panel only stages the request.

### 6.28 Pairings never expire *(low → resolved)*

**Finding:** a paired key is valid forever, with no reconfirmation and no visibility decay. Keys accumulate; a pairing nobody remembers granting is one nobody thinks to revoke.

**Resolution:** optional per-pairing expiry, and any key unused for 90 days flagged for reconfirmation before its next session. §4.3.

### 6.29 Session concurrency undefined *(low → resolved)*

**Finding:** nothing in v3 says whether two devices can hold sessions to one host simultaneously. Undefined concurrency around input injection and capture state is where race conditions live.

**Resolution:** **one active session per host by default.** A second `connect_request` while a session is live surfaces on the host as a prompt naming both devices, and is denied by default. Concurrent sessions are a host-side opt-in.

### 6.30 Server logs die with the server *(medium → resolved)*

**Finding:** T1 assumes full compromise of the VPS. Control-plane and TURN logs stored on that VPS are erased by the same event they exist to evidence.

**Resolution:** near-real-time log shipping to append-only object storage in a separate account with its own credentials. §3, Phase 1.

### 6.31 PID reuse race in helper peer verification *(low → resolved)*

**Finding:** `GetNamedPipeClientProcessId` → resolve image path → verify Authenticode has a small window in which the connecting PID is recycled between the call and the check. Same shape on Linux with `SO_PEERCRED` and `/proc/<pid>/exe`.

**Resolution:** compare **process creation time** alongside the PID on Windows, and on Linux verify the `/proc/<pid>` starttime field and hold an open handle to the peer's `/proc` entry across the check. Cheap, and it closes the window entirely. §6.2, §6.9.

### 6.32 Android manifest hardening unspecified *(low → resolved)*

**Finding:** Phase 6 specifies `FLAG_SECURE` and Keystore but nothing about the app's own attack surface.

**Resolution:** `android:allowBackup="false"`, `usesCleartextTraffic="false"`, no exported components, `android:exported="false"` on every activity and service that does not need otherwise, network security config pinning the control plane, and no debuggable release builds. Verified by a CI lint gate.

### 6.33 The pinned admin audit key cannot rotate *(medium → resolved)*

**Finding:** the admin X25519 public key is compiled into agent builds, and §6.4 removed remote reconfiguration. So a lost or compromised admin keypair meant every future audit entry was sealed to a key you no longer controlled, permanently, with no path back.

**Resolution:** agents pin an epoch-stamped **list** of accepted admin public keys, changeable only through the signed release channel. Rotation requires the offline YubiKey and a staged rollout. §4.7.

### 6.34 Recovery secret custody was ambiguous *(medium → resolved)*

**Finding:** v3 said to export "the wrapped key plus the 256-bit recovery secret" without stating whether the recovery secret unwraps anything. Read one way, losing both authenticators makes every audit log permanently unreadable. Read the other way, there is a second unwrap path that §6.8's analysis never considered.

**Resolution:** stated explicitly in §4.7 — the X25519 key is wrapped **three times independently** (authenticator A, authenticator B, recovery secret), any one opens it, and losing all three is an intended terminal failure. The recovery secret is 256 CSPRNG bits, never typed online, so it is a physical-custody problem rather than a brute-force one.

### 6.35 Security-critical UI is single-channel *(usability → resolved)*

**Finding:** the SAS is "large type," tamper warnings are "red," and the consent prompt is visual. A control that a colour-blind or low-vision user cannot perceive is a control that gets clicked through — and these are the controls the entire model rests on.

**Resolution:** §5.5 — screen-reader and audio rendering of the SAS on both devices, icon-plus-text for every tamper and truncation warning, keyboard-reachable consent prompt that never auto-focuses Allow.

### 6.36 H.264 Baseline profile is a needless bitrate tax *(low → resolved)*

**Finding:** Baseline omits CABAC, costing roughly 10–15% bitrate against a 2 Mbps ceiling on exactly the constrained links this project targets.

**Resolution:** **Main profile**, with Baseline retained as a negotiated fallback for any decoder that refuses. Every Android hardware decoder made this decade handles Main.

### 6.37 Pattern worth noticing, round two

§6.12 observed that eight of eleven v3 findings sat in components added to *protect* the system. Round two shows a second pattern, and it is the more uncomfortable one.

**The three worst findings here were not weak mitigations. They were absent ones.** §6.13 and §6.14 describe components that cannot work at all. §6.17 describes an entire threat direction never modelled. §6.25 describes a control that was well-built, well-reviewed, and the wrong kind of thing.

An adversarial reviewer asks "can I break this mitigation?" — a question that presupposes the mitigation exists and does what its name suggests. Both reviews were thorough; only the second asked whether the pieces were real. So the standing instruction from §6.12 gains a second half:

> Re-run this review at the end of every phase, against the code rather than the spec. **Then ask separately, for each control, whether it exists, whether it functions, and whether it is authorization or merely notification.** Build a demo of each control failing. A control you have never seen fail is a control you have never seen.

---

## 7. Phased build plan

Each phase has a hard exit criterion. Do not start the next until it is met.

### Phase 0 — Foundations

- Cargo workspace (`agent-core`, `agent-win`, `agent-linux`, `helper-win`, `helper-linux`, `proto`) + Go module (`control`, `admin`) + Gradle project (`android`).
- Cargo workspace gains **`broker-win`** (§4.10) alongside the existing crates.
- Wire protocol in **Protocol Buffers**, versioned with an explicit `v` field plus a compiled-in `MIN_PROTOCOL_VERSION` floor (§6.24). **Do not define grant, pair, wipe, elevate, or server-originated connect messages. Their absence is a security control** — say so in a comment so future-you does not helpfully add them.
  - *v4 clarification:* `connect_request` **does** exist — it travels peer-to-peer and is *answered by the host user* (§4.9). What does not exist is any message by which the **server or admin** initiates, approves, or observes a session. The distinction matters; write it in the comment.
  - `elevate` and its capability token are deleted outright (§6.14).
- CI: `cargo clippy -- -D warnings`, `cargo deny check`, `cargo fmt --check`, `govulncheck`, `gradle lint`, **Android manifest lint gate** (§6.32). Fail on any advisory. **CI holds no signing credential.**
- **Offline release signing set up first:** YubiKey with touch policy `always`, public half committed for pinning, Sigstore/cosign workflow documented and tested end-to-end on a dummy artifact. **Rollback-manifest format defined now** (§6.27) rather than retrofitted during an incident.
- Generate the **admin audit keypair** in-browser, random, wrapped **three ways** — authenticator A, authenticator B, and a 256-bit paper recovery secret (§6.34). Public half committed as the first entry in the agent's **epoch-stamped admin key list** (§6.33).
- Pin the **control-plane SPKI and server identity public key** into agent builds (§6.20).
- Write `THREAT-MODEL.md` from §2 and `SECURITY-REVIEW.md` from §6 and §6A.

**Exit:** CI produces reproducible unsigned artifacts; you sign one manually with the YubiKey; a stub agent verifies signature + Rekor proof + version monotonicity and rejects a deliberately downgraded build. Two builds of the same commit are byte-identical. **A rollback manifest with a stale epoch is rejected; one with a fresh epoch is accepted.** All three audit-key unwrap paths are exercised and proven independent.

### Phase 1 — Control plane

- `POST /v1/auth/register` (invite-gated), `/v1/auth/token`, `/v1/auth/refresh` with rotating opaque refresh tokens and reuse detection.
- `GET /.well-known/jwks.json`; `POST|GET /v1/devices` (public keys only).
- `WS /v1/signal` — relays **opaque** blobs between device IDs. The server must not parse the payload. Treat it as `[]byte`.
- Rate limiting per IP and per user; `slog` structured logs with no secrets or payloads.

- **Monotonic revocation epoch** (§6.23), incremented on every revoke or suspend, persisted outside the main database and checked at startup.
- **Server identity signing key** for `kill_session`, `revoke_device`, JWKS, and update manifests (§6.19). Separate from the offline release key.

Deploy:
- **Two VPS instances:** control plane + Postgres, and a separate TURN host (§6.6). Region close to your users — for Pakistan, Singapore or Dubai beats Frankfurt by a wide margin.
- Caddy, TLS 1.3 only, HSTS. **The panel gets its own registrable domain, not an `admin.` subdomain** (§6.16), with its own Caddy block and `__Host-` cookies.
- IMDSv2-required or metadata disabled on both instances.
- Daily `pg_dump` to object storage, encrypted with `age`; **the `age` key lives on offline hardware**, not on either VPS (§6.23).
- **Log shipping off-box** to append-only object storage under separate credentials (§6.30).
- Firewall: 443/tcp on control; 3478/udp+tcp and 49152–65535/udp on TURN only. SSH key-only, non-standard port, `PermitRootLogin no`, fail2ban.

**Exit:** two devices register, obtain tokens, and relay an arbitrary blob. Refresh reuse revokes the family, proven by test. **A CI test asserts coturn refuses to relay to `169.254.169.254` and to every RFC1918 range.** **Restoring yesterday's `pg_dump` after a revocation causes the control plane to refuse to serve and alert** (§6.23).

### Phase 2 — Host agent skeleton

- Device key into TPM/DPAPI (Windows), systemd-creds/keyring (Linux).
- Enrollment: invite code → register pubkey → tokens in OS credential store.
- Persistent WebSocket with exponential backoff + jitter.
- **Silent token refresh** on a background timer at 50% of TTL. If the chain genuinely breaks, the agent **stops connecting and shows a desktop notification to that machine's owner** — it does **not** wipe its keys (§6.4), and you are never in the loop.
- **Windows: the broker/worker split of §4.10** — SYSTEM service via `windows-service` that only launches and supervises an **unprivileged per-session worker**, plus full `WTS_SESSION_LOGON`/`LOGOFF`/`LOCK`/`UNLOCK`, fast-user-switching, and RDP-takeover handling. Build this now; retrofitting it after Phase 5 means rewriting the capture path (§6.13).
- Linux: systemd **user** unit. **Run unprivileged.**
- **SPKI pin + pinned server identity key verification** on every control-plane response (§6.20), and `MIN_PROTOCOL_VERSION` enforcement (§6.24).
- Config `0600` at `%PROGRAMDATA%\tether\` / `$XDG_CONFIG_HOME/tether/`. Single-instance lock, graceful shutdown, rotating logs.

**Exit:** survives reboot, network loss, and sleep/wake on both OSes; 72 hours continuous with silent refresh. No capture, input, or helper code compiled in. **On Windows: log out, switch users, lock, unlock, and take the session over via RDP — the broker relaunches a worker into the correct session every time.** A response signed by the wrong identity key is rejected.

### Phase 3 — Pairing, Noise, and the SAS

- QR generation with visible TTL countdown; **capture-active detection that suppresses the QR** (§4.3).
- Noise_IK via `snow` / `noise-java`.
- **Short authenticated string** computed from the handshake hash, displayed at 48px on both devices, with the claimed label demoted and marked unverified.
- **`relay_hint` allowlist validation and phone-side host confirmation** before the handshake (§6.18).
- **Backup credential registration** at pairing — second device or printed 256-bit key (§4.11).
- Local allowlist: SQLite `$DATA/peers.db`, `0600`, one row per key with capabilities, **access mode** (§4.9), optional expiry, and last-used timestamp. Host-side revocation UI.
- All pairing and token expiries on **monotonic clocks** (§4.13).
- SAS rendered for screen readers and available as audio (§6.35).

**Exit, five tests:**
1. Phone and laptop complete Noise_IK and exchange an encrypted echo.
2. **Modify your own signaling server to tamper with relayed bytes; the handshake must fail.** If it succeeds, stop — nothing after this matters.
3. **Screenshot the QR and race the victim from a second device; the two SAS codes must differ.**
4. **A QR carrying an unlisted `relay_hint` is refused by the phone before any handshake byte is sent.**
5. **Moving the host system clock forward does not extend a pairing token past 90 seconds.**

### Phase 4 — Admin panel

Deliberately before video: user management and the audit pipeline are far easier to get right while the system is simple, and every later phase then emits into a pipeline that already exists.

- WebAuthn registration/login, two authenticators, step-up per destructive op. **Middleware asserts the WebAuthn identity is a registered admin — never the `role` claim alone** (§4.6).
- **Served from a separate registrable domain with `__Host-` cookies, per-request CSRF tokens, and server-side `Origin` checks** (§6.16).
- `templ` + htmx, SSE for live lists. **§5.5 input handling enforced at ingest**, with an XSS test corpus in CI.
- All §5.4 routes; step-up enforced in middleware, not per-handler.
- **Epoch-stamped admin audit key list** and the rotation path through the release channel (§6.33).
- HPKE audit upload; server stores ciphertext + plaintext chain hashes + **signed checkpoints**.
- Client-side decryption via **WebAuthn `prf`** → HKDF → AES-GCM unwrap → HPKE open, memory-only.
- Chain **and checkpoint** verification with prominent tamper/truncation warnings.
- Admin action log, hash-chained.
- `kill_session` and `revoke_device` — the **only** two server-originated commands the agent obeys, both strictly restrictive and both reversible.
- Host transparency panel with working opt-out.

**Exit, two tests:**
1. Invite a user, they enroll, you see their device, you kill a session — all of it appears in a verifiable chain.
2. **Adversarial test:** with full database write access *and* a valid admin session, attempt to (a) reach a host you have not physically paired with, (b) forge an audit entry, (c) truncate a log undetected, (d) recover the audit key, **(e) approve a connection on a user's behalf or change a device's access mode, (f) drive a state-changing panel request from a page hosted on the API domain, (g) lower the revocation epoch by restoring a backup.** Document every avenue and why each failed. Any success stops the project until the protocol is fixed.

### Phase 5 — Video pipeline

- **Windows:** DXGI Desktop Duplication; handle `DXGI_ERROR_ACCESS_LOST` (resolution change, UAC, fullscreen switch, driver reset) by reinitialising. This will be most of your bug reports.
- **Linux:** `xdg-desktop-portal` ScreenCast → PipeWire; handle the permission dialog. X11 `XShm` fallback behind a flag.
- **Windows secure-desktop and lock handling:** detect the desktop switch and send an explanatory overlay rather than a black or frozen frame (§6.14, §6.15). Same for the greeter on Linux.
- **Encoding:** NVENC / QSV / VAAPI / AMF first, `openh264` fallback. **Main profile** with Baseline as a negotiated fallback (§6.36), low-latency preset, **no B-frames**.
- Adaptive bitrate from REMB/TWCC. Ceiling **2 Mbps**, floor 200 kbps.
- WebRTC with your STUN, hardened coturn fallback, short-lived HMAC credentials.
- **SFrame-style per-frame encryption implementing the full §4.4 key schedule** — per-direction keys, explicit header counter, replay window, epoch rekey. Do not improvise this part (§6.21).
- **mDNS ICE candidate obfuscation on; TURN-only for untrusted peers** (§4.4).

**Exit:** live video from Windows and Linux hosts across two genuinely different networks, sub-200ms glass-to-glass on P2P. `tcpdump` on the relay recovers no decodable frame. Host LAN IP absent from candidates in TURN-only mode. **A test reorders, duplicates, and drops encrypted frames and confirms no nonce is ever reused and every replay is dropped. Triggering a UAC prompt produces the overlay, not a black screen.**

**Expect this to overrun.** On carrier-grade NAT — common on Pakistani mobile networks — hole punching frequently fails and everything lands on TURN. Measure your real P2P rate; the Phase 4 bandwidth view is how you watch the cost.

### Phase 6 — Android client

- Keystore + StrongBox, `setUserAuthenticationRequired(true)`.
- CameraX + ML Kit QR scanner; **SAS confirmation screen** matching §4.3.
- WebRTC SDK, `MediaCodec` decode, `SurfaceView` (not `TextureView` — an extra copy per frame). `FLAG_SECURE` on the session activity.
- **Decoder input validation before every `MediaCodec` submission** — resolution caps, NAL size caps, SPS/PPS bounds checks — with out-of-process decode where practical (§4.12, §6.17).
- **Manifest hardening:** `allowBackup="false"`, `usesCleartextTraffic="false"`, no exported components, network security config pinning the control plane, no debuggable release builds (§6.32). CI lint gate.
- **Trackpad mode default.** Swipe = relative cursor, tap = left, two-finger tap = right, two-finger scroll, pinch to zoom viewport. Direct-touch available, off by default.
- Action bar: keyboard, sticky modifiers, mode switch, quality, disconnect. **No Ctrl+Alt+Del button — it cannot work** (§6.15); the app shows "waiting for local sign-in" when the host is at a greeter or lock screen.
- Mobile-data warning at session start with a hard-cap toggle; state the 0.5–2 GB/hour figure in the UI.
- Foreground service with persistent notification. Biometric prompt per connection.

**Exit:** open a file manager, type a path, launch an app on both hosts over mobile data without wanting to throw the phone.

### Phase 7 — Input injection (helper-isolated)

**Scope note:** with `elevate` removed (§6.14), the helpers inject ordinary input only. They never touch the secure desktop, and there is no code path that tries.

- **Windows helper:** separate SYSTEM binary, <500 lines, no network code. Pipe SDDL restricted to the agent SID; `GetNamedPipeClientProcessId` → image path → Authenticode verification, **plus process creation time compared to close the PID-reuse window** (§6.31); session-bound capability token (§6.2). Inert outside an authorized session.
- **Linux helper:** systemd **system** unit as user `tether-input`, `DeviceAllow=/dev/uinput rw`, `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateNetwork=yes`. Unix socket with `SO_PEERCRED` + `/proc/<pid>/exe` verification **+ `/proc/<pid>` starttime comparison with the handle held open across the check** (§6.31) + the same capability token. **No udev rule grants `/dev/uinput` to your login user** (§6.9).
- Capability token expiry on a **monotonic clock** (§4.13).
- Send **hardware scancodes**, not characters — otherwise Urdu, German, and French layouts break three different ways.
- Monotonic sequence numbers; drop out-of-order and replayed events. Inbound rate cap ~500/sec.

**Exit:** full control on both platforms including modifiers and a non-US layout. **Plus: a local unprivileged process attempting to drive either helper directly is rejected, and the attempt is logged.**

### Phase 8 — Hardening

- **The §4.9 consent gate: per-connection prompt, three access modes, 60s deny-by-default timeout.** This is the largest single item in the phase and the one that closes §6.25. Ship it before anything else here.
- **Backup credential flow** (§4.11): registration, re-pair via SAS, 24-hour delay, alerts on every other paired device during the window.
- **One active session per host by default**, with a naming prompt for a second concurrent request (§6.29).
- Pairing expiry and 90-day reconfirmation flagging (§6.28).
- On-screen indicator, tray icon, session-start notification. **Unattended sessions are visually distinct from attended ones.**
- Global-hotkey kill switch.
- Host-side hash-chained append-only log with filesystem enforcement; signed checkpoints. Ordering by `seq`, with backwards-moving `ts` flagged (§4.13).
- Transparency panel with working opt-out, showing the current access mode and any registered backup credential.
- Capability enforcement **before** parsing a gated message body.
- Idle timeout with biometric re-auth.
- **Accessibility pass on every security-critical control** (§6.35): screen-reader SAS, icon-plus-text warnings, keyboard-reachable consent prompt with no auto-focused Allow.
- **Fuzzing:** `cargo-fuzz` on every protobuf decoder, the Noise parser, the HPKE path, and **both helper IPC parsers**. ≥24 CPU-hours each.
- Windows: CFG, ASLR, DEP. Linux: full RELRO, PIE, stack protector, seccomp-bpf on the agent.

**Exit:** a written self-review walking every row in §2 and every finding in **§6 and §6A**, stating how each is handled. Anything unhandled moves to accepted risks with a reason. **Then run the §6.37 second pass: for each control, demonstrate it failing.** A mitigation you have never watched fail is a mitigation you have not tested.

### Phase 9 — Convenience features

Only after Phase 8. Each is new attack surface, so each ships **off by default** with per-session grant and an audit entry: file transfer (chunked, path-traversal validated, size caps, confined destination, **Mark-of-the-Web applied on Windows and never an execute bit on Linux**) · clipboard sync (size-capped, text-only — image clipboard is a decompression-bomb vector) · multi-monitor selection · audio (Opus) · quality presets.

**Validation is symmetric** (§4.12). Every one of these carries data in both directions, and the client must distrust the host exactly as much as the host distrusts the client.

### Phase 10 — Distribution

- Windows MSI via `cargo-wix`, EV code-signing certificate (~$300–400/year; an OV cert means months of SmartScreen purgatory).
- Linux `.deb` + `.rpm` or Flatpak, signed repo metadata.
- Android signed APK; direct distribution or a private Play track beats public listing, since Play's review of remote-control apps is slow and will ask pointed questions about consent UX. Phases 4 and 8 are the answer.
- **Auto-update:** all four checks from §6.1 — embedded-key signature, Rekor inclusion proof, version monotonicity, staged rollout cohort — **plus the rollback-manifest path of §6.27**, which is the only way a lower version is ever accepted.
- Reproducible builds documented so a third party can verify binaries against source.
- **Onboarding doc** for family and friends: what the app can see, what you as admin can and cannot do, that metadata is a behavioural profile (§6.11), that a compromised phone defeats the model (§6.10), how to read the transparency panel, how to opt out. **Added in v4:** how the consent prompt works and why "always allow" is a real decision (§4.9); that there is no access to the lock screen or UAC and what that means in practice (§6.15); what a backup credential is and where to store it (§4.11); that the person on the other end cannot connect without them saying yes, unless they have chosen otherwise. Write it honestly — people agreeing to install remote-control software deserve to understand exactly what they are agreeing to.

---

## 8. Testing strategy

| Layer | Approach |
|---|---|
| Crypto | Noise spec vectors; property tests on the handshake state machine; RFC 9180 HPKE vectors |
| Protocol | `cargo-fuzz` on all decoders + both helper IPC parsers; malformed corpus in-repo |
| MITM resistance | Hostile signaling server in the test suite that tampers, reorders, drops, replays |
| **Pairing** | Screenshot-and-race simulation asserting SAS divergence; QR suppression while capture is active |
| **Admin containment** | Forged server messages asserting `grant_capability`, `add_peer`, `start_session`, `wipe` are dropped and logged |
| **Audit integrity** | Mutate ciphertext, delete a `seq`, reorder, **truncate the tail** — every case flagged |
| **Helper isolation** | Unprivileged local process attempts to drive both helpers; expired and forged capability tokens rejected |
| **TURN** | Relay attempts to metadata IP and every RFC1918 range must fail |
| **Panel** | XSS corpus in device labels; CSP violation reporting; `prf` unwrap failure paths |
| Auth | `alg=none`, `alg` confusion, expired, wrong `aud`, unknown `kid`, refresh reuse, admin route without WebAuthn |
| **Update** | Downgrade attempt, missing Rekor proof, valid signature with wrong embedded key — all rejected. **Rollback manifest: stale epoch rejected, fresh epoch accepted, replay of a used manifest rejected** |
| Capture | Windows: resolution change, UAC, fullscreen, driver reset, monitor hotplug, RDP takeover. Linux: X11 + Wayland, portal denial, multi-monitor |
| **Windows sessions** | Logon, logoff, lock, unlock, fast user switching, RDP takeover, worker crash — broker relaunches into the correct session every time (§6.13) |
| **Media crypto** | Reorder, duplicate, drop, and replay encrypted frames; assert no nonce reuse, replay window holds, epoch rekey is clean (§6.21) |
| **Consent gate** | Connect with each access mode; timeout defaults to deny; unattended window boundaries; peer-supplied label never displayed in the prompt (§6.25) |
| **Hostile host → client** | Oversized NALs, SPS declaring absurd dimensions, truncated frames, clipboard bombs, traversal paths in filenames — all rejected before the decoder or filesystem (§6.17) |
| **Pairing input** | Unlisted `relay_hint` refused before handshake; forged QR from an unknown host (§6.18) |
| **CSRF / origin** | State-changing panel request from the API origin and from a foreign origin, both rejected and logged (§6.16) |
| **Clock manipulation** | Move the system clock forward and backward; pairing tokens, capability tokens, consent timeouts, and idle timeouts all hold (§6.22) |
| **Backup/restore** | Restore a pre-revocation dump; control plane refuses to serve and alerts (§6.23) |
| **Recovery** | Each of the three audit-key unwrap paths independently; backup credential re-pair including the 24h delay and alerts (§6.26, §6.34) |
| **Helper PID race** | Rapid connect/exit loop attempting PID reuse against both helpers (§6.31) |
| Network | 5% loss, 300ms RTT, symmetric NAT via `tc netem`; TURN-only path |
| Client | Keystore auth flows, biometric enrollment invalidation, **manifest lint gate** |
| **Accessibility** | Screen-reader walkthrough of SAS, consent prompt, and tamper warnings; no control conveyed by colour alone (§6.35) |

---

## 9. Running costs

| Item | Estimate |
|---|---|
| VPS — control plane (2 vCPU / 4 GB) | $6–12/month |
| VPS — TURN, separate host (§6.6) | $5–8/month |
| TURN bandwidth (worst case) | $0–20/month |
| Audit storage (90-day retention) | negligible |
| **Two domains — API and panel, separate registrable domains (§6.16)** | **~$24/year** |
| **Off-box log storage, append-only (§6.30)** | **~$1–3/month** |
| Cloud KMS (TLS/token keys only) | ~$1–3/month |
| **Hardware keys — 2× WebAuthn + 1× release signing** | **~$75 one-off** |
| Windows EV code-signing cert | $300–400/year |
| **Total** | **~$17–50/month + ~$425 one-off** |

The second VPS is the price of finding 6.6. It is worth it — colocating TURN with your database means one SSRF bug costs you everything. The second domain is the price of finding 6.16, and at $12/year it is the cheapest security control in this document.

---

## 10. Timeline

| Phase | Effort | Change from v3 |
|---|---|---|
| 0 — Foundations (incl. offline signing) | 2 weeks | +0.5 — rollback format, key list, triple-wrap |
| 1 — Control plane + hardened TURN | 3 weeks | +0.5 — revocation epoch, second domain, log shipping |
| 2 — Agent skeleton | **3–3.5 weeks** | **+1–1.5 — broker/worker split and session handling (§6.13)** |
| 3 — Pairing + Noise + SAS | 3 weeks | +0.5 — relay validation, backup credential |
| 4 — Admin panel | **4 weeks** | +0.5 — CSRF, origin separation, key rotation |
| 5 — Video pipeline | **4–6 weeks** | unchanged, and still the one that overruns |
| 6 — Android client | 3.5–4.5 weeks | +0.5 — decoder hardening, manifest gate |
| 7 — Input injection + helpers | 2.5 weeks | **−0.5 — `elevate` removed (§6.14)** |
| 8 — Hardening | **4–5 weeks** | **+2 — consent gate, backup credential flow, accessibility** |
| 9 — Convenience | 2–3 weeks | unchanged |
| 10 — Distribution | 2–2.5 weeks | +0.5 — rollback path, expanded onboarding doc |
| **Total** | **8–10 months** | **+4–5 weeks** |

The v3 fixes added roughly three weeks; the v4 fixes add four to five more. Two things are worth noting about where that time goes.

**Phase 2 grew because §6.13 is architectural, not cosmetic.** Building the broker/worker split now costs a week; discovering it during Phase 5 costs the capture path.

**Phase 8 nearly doubled**, and that is the right shape. The consent gate is not a hardening detail bolted onto a finished system — it is the control that makes the difference between this and a RAT, per §0. If schedule pressure arrives, cut Phase 9 entirely before touching it.

Phase 5 still dominates and will still overrun. DXGI's failure modes, the Wayland portal permission model, and now Windows session-change handling are each a week of surprises on their own.

---

## 11. Milestones

- **Useful to you** — Phases 0–3, 5–7 (defer 4). Rough edges, no panel. You control your own laptop from your phone. ~5 months.
- **Manageable** — add Phase 4. You can invite people and oversee the system without touching their machines. ~6.5 months.
- **Shippable to family and friends** — Phases 0–10. Someone who is not you can install it unaided, and you would not be embarrassed if a security researcher read the code. ~8–10 months.

**One hard rule about ordering (v4).** The consent gate of §4.9 lands in Phase 8, which means Phases 5–7 produce a working system in which any paired device can connect at will. That is fine while you are the only user. **It is not fine the moment a second person installs it.** Do not hand this to anyone — not even someone who insists they do not mind — before Phase 8 ships. The whole argument of §13 depends on it.

Ship to yourself first, and run it as your daily driver for a full month before handing it to anyone. That month surfaces what no test suite catches.

---

## 12. Using something else in the meantime

None of this stops you using **Tailscale + RustDesk** today, and you should. Running a mature implementation of the thing you are building teaches you more about the requirements than any spec — including this one — and it keeps the project a learning exercise rather than a dependency, which is a much healthier place to build from.

---

## 13. A note on the people you invite

You are asking family and friends to install software that can see their screen and move their mouse. They will say yes because they trust you, not because they have evaluated the threat model. That trust is the real thing you are managing, and it is worth more than the code.

Everything restrictive here — the absent grant and wipe messages, the host-side allowlist, the narrow audit scope, the offline signing key, the removed elevation capability, the visible transparency panel, the working opt-out, and above all **the prompt that lets them say no every single time** — exists so their trust is *justified* rather than merely *given*. Keep it that way even when a shortcut would be convenient, and especially when nobody would notice.

**A closing note on v4.** The second review's most useful finding was not a cryptographic flaw. It was §6.25: v3 had a complete, well-argued, carefully-reviewed consent architecture in which the person being watched never actually got to decide. Every individual control was sound. The system still let the remote party choose when to look, and the reviews kept asking whether the controls were strong instead of whether they were the right kind of thing.

That failure mode does not announce itself, and it will not be the last time. When you review this code, ask of every protection: *does it exist, does it work, and does it authorize or merely inform?* The third question is the one that is easy to skip and expensive to get wrong.
