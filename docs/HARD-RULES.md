# tether — HARD RULES

**Source:** `implementation-spec-v4.md` (spec revision v4)
**Status:** normative. Everything here is a constraint, not a suggestion.
**How to use:** paste into `CLAUDE.md` / agent context at the root of the repo. Every rule has an ID. Cite the ID in code comments, PR descriptions, and commit messages when a decision is driven by one.

> **Rule of interpretation** *(settled 2026-08-17, BLK-10)*. Where this document and any other document disagree, **this document wins — including on contracts.** Where this document is silent, do not infer — see Appendix A and stop.
>
> **And the condition that makes that safe:** any rule here that *deliberately* differs from `implementation-spec-v4.md` must **say so at the rule**, quoting what the spec says and why it is not being followed. Without that, a silent transcription slip becomes law and looks identical to a considered decision. HR-4.3 is the one current instance and carries its citation inline.
>
> A consequence worth stating, because it caused real gaps: **an omission here is not a decision.** Where this document simply failed to carry a value the spec fixed, that is a defect in this document, not licence to invent one. Seven such omissions were found and transcribed on 2026-08-17 — HR-2.10, HR-2.11, HR-2.12, HR-4.10, HR-8.6, HR-9.10, HR-11.7.

---

## 0. The four governing rules

These are the rules from which most of the others are derived. If a proposed change violates one of these, the change is wrong regardless of how convenient it is.

| ID | Rule |
|---|---|
| **HR-0.1** | **Admin operations are monotonically restrictive.** The panel can revoke, suspend, and kill. It can never grant, pair, or connect. The messages that would let an admin add themselves to someone's allowlist do not exist in the wire protocol — not disabled, not permission-gated, **absent**. |
| **HR-0.2** | **Nothing online can sign a release.** The release key is offline hardware requiring a physical touch. CI can build; only a human with the token can ship. |
| **HR-0.3** | **No secret is ever derivable from something guessable.** No passphrase-derived keys, anywhere. Every long-term secret lives in hardware (TPM, StrongBox, or a security key) or is 256 bits of CSPRNG output. |
| **HR-0.4** | **Pairing is not permission to connect.** A paired device may *request* a session. The host user decides, per connection, at the moment of connection. Unattended access is a deliberate opt-in the host user makes for a named device — never a side effect of having paired once. |

> **ZERO-BUDGET DEVIATION on HR-0.2, cited per the BLK-10 resolution. 2026-08-17.**
> No YubiKey is being bought. The release key instead lives in this machine's **TPM 2.0**
> as a non-exportable CNG key. Accounting, because "equivalent" would be false:
>
> | Property HR-0.2 buys | TPM substitute |
> |---|---|
> | CI cannot sign | **kept in full** — this is the AnyDesk control (spec §6.1) and it is free |
> | the key cannot be copied off the machine | **kept** — the TPM refuses to export it |
> | every signature needs a physical touch | **LOST.** A process running as you can sign. A TPM PIN adds a human step, but a PIN can be keylogged and replayed; a touch cannot |
>
> Consequence, and it binds: **do not distribute builds to anyone else** until the Phase 6
> Android client can hold the key in StrongBox behind a biometric, which restores the third
> property for free. HR-15.2 already forbids handing this to a second person before Phase 8;
> this is an independent second reason for the same line.
> Full analysis: [FREE-TIER-SUBSTITUTIONS.md](FREE-TIER-SUBSTITUTIONS.md) §4.

**HR-0.5 — The trust boundary runs in both directions.** Every byte crossing a session, in either direction, is untrusted input to whoever receives it. A compromised host attacking the phone is as much a threat as the reverse.

**HR-0.6 — The difference between this and a RAT is verifiable consent plus an audit trail the session cannot erase.** Any change that weakens either erases the difference.

---

## 1. Protocol absences — the "does not exist" list

**HR-1.1** The following have **no wire representation** in the protobuf schema. Not commented out, not feature-flagged, not permission-gated. Absent.

- `grant_capability` — or any message that modifies a host's capability table
- `add_peer` / any message that adds a key to a host allowlist
- `start_session` / `join_session` / `observe_session` — any server- or admin-originated session initiation
- `wipe` / `reset` / `reconfigure` — any host-side self-destruct or remote configuration
- `elevate` and its capability token — deleted outright (§6.14)
- any message that **approves a connection** on a user's behalf
- any message by which the **server or admin queries or sets** a device's access mode

  *Scope, because HR-1.1 and HR-9.8 previously disagreed on the verb.* The prohibition
  is on a **control-plane query or command**. It is not a claim that the access mode is
  invisible to an admin: HR-10.7 uploads `access_mode_changed`, so an admin who can
  unwrap the audit log learns of a change. That path is legitimate and different in
  kind — it is **host-originated**, one-way, HPKE-sealed, and severable by the host
  user at any time (HR-10.9). What must not exist is a message the *server* can send
  to read or set the mode, because that is the difference between a report the user
  controls and a capability the admin holds.
- any message that **sets or clears a backup credential**
- any message by which the panel or CI **signs** a release or rollback manifest

**HR-1.2** Their absence is a security control. Say so in a comment in the `.proto` file, naming this rule, so that a future contributor does not helpfully add them back.

**HR-1.3** `connect_request` **does** exist. It travels peer-to-peer and is answered by the host user (HR-2.1). What does not exist is any message by which the **server or admin** initiates, approves, or observes a session. Write that distinction in the comment too.

**HR-1.4** The agent obeys exactly **two** server-originated commands: `kill_session` and `revoke_device`. Both are strictly restrictive, both are reversible, and both are signed by the pinned Ed25519 server identity key. No other message type is signed, and therefore no other message type is obeyed.

**HR-1.5** The agent **rejects and logs any inbound message type it does not recognise**, and **never accepts an authorization decision from the control plane**. This is a required test, not an aspiration: feed the agent a forged but validly-signed server message asserting `grant_capability` and assert it is dropped and logged.

**HR-1.6** The wire protocol carries an explicit `v`. Each build compiles in `MIN_PROTOCOL_VERSION` and **refuses anything below it — no negotiation, no fallback path.**

**HR-1.7** Revocation is enforced **solely by the server declining to relay.** It requires no host cooperation. Hosts keep their keys and pairings; if a revocation is reversed, everything resumes automatically. There is no self-wipe.

---

## 2. Authorization and consent

**HR-2.1** Every session begins with a host-side decision. The sequence is fixed:

1. Paired device sends `connect_request { device_label, capabilities_wanted }`
2. Host raises a consent prompt **on the host**, showing the **verified local pairing name**, the peer key fingerprint (short form), and what is being requested. Options: *Allow once / Allow and remember / Deny / Deny and revoke*.
3. **No response within 60s → treated as Deny**, logged as `consent_timeout`.
4. **Only on Allow does the media path start.**

**HR-2.2** The device label shown in the prompt is the **locally-stored pairing name**, never the peer-supplied one. The peer-supplied label is never displayed in the consent prompt at all.

**HR-2.3** Access mode is one of three, is set **on the host by its owner**, is stored **only on the host**, and is settable by **no wire message**:

| Mode | Behaviour | Default |
|---|---|---|
| Ask every time | Prompt per connection | **yes** |
| Unattended window | No prompt inside a host-set schedule; prompt outside it | opt-in |
| Always allow | No prompt. Indicator, notification, and audit still mandatory | opt-in, discouraged |

**HR-2.4** Capability defaults are fixed:

| Capability | Default | Requires |
|---|---|---|
| `connect` | **denied** | per-connection consent, or a standing unattended grant |
| `view` | granted at pairing | an approved `connect` |
| `control` | granted at pairing | an approved `connect` |
| `clipboard_read` | **denied** | per-session opt-in on host |
| `clipboard_write` | **denied** | per-session opt-in on host |
| `file_transfer` | **denied** | per-session opt-in on host |
| `elevate` | **does not exist** | — |

**HR-2.5** Capability enforcement happens **before** parsing a gated message body, never after.

**HR-2.6** **One active session per host by default.** A second `connect_request` while a session is live surfaces a prompt naming both devices and is **denied by default**. Concurrent sessions are a host-side opt-in.

**HR-2.7** Revocation is immediate and local: delete the row, kill any live session bound to that key. The server and panel cannot read or modify this table.

**HR-2.8** Pairings are not immortal. Optional per-pairing expiry at creation; any key unused for **90 days** is flagged for reconfirmation before its next session.

**HR-2.9** Notification is not authorization. The on-screen border, tray icon, and toast are necessary and **not sufficient**. If a control only informs the host user after the fact, it does not satisfy any rule in this section.

> **HR-2.10 to HR-2.12 transcribe values fixed in spec §4.8 that this document previously
> omitted.** They are necessary-but-insufficient notification controls under HR-2.9, not
> authorizations — but their *parameters* are decided, and leaving them out of a normative
> document that says "where this document is silent, do not infer — stop" turned settled
> decisions into halts.

**HR-2.10 — Persistent session indicator.** During any session: a **3px accent border on all monitors**, a tray icon, and an OS notification **at session start naming the connecting device**. The name shown is the locally-stored pairing name (HR-2.2), never the peer-supplied one. Unattended sessions are **visually distinct** from attended ones.

**HR-2.11 — Kill switch.** A tray item **and** the global hotkey **`Ctrl+Alt+Shift+K`**. It terminates **all** sessions, not the focused one, and **requires explicit confirmation to resume**. Logged as `killswitch_triggered` (HR-10.7). It must work when the UI is unresponsive — that is why it is a global hotkey and not a button.

**HR-2.12 — Idle timeout.** **15 minutes** without input ends the session. Resuming requires **fresh biometric authentication**, not merely reconnecting. Measured on a monotonic clock (HR-6.1) — a local attacker who moves the wall clock must not be able to extend it.

---

## 3. Pairing and the short authenticated string

**HR-3.1** Pairing sequence is fixed:

1. Host checks whether any screen capture or tether session is active; if so, **refuses to display the QR** and explains why.
2. QR contains `{ v:1, host_id, host_pubkey (32B), pairing_token (16B), relay_hint }`.
3. Phone scans. The camera is the out-of-band channel.
4. Phone **validates `relay_hint` against a compiled-in allowlist** of your own relays and shows an explicit confirmation naming the host **before any handshake byte is sent**.
5. Phone opens Noise_IK using the scanned `host_pubkey` as the remote static key. The server only relays bytes.
6. Both devices compute `sas = BLAKE2s(handshake_hash || "tether-sas-v1")`; `code` = **first 20 bits**, rendered as **6 decimal digits**, displayed at 48px.
7. Human confirms **on the host**. Both sides persist the peer key. Pairing token is burned.

**HR-3.2** The SAS derives from the **live handshake**, not from the QR. This is the actual control; QR suppression is defence in depth.

**HR-3.3** The peer-claimed device label is rendered **small, muted, and explicitly marked unverified**, always beneath the six digits it cannot forge.

**HR-3.4** Capture-active detection is **best-effort, not a guarantee** — on Wayland the portal model prevents enumerating other capturers. Where the compositor exposes nothing, **the UI says so** rather than implying a check happened. Never present this check as a guarantee in copy, docs, or code comments.

**HR-3.5** Pairing tokens: **128-bit CSPRNG, 90-second TTL, single use, max 5 attempts per host per hour**, expiry measured on a **monotonic clock**.

**HR-3.6** There is no server-side path to add a key to a host allowlist. Pairing requires a human physically at that machine, or the registered backup credential (HR-4.7).

---

## 4. Cryptography and key custody

**HR-4.1** Fixed algorithm choices. Do not substitute:

| Purpose | Construction |
|---|---|
| E2E session | `Noise_IK_25519_ChaChaPoly_BLAKE2s`, **inside** DTLS 1.3 / SRTP |
| Audit sealing | HPKE (RFC 9180), anonymous mode, X25519 + ChaCha20-Poly1305 |
| Audit key wrap | WebAuthn `prf` → HKDF → AES-GCM key wrap |
| Tokens | EdDSA (Ed25519) via JWKS |
| Video | H.264 **Main** profile, Baseline as negotiated fallback only, no B-frames |

**HR-4.2** DTLS alone is insufficient — fingerprints are exchanged through the signaling server. Noise inside DTLS is mandatory, and its keys come from out-of-band pairing, not from anything the server touched.

**HR-4.3** Media encryption (SFrame-style, per-frame). The schedule is pinned:

> **DELIBERATE DEVIATION FROM THE SPEC — cited per the BLK-10 resolution.**
> `implementation-spec-v4.md` §4.4 specifies `salt = noise_handshake_hash`. **That is
> wrong and must not be implemented.** In the Noise specification the handshake hash
> `h` is explicitly **not secret**: it is derived from the protocol name, the static
> public keys, and the transmitted ciphertexts, every one of which a passive relay
> observes. If `h` is the only input to `HKDF-Extract`, the relay derives the media
> keys and the "relay CANNOT decrypt" property in §4.4's own diagram collapses,
> taking T1 and T2 with it. This rule requires **secret** Noise output instead — see
> Appendix A-1 for the exact input, which is still to be pinned (BLK-1).
>
> Using `h` for the **SAS** (HR-3.1 step 6) is correct and must not change. The SAS
> needs a value both ends can compute and an attacker cannot *predict*; it does not
> need secrecy, because it is compared by a human out of band.

```
base       = HKDF-Extract(salt = <secret noise output — see Appendix A-1>, ikm = "tether-media-v1")
key_h2c    = HKDF-Expand(base, "host-to-client-key",   32)
key_c2h    = HKDF-Expand(base, "client-to-host-key",   32)
salt_h2c   = HKDF-Expand(base, "host-to-client-salt",  12)
salt_c2h   = HKDF-Expand(base, "client-to-host-salt",  12)

per frame: ctr   = explicit 48-bit counter carried in the frame header
           nonce = salt XOR (epoch || ctr)
           aad   = frame header (epoch, ctr, keyframe flag)
```

- **HR-4.3a** Directional separation is **mandatory**. One key in both directions plus a relay that can loop a packet back is nonce reuse by construction.
- **HR-4.3b** The counter is **explicit in the frame header**, never inferred from the RTP sequence number. The relay controls RTP sequencing and must not be able to steer nonce selection.
- **HR-4.3c** Receiver keeps an RFC 3711-style **64-frame replay window** and drops anything outside it or already seen.
- **HR-4.3d** Rekey at **2^32 frames or 12 hours, whichever comes first**, by incrementing `epoch` and re-expanding from `base`.
- **HR-4.3e** Do not improvise any part of this. See **Appendix A-1** — the input to `HKDF-Extract` must be resolved before implementation.

**HR-4.4** Every host and phone holds a long-lived Ed25519 identity keypair. **Private keys never leave the device.**

- Windows host: CNG, TPM 2.0 via `NCRYPT_PLATFORM_KEY_STORAGE_PROVIDER`; fallback DPAPI `CurrentUser` + entropy blob.
- Linux host: `systemd-creds` (TPM2-sealed); fallback `0600` file under `$XDG_DATA_HOME/tether/` encrypted with a kernel-keyring key.
- Android: Keystore with **StrongBox** (`setIsStrongBoxBacked(true)`), TEE fallback, `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)`, `setInvalidatedByBiometricEnrollment(true)`.

**HR-4.5** The admin X25519 audit key is generated **randomly in-browser** and wrapped **three times independently**: authenticator A, authenticator B, and `HKDF(recovery_secret)` where `recovery_secret` is 256 CSPRNG bits rendered as mnemonic words and stored on paper offline. **Any one opens it. Losing all three is the intended terminal failure — there is no fourth copy anywhere.**

**HR-4.6** There is **no passphrase anywhere in the audit key chain**, so there is no offline brute-force target. Never reintroduce one, including "just for development".

**HR-4.7** At pairing time the host also registers a **backup credential** — a second paired device, or a printed 256-bit recovery key sealed into the host allowlist. Re-pairing via backup credential runs the **same Noise_IK handshake and the same 6-digit SAS**, plus: a mandatory **24-hour delay** before the new key is usable, and an alert on **every other paired device** and in the transparency panel throughout that window.

**HR-4.8** Agents pin an **epoch-stamped list** of accepted admin public keys, changeable only through the signed release channel. Hosts seal to the highest-epoch key they know and keep the previous key valid for exactly one release cycle.

**HR-4.10 — Media parameters (transcribed from spec §3 and Phase 5; previously omitted here).** H.264 **Main** profile, with Baseline as a **negotiated fallback only**. **No B-frames** — they add a frame of latency for a bitrate saving this project cannot spend. Adaptive bitrate from REMB/TWCC, **ceiling 2 Mbps, floor 200 kbps**. Hardware encode first (NVENC / QSV / VAAPI / AMF), `openh264` fallback.

**HR-4.9** Agents pin the control plane's **SPKI** (with a backup pin for the next rotation) **and** a **pinned Ed25519 server identity key**, both compiled into the binary. TLS is a transport convenience, not a trust anchor. Every control-plane response the agent acts on — JWKS, `kill_session`, `revoke_device`, update manifests — is verified against the pinned identity key.

---

## 5. Control-plane identity

**HR-5.1** Access token: JWT, EdDSA/Ed25519, TTL **10 minutes**. Claims: `sub`, `did`, `aud` (`tether-control`), `role`, `iss`, `exp`, `iat`, `jti`.

**HR-5.2** Refresh token: **opaque 256-bit random, never a JWT**, stored as an Argon2id hash, **rotating**. Presenting one twice revokes the whole family and notifies the user.

**HR-5.3** JWT verification, non-negotiable, in this order:

```
1. Fetch key by `kid` from cached JWKS. Unknown kid → refetch once, then reject.
2. Require alg == "EdDSA". NEVER read alg from the token header to select the algorithm.
3. Reject alg == "none" unconditionally.
4. Verify iss, aud, exp, nbf with ≤60s clock skew.
5. Check jti against a replay cache for the token's remaining TTL.
6. Admin endpoints additionally require a live WebAuthn session.
```

**HR-5.4** **The JWT authorizes you to the control plane. It does not authorize you to a host.** The host makes its own authorization decision, locally, against a list only it can modify. `role` is **advisory only** — a forged `role: admin` gets the panel, not a desktop.

**HR-5.5** JWKS rotation every 90 days: publish the new key **before** signing with it, with overlap ≥ 2× max token TTL; retire the old key once its tokens expire.

**HR-5.6** A **monotonic revocation epoch** is incremented on every revoke or suspend, persisted **outside the main database**, and checked at control-plane startup. A restore that lowers the epoch **refuses to serve and alerts**.

---

## 6. Clocks and expiry

**HR-6.1** **All local expiries use a monotonic clock** — `Instant` in Rust, `SystemClock.elapsedRealtime()` on Android. Never wall-clock. This covers pairing TTL, capability-token expiry, idle timeout, consent timeout, and unattended windows.

**HR-6.2** Wall-clock is used **only** for JWT `exp`/`nbf`, with the ≤60s skew allowance.

**HR-6.3** Audit ordering authority is **`seq` and the hash chain — never `ts`**. The panel orders by `seq` and flags any entry whose `ts` moves backwards relative to its predecessor.

---

## 7. Process and privilege model

**HR-7.1 — Windows.** A SYSTEM **broker** service and an unprivileged per-session **worker**:

- Broker: **no capture code, no input code, no session keys, no network code.** It launches the worker into the active console session via `CreateProcessAsUser`, handles `WTS_SESSION_LOGON/LOGOFF/LOCK/UNLOCK`, fast user switching, RDP takeover, and worker crash restart. Reviewed line-by-line.
- Worker: DXGI capture, encode, WebRTC, Noise, consent UI. **Unprivileged.** Holds all session keys. Dies with the session.

**HR-7.2 — Linux.** The agent is a systemd **user** unit, unprivileged, and dies with the session.

**HR-7.3 — Input helper.** Input injection is isolated in a small privileged helper — **separate binary, under 500 lines, no network code, reviewed line-by-line** — behind an authenticated local socket. Never a blanket device grant.

**HR-7.4 — Helper authentication, all four layers required:**

- **Windows:** pipe SDDL `D:(A;;GA;;;<agent-sid>)(D;;GA;;;WD)`; `GetNamedPipeClientProcessId` → resolve image path → verify Authenticode chain to your signing cert; **compare process creation time** alongside the PID.
- **Linux:** systemd **system** unit as user `tether-input`, `DeviceAllow=/dev/uinput rw`, `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateNetwork=yes`; Unix socket with `SO_PEERCRED` + `/proc/<pid>/exe` verification + **`/proc/<pid>` starttime comparison with the handle held open across the check**.
- **Both:** a session-bound capability token `HMAC(noise_session_key, "input" || session_id || expiry)`, expiry on a monotonic clock, handed over at session start.
- **Both: outside an authorized session the helper is inert.** The escalation primitive must not exist when nobody is connected.

**HR-7.5** **No udev rule grants `/dev/uinput` to the login user.** Ever. That is the Wayland sandbox escape the helper exists to prevent.

**HR-7.6** Input is sent as **hardware scancodes, not characters**. Monotonic sequence numbers; drop out-of-order and replayed events; inbound rate cap ~500/sec.

---

## 8. Untrusted input, both directions

**HR-8.1 — Before `MediaCodec` on the client:** enforce a compiled-in maximum resolution and maximum NAL unit size; reject SPS/PPS declaring dimensions outside the negotiated bounds; reject frames whose declared length exceeds the received buffer. **Decode in a separate process** where practical.

**HR-8.2 — Inbound clipboard, both directions:** text only, size-capped. No rich text, no images.

**HR-8.3 — Inbound files:** confined destination directory, path-traversal validated, size-capped. On Windows, written with **Mark-of-the-Web**. On Linux, **never an execute bit**.

**HR-8.4 — Symmetric.** The host applies the same parser hardening to input events and clipboard arriving from the client. The client distrusts the host exactly as much as the host distrusts the client.

**HR-8.6 — Mobile-data cost disclosure (transcribed from spec Phase 6; previously omitted here).** The client warns at session start when on mobile data, offers a **hard-cap toggle**, and **states the 0.5–2 GB/hour figure in the UI**. Not a security control, and included here for the same reason as HR-14.4: a user who agreed to something without being told its cost did not really agree. Withholding a number you know is a form of the dishonesty HR-3.4 forbids elsewhere.

**HR-8.5 — Android manifest:** `allowBackup="false"`, `usesCleartextTraffic="false"`, no exported components, `android:exported="false"` wherever possible, network security config pinning the control plane, no debuggable release builds. Enforced by a CI lint gate.

---

## 9. Admin panel

**HR-9.1** The panel is served from a **separate registrable domain** — not `admin.example.com`. `SameSite` and cookie scope operate on the registrable domain, so a subdomain leaves API-side XSS same-site with the panel.

**HR-9.2** **WebAuthn/passkey mandatory.** No password, TOTP, or magic-link fallback, in any environment. At least two authenticators registered. Break-glass is a **256-bit random recovery secret rendered as mnemonic words**, printed, stored physically — never a passphrase. Its use is audited and emails you.

> **Zero-budget note, 2026-08-17: this is NOT a deviation.** No security keys are being
> bought, and none are needed. **Windows Hello** (backed by this machine's TPM 2.0) and an
> **Android phone** passkey are both genuine, hardware-backed WebAuthn authenticators, and
> HR-9.2's own wording already contemplates a phone. Two caveats to hold: Windows Hello is
> bound to this laptop, so losing it loses that authenticator — which is exactly why HR-4.5
> keeps a **third**, paper wrap; and Android passkeys sync by default, so prefer a
> device-bound credential where the platform offers the choice. The prohibition on a
> password, TOTP, or magic-link fallback is **unchanged and absolute**.

**HR-9.3** Session cookie: `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite=Strict`, **30-minute TTL**, bound to a server-side record, invalidated on IP or User-Agent change.

**HR-9.4** **Per-session, per-request CSRF tokens** on every state-changing request, delivered via `hx-headers`, verified in middleware, plus server-side `Origin` checking with mismatches rejected **and logged**.

**HR-9.5** **The WebAuthn session is the authority, not the `role` claim.** Middleware asserts the authenticated credential belongs to a registered admin. `role: admin` alone is never sufficient for any route.

**HR-9.6** **Step-up reauth — a fresh WebAuthn assertion — for every destructive operation.** Enforced in middleware, not per-handler.

**HR-9.7** Untrusted strings (device labels, display names, invite notes):
- Ingest allowlist `^[\p{L}\p{N} _\-]{1,32}$`, applied **server-side at write time**. **Reject, do not sanitise.**
- Render as **text nodes only** — never in an HTML attribute, never adjacent to an `hx-*` directive, never in an `hx-vals` payload.
- `htmx.config.allowEval = false` and `htmx.config.allowScriptTags = false`, set **before** htmx initialises.
- CSP: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. No inline scripts, SRI on every asset, htmx and Tailwind served locally.

**HR-9.8** The panel **cannot**, by protocol: start/join/observe a session · add a key to any allowlist · grant or modify a capability · read or write files, clipboard, or screen content · change host settings · wipe or reconfigure a host · recover or export any private key · read audit entries its own hardware key cannot unwrap · approve a connection or change an access mode · set or clear a backup credential · sign a release or rollback manifest.

**HR-9.9** **Every admin operation reduces access. None expands it, and none is irreversible.** A new panel operation that fails this test does not ship.

**HR-9.10 — Enrollment limits (transcribed from spec §5.1; previously omitted here).** Invite codes are **single-use** with a **7-day TTL** and an optional device cap. Per-user device limit defaults to **3**. Both are access-control values, not preferences: an invite with no expiry is a credential left on the floor, and an unbounded device count makes "list devices per user" useless as a review surface.

---

## 10. Audit

**HR-10.1** Four properties must hold simultaneously: the admin can read it, the server cannot, nobody can forge it, and **nobody can silently truncate it**.

**HR-10.2** On the host (authoritative): append-only `$DATA/audit.jsonl`. Filesystem enforcement: `chattr +a` on Linux, ACL denying `DELETE` and `WRITE_DATA` on Windows. The host keeps full plaintext forever; the server's copy is a replica.

**Stored entry** (JSON, for humans — the host user reads this in the transparency panel, HR-10.9):

```
{ seq, ts, event, client_key_fp, client_ip, capabilities, detail, prev_hash, hash }
```

`detail` is a flat map of event-specific strings, drawn from a **closed set of keys per event type**. It exists because HR-10.7 requires `session_end` to record duration, bytes, and reason, and `session_start` to record transport, and the previous schema had nowhere to put them.

> **DELIBERATE DEVIATION FROM THE SPEC — cited per the BLK-10 resolution. Resolves BLK-13.**
> `implementation-spec-v4.md` §4.7 specifies `hash = BLAKE2s(prev_hash || canonical_json(entry_without_hash))`. **`canonical_json` is never defined** — not there, and previously not here. Key ordering, number formatting, unicode escaping, and whitespace are all left open, and the host writes this chain in **Rust** while the panel verifies it in **browser JavaScript**. Any disagreement makes an *intact* chain fail verification, which HR-10.4 renders as `TRUNCATED — N entries missing`: the tamper alarm firing on healthy data, which is how a real alarm comes to be ignored. A verifier made lenient to silence that noise would accept a *forged* entry instead.
>
> The chain hash therefore does **not** run over JSON. JSON is a format for *exchanging* data; a hash needs a format for *identifying* it.

**Chain hash** — over a length-prefixed binary encoding, fields in exactly this order:

```
hash = BLAKE2s(
    prev_hash                      32 bytes, raw
 || u64be(seq)
 || u64be(ts_unix_millis)
 || lp(event)                      UTF-8
 || client_key_fp                  32 bytes, raw
 || lp(client_ip)                  UTF-8, textual form
 || u32be(count(capabilities))
 || lp(capability) for each        ASCENDING by name  <-- see below
 || u32be(count(detail))
 || lp(key) || lp(value) for each  ASCENDING by key
)

lp(x) = u32be(byte_length(x)) || x
```

- **`lp()` on every variable-length field is the whole point.** Bare concatenation is ambiguous: `"ab"||"c"` and `"a"||"bc"` are byte-identical, so two different entries can share one hash. That is a forgery, and it is the same defect HR-7.4's token had (BLK-3).
- **Capabilities are sorted ascending, always.** A Rust `HashSet` randomises iteration order *per process*, so an unsorted list gives the same entry a different hash on every restart — indistinguishable from tampering.
- **Numbers in `detail` are decimal ASCII**, no sign for positives, no leading zeros, no exponent. Never a float.
- The same encoding covers HR-10.4's checkpoint. It has no JSON path either.

**HR-10.2a** Nothing in the chain hash may be computed by a JSON serialiser, in any language, for any reason. If you find yourself needing canonical JSON, you have reintroduced BLK-13.

**HR-10.3** Uploaded entries are HPKE-sealed to the admin public key. The host holds **no admin secret**. Server stores `(device_id, seq, prev_hash, hash, ciphertext)` — hashes in plaintext so the chain verifies without decryption. Batched every 60s; immediate for `session_start`, `session_end`, `capability_granted`.

**HR-10.4** Every heartbeat (30s) carries a **signed checkpoint** `sign_devicekey({device_id, max_seq, head_hash, ts})`, stored separately from entries. The panel compares checkpoint `max_seq` against the highest stored `seq` and renders any shortfall as **`TRUNCATED — N entries missing`**.

**HR-10.5** Server-side audit replica retention is capped at **90 days**. The host keeps its own copy as long as its owner wants.

**HR-10.6** Reading a device's audit log is itself an audited admin action.

**HR-10.7 — Audit scope is drawn at remote-access events only.**

*Logged:* `session_start` · `session_end` · `auth_failure` · `pairing_attempt` / `pairing_success` · `capability_granted` / `capability_denied` · `file_transfer` (direction, name, size) · `killswitch_triggered` · `agent_start` / `agent_stop` / `agent_update` · `audit_sharing_disabled` · `connect_requested` / `consent_granted` / `consent_denied` / `consent_timeout` · `access_mode_changed` · `unattended_session_start` (flagged distinctly) · `backup_credential_registered` / `backup_credential_used` · `repair_delay_started` · `helper_auth_failure` · `decoder_input_rejected`

*Never logged; **no code path exists**:* screen content or screenshots · keystrokes or keystroke counts · applications launched, window titles, focus history · browsing activity, URLs, locally opened files · any local (non-remote) computer usage · location beyond the routing IP · microphone, camera, or filesystem contents

**HR-10.8** If you are ever tempted to add an item from the second list, **that is the moment this stops being a remote-access tool and becomes monitoring software.** That sentence goes in the README.

**HR-10.9** The host transparency panel states plainly *"This device reports remote-access events to admin `<name>`"*, lists the exact event types uploaded, shows the last 50 entries in plaintext, shows the current access mode and any registered backup credential, and offers one-click **stop sharing** that severs upload without breaking the user's own access. Opting out appears in the panel as `audit: opted-out`, **never as silence**.

---

## 11. Infrastructure

**HR-11.1** TURN runs on a **separate host** from the control plane and database, with this configuration verified by a CI test:

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

Plus IMDSv2-required (or metadata disabled) on both instances, and short-lived HMAC TURN credentials issued per session by the control plane.

**HR-11.2** `WS /v1/signal` relays **opaque** blobs between device IDs. **The server must not parse the payload.** Treat it as `[]byte`.

**HR-11.3** Logs ship **off-box in near-real-time** to append-only object storage in a separate account with its own credentials. Logs stored on the VPS are erased by the same event they would have evidenced.

**HR-11.4** Daily `pg_dump` to object storage encrypted with `age`; **the `age` key lives on offline hardware**, not on either VPS.

**HR-11.5** Structured logs carry **no secrets and no payloads**.

**HR-11.6** ICE: mDNS candidate obfuscation always on. Peers not explicitly marked *trusted* on the host get **TURN-only**. Default trusted: none.

**HR-11.7 — Host firewall and SSH (transcribed from spec Phase 1; previously omitted here).** Control plane: **443/tcp only**. TURN host: **3478/udp+tcp and 49152–65535/udp only**. Both: SSH **key-only**, on a non-standard port, `PermitRootLogin no`, fail2ban. Deny-by-default inbound. HR-11.1 already requires TURN on a separate host; these are the rules that make "separate" mean something.

---

## 12. Release and update

**HR-12.1** **CI holds no signing credential of any kind.** CI builds and produces artifacts plus a digest manifest. A human signs the manifest on an air-gapped-ish workstation with a YubiKey whose touch policy is `always`.

**HR-12.2** Agents accept an update only when **all four** pass:

```
1. Ed25519 signature over the manifest, against the key compiled into the binary
2. Sigstore/Rekor inclusion proof for that digest
3. version > current_version   (downgrade refused)
4. rollout_cohort gate — staged 5% / 25% / 100% over 24h
```

**HR-12.3** A **lower version is accepted only inside a signed rollback manifest** carrying its own epoch above the last one seen, naming the bad version explicitly. Signing still requires the offline key — **the panel only stages the request**.

**HR-12.4** Cloud KMS is used for **TLS and token keys only**, never for release signing.

**HR-12.5** Builds are reproducible: two builds of the same commit are byte-identical, and the procedure is documented so a third party can verify binaries against source.

---

## 13. Accessibility of security-critical UI

**HR-13.1** The SAS, the consent prompt, and tamper/truncation warnings are the controls the entire model rests on. **A control nobody can perceive is a control that gets clicked through.**

**HR-13.2** The 6-digit SAS is announced to screen readers **digit by digit** and available as **audio on both devices**.

**HR-13.3** Tamper and truncation warnings carry an **icon plus explicit text**. Never colour alone.

**HR-13.4** The consent prompt is **keyboard-reachable and never auto-focuses its Allow button.**

---

## 14. Scope — never build these

**HR-14.1** Out of scope permanently: multi-tenancy, billing, org/team management · attended support flows (one-time codes for strangers) · iOS client, macOS host · low-latency gaming · Wake-on-LAN, remote printing, session recording · a **web client for sessions** (the panel is administration only and never renders a remote desktop) · **activity monitoring of any kind** · host-side remote wipe or remote configuration.

**HR-14.2** **No access to the Windows secure desktop (UAC), the Winlogon desktop, the lock screen, or the login greeter on either OS.** This is a hard limitation, stated as such, not worked around — every workaround requires exactly the SYSTEM-session input primitive the helper design exists to deny. Remote software installation on Windows largely stops working. That is the accepted price.

**HR-14.3** There is **no Ctrl+Alt+Del button** in the client UI. It cannot work. When the host is at a greeter or lock screen the client shows *"waiting for local sign-in"* and reconnects automatically once a session exists. The host sends an explanatory overlay, never a black or frozen frame.

**HR-14.4** Accepted risks are **documented in the onboarding doc, not hidden**: a fully compromised host OS defeats everything · a compromised Android client with an Accessibility Service can observe the decoded desktop and inject taps · traffic metadata is a behavioural profile over weeks · an admin can always refuse to relay · no lock screen / greeter / UAC access · the backup credential is a second key to the house · the host user can decline consent and defeat their own remote access.

**Added 2026-08-17 (zero-budget build):** · **the release signing key lives in a TPM on an online machine rather than on offline hardware with a touch policy**, so malware present while you are signing can sign things you did not intend. CI still cannot sign, and the key still cannot be exfiltrated — it is the per-signature physical act that is missing. This is why builds must not be distributed to anyone else until the Phase 6 StrongBox path restores it. See [FREE-TIER-SUBSTITUTIONS.md](FREE-TIER-SUBSTITUTIONS.md).

---

## 15. Process rules

**HR-15.1** **Each phase has a hard exit criterion. Do not start the next phase until it is met.** Exit criteria are tests that run, not judgements.

**HR-15.2** **Do not hand this to a second person before Phase 8 ships.** Phases 5–7 produce a working system in which any paired device can connect at will, because the consent gate lands in Phase 8. That is fine while you are the only user and unacceptable the moment anyone else installs it — including someone who insists they do not mind.

**HR-15.3** Ship to yourself first and run it as a daily driver for a full month before handing it to anyone.

**HR-15.4** If schedule pressure arrives, **cut Phase 9 (convenience features) entirely before touching Phase 8.**

**HR-15.5** Every Phase 9 feature ships **off by default**, with per-session grant and an audit entry.

**HR-15.6 — Review discipline, run at the end of every phase, against the code rather than the spec.** For each control, ask three separate questions:

> 1. **Does it exist?**
> 2. **Does it function?**
> 3. **Does it authorize, or does it merely inform?**

**Build a demo of each control failing. A control you have never seen fail is a control you have never seen.**

**HR-15.7** Bugs in security machinery are worth more than bugs in feature code — eight of eleven first-round findings and the three worst second-round findings sat in components added to *protect* the system. Weight review effort accordingly.

**HR-15.8** Any successful adversarial test — any path by which an admin or a compromised server reaches a host — **stops the project until the protocol is fixed.** Not the code: the protocol.

---

## Appendix A — Unresolved. Do not guess.

These are places where the spec is ambiguous, internally tense, or (in A-1) probably wrong. **Resolve each with the spec author before writing the code it affects.** Do not pick a plausible interpretation and continue.

**A-1 — Media key derivation input (blocks Phase 5, affects HR-4.3).**
§4.4 derives media keys from `noise_handshake_hash`. In the Noise specification the handshake hash `h` is explicitly **not secret** — it is computed from the protocol name, public keys, and transmitted ciphertexts, all of which a passive relay observes. If `h` is the only input to `HKDF-Extract`, the relay can derive the media keys and the entire "relay cannot decrypt" property collapses. The correct input is secret Noise output — the `CipherState` keys from `Split()`, or a proper Noise exporter over the chaining key `ck`. Using `h` for the **SAS** (§4.3) is correct and should not change; using it for **key material** should not stand. Pin the exact input before implementing.

**A-2 — `epoch` field width (blocks Phase 5).**
`nonce = salt XOR (epoch || ctr)` with a 12-byte salt and a 48-bit counter leaves 48 bits for `epoch`, but the width is never stated, nor the byte order of the concatenation. Pin both, and pin the frame-header wire layout alongside them.

**A-3 — Who holds `noise_session_key` for helper token verification (blocks Phase 7).**
HR-7.4's capability token is `HMAC(noise_session_key, ...)`, which the privileged helper must verify — so the helper needs that key or a derivation of it. That puts session-derived key material inside a SYSTEM process, in tension with the principle that privileged components hold no keys. Preferred resolution: the worker derives a dedicated `key_helper = HKDF-Expand(base, "helper-token", 32)` and hands **only that** to the helper at session start. Confirm before building. Also pin length-prefixed encoding for the HMAC input rather than bare concatenation.

**A-4 — Unattended access versus the lock screen (affects Phases 5, 8, and the onboarding doc).**
HR-2.3 offers unattended windows; HR-14.2 makes the lock screen uncapturable. A machine that is genuinely unattended is usually locked, so unattended access mostly resolves to *"connect to a machine that is logged in, unlocked, and unattended."* That is a much narrower feature than the onboarding doc will imply. Decide whether that is acceptable and **say so plainly in the onboarding copy** rather than letting users discover it.

**A-5 — Consent-prompt flooding (affects Phase 8).**
Nothing in §4.9 rate-limits `connect_request`. A paired device can generate prompts indefinitely, which is the MFA-fatigue shape: the goal is not to be allowed, it is to be annoying enough that someone taps Allow. Needs a per-device cooldown after a Deny, a cap on outstanding prompts, and probably an auto-quarantine after N consecutive denials.

**A-6 — "Delete user cascade-deletes audit replicas" (affects Phase 4).**
§5.1 gives the admin a one-click path to destroy server-side audit history, which sits awkwardly beside HR-9.9 ("none is irreversible") and HR-10.1 ("nobody can silently truncate it"). The host copy is authoritative and survives, so this is defensible — but it should be an explicit, separately-audited, step-up-gated operation with a stated retention tombstone, not a silent cascade.

**A-7 — `file_transfer` logs the filename (affects Phase 9).**
HR-10.7 logs file names while the never-logged list forbids "locally opened files". A filename is content-adjacent metadata about a user's machine. Decide: log direction and size only, or log the name and justify it explicitly in the transparency panel copy.

**A-8 — Where the revocation epoch lives (blocks Phase 1).**
HR-5.6 says "outside the main database" without saying where. It needs to be somewhere a `pg_dump` restore cannot roll back and a compromised control plane cannot lower.

**A-10 — RESOLVED 2026-08-17. `canonical_json` was never defined; the chain hash no longer uses JSON.** See **HR-10.2**, which now pins a length-prefixed binary encoding, sorted capabilities, an explicit `detail` map, and HR-10.2a forbidding any JSON serialiser in the hash path. Tracked and closed as BLK-13. Original statement of the problem, retained because the reasoning is the useful part:
HR-10.2 and spec §4.7 both specify `hash = BLAKE2s(prev_hash || canonical_json(entry_without_hash))`, and neither document says what canonical JSON *is* — key ordering, number formatting, unicode escaping, whitespace, or how absent fields are treated. The host writes the chain in Rust; the panel verifies it in browser JavaScript. Two serialisations that differ in any of those respects produce different hashes, so an intact chain fails verification and HR-10.4 renders it as **`TRUNCATED — N entries missing`**: the tamper alarm firing on healthy data, which is how a real alarm gets ignored. The same undefined operation is signed in HR-10.4's checkpoint. Related and unresolved with it: the fixed entry schema has **no field** for what HR-10.7 requires — `session_end`'s duration, bytes, and reason, or `session_start`'s transport. Adding one changes the hash input, so the shape must be pinned before Phase 8 writes the first entry.

**A-9 — WebAuthn RP ID after the domain split (affects Phase 4).**
Moving the panel to a separate registrable domain (HR-9.1) binds every WebAuthn credential to that domain. Choose the panel domain **before** registering any authenticator; changing it later invalidates every passkey and forces the break-glass path.

---

## Appendix B — Pre-merge self-check

Run this against every PR that touches the agent, the protocol, or the panel.

1. Does this add a wire message that grants, pairs, connects, approves, or configures? → **stop** (HR-0.1, HR-1.1).
2. Does this let anything online sign anything shippable? → **stop** (HR-0.2).
3. Does this introduce a secret derived from a passphrase, PIN, or user-chosen string? → **stop** (HR-0.3).
4. Does this let a paired device start a session without a host-side decision? → **stop** (HR-0.4).
5. Does this treat data from the other end of the session as trusted? → **stop** (HR-0.5).
6. Does this use a wall clock for a local expiry? → **stop** (HR-6.1).
7. Does this put keys, network code, capture code, or input code in a privileged process? → **stop** (HR-7.1, HR-7.3).
8. Does this log anything on the never-logged list, or add a code path that could? → **stop** (HR-10.7).
9. Is the new control an authorization, or is it a notification wearing an authorization's name? → **answer out loud** (HR-15.6).
10. Have you watched it fail? → if no, it is untested (HR-15.6).
