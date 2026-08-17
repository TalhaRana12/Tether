# Kotlin / Android hard rules — tether

**Binding at every gate** ([implementation-workflow.md §8](../implementation-workflow.md)). Stable IDs.
**MUST** blocks merge. **SHOULD** needs a one-line justification. Break either only with a
`WAIVER KT-<n>: <reason>` comment at the site plus the same line in the pull request.

Created 2026-08-17 per the BLK-11 resolution, option C: **seeded, not comprehensive.** No Kotlin exists
yet — the Android client is spec Phase 6 — so these are the rules the spec already fixes, written down
now so Phase 6 starts from them rather than discovering them.

The framing that matters for this file: **the client must defend itself against the host.** Spec §6.17
found that v3's entire threat model ran one direction. The host chooses every byte of H.264 fed to a
vendor `MediaCodec`, historically one of the most productive Android RCE surfaces there is.

---

## Decoder input — the highest-value rule in this file

**KT-1 (MUST)** Before **every** `MediaCodec` submission: enforce a compiled-in maximum resolution and
maximum NAL unit size; reject SPS/PPS declaring dimensions outside the negotiated bounds; reject any
frame whose declared length exceeds the received buffer.
*Why:* HR-8.1, T25. The vendor decoder is not our code and cannot be fixed by us.

**KT-2 (SHOULD)** Decode in a **separate process** where practical, so a decoder crash is a reconnect
rather than a compromise of the process holding the Keystore-backed identity key.
*Why:* HR-8.1. `SHOULD` rather than `MUST` because the spec says "where practical"; a justification is
required either way.

**KT-3 (MUST)** No inbound frame, clipboard payload, or filename from the host is trusted. Clipboard is
text only and size-capped; no rich text, no images. Filenames are path-traversal validated against a
confined destination directory.
*Why:* HR-8.2, HR-8.3, HR-8.4.

## Keystore and identity

**KT-4 (MUST)** The device identity key is generated in the Keystore with `setIsStrongBoxBacked(true)`
(TEE fallback permitted), `setUserAuthenticationRequired(true)`,
`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)`, and
`setInvalidatedByBiometricEnrollment(true)`.
*Why:* HR-4.4, T3. The last flag is the deliberate one: a coerced new fingerprint **destroys** the key
rather than unlocking it.

**KT-5 (MUST)** The private key never leaves the Keystore. No export, no backup, no copy into
application memory — not for testing, not behind a debug flag.

## Time

**KT-6 (MUST)** Local expiry uses `SystemClock.elapsedRealtime()`. Never `System.currentTimeMillis()`,
never `Date`, never `Instant.now()`.
*Why:* HR-6.1, T29. Wall clock is user-settable on Android with no privilege at all.

## Manifest and app surface

**KT-7 (MUST)** `android:allowBackup="false"`, `android:usesCleartextTraffic="false"`, no exported
components, `android:exported="false"` on every activity and service that does not require otherwise, a
network security config pinning the control plane, and no `android:debuggable` in a release build.
*Why:* HR-8.5, §6.32. Enforced by a CI lint gate, not by review.

**KT-8 (MUST)** `FLAG_SECURE` on the session activity.
*Why:* raises the bar against screenshots. Note honestly what it does **not** do: it is no defence
against an Accessibility Service, which is a documented accepted risk (§6.10) and must not be described
in code comments or UI copy as though it were protection.

## Session UI

**KT-9 (MUST)** No Ctrl+Alt+Del control anywhere in the UI. When the host is at a greeter or lock
screen the app shows *"waiting for local sign-in"* and reconnects automatically.
*Why:* HR-14.3. It cannot work, and a button that cannot work is worse than an absent one.

**KT-10 (MUST)** The 6-digit SAS is announced to screen readers **digit by digit** and available as
audio. Tamper and truncation warnings carry an icon **and** explicit text, never colour alone.
*Why:* HR-13.1 — a control nobody can perceive is a control that gets clicked through, and the SAS is
the control the entire pairing model rests on.

**KT-11 (MUST)** `SurfaceView`, not `TextureView`, for the session surface.
*Why:* spec §3 — `TextureView` costs an extra copy per frame.

**KT-12 (MUST)** The mobile-data warning at session start states the **0.5–2 GB/hour** figure and offers
a hard-cap toggle.
*Why:* HR-8.6. A user who agreed without being told the cost did not really agree.

## Logging

**KT-13 (MUST)** Never log session content, decoded frame data, clipboard contents, key material, or
input events. Not at `DEBUG`, not behind a build flag.
*Why:* HR-10.7's never-logged list has **no code path**, and a log statement is a code path.

## Coroutines and errors

**KT-14 (MUST)** No `GlobalScope`. Every coroutine is scoped to a lifecycle that ends with the session,
so a torn-down session cannot leave work running that still holds a key reference.

**KT-15 (MUST)** No empty `catch` blocks. Handle, rethrow with context, or comment why the exception is
safe to drop.

**KT-16 (MUST)** No `!!`. If a value can be null, handle it; if it cannot, restructure so the type says so.

---

## Waiver format

```kotlin
// WAIVER KT-2: single-process decode for the first Phase 6 milestone; out-of-process
// decode tracked for the hardening pass. Input validation of KT-1 is fully applied.
codec.queueInputBuffer(...)
```

The identical line goes in the pull request description.
