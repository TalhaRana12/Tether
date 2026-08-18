package dev.tether.client

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Foreground service holding a live session. Phase 6.
 *
 * `onBind` returns null deliberately: this service exposes no IPC surface. Combined with
 * android:exported="false" in the manifest, that means no other app on the device can
 * reach into the process holding the Keystore-backed device identity (HR-8.5, HR-4.4).
 *
 * KT-6 when the session logic arrives: idle timeout and every other local expiry use
 * SystemClock.elapsedRealtime(), never System.currentTimeMillis() - the wall clock is
 * user-settable on Android with no privilege at all (HR-6.1, T29).
 */
class SessionService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
}
