package dev.tether.client

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager

/**
 * The remote desktop surface. Phase 6.
 *
 * FLAG_SECURE is applied here rather than in Phase 6 because it is one line and it is the
 * kind of line that gets forgotten. It blocks screenshots and excludes the window from
 * non-secure displays.
 *
 * What it does NOT do, stated so no one later mistakes it for protection: it is no defence
 * against an Accessibility Service. Spec §6.10 documents malware holding one as an
 * ACCEPTED RISK - it can observe the decoded desktop and inject taps, and StrongBox
 * protects the key, not the rendering. There is no fix at this layer.
 */
class SessionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    }
}
