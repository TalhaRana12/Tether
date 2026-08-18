package dev.tether.client

import android.app.Application

/**
 * Phase 6 builds the real client. Present at Phase 0 so the manifest declares real
 * components and `internal/cigates` has something meaningful to check.
 *
 * KT-13, and it applies from the first line of Kotlin written here: never log session
 * content, decoded frames, clipboard contents, key material, or input events. Not at
 * DEBUG, not behind a build flag. HR-10.7's never-logged list has "no code path", and a
 * log statement is a code path.
 */
class TetherApplication : Application()
