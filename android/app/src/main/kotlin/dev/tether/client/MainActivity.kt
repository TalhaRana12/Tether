package dev.tether.client

import android.app.Activity

/**
 * Pairing and device list. Phase 6.
 *
 * Two rules land here when it is built:
 *   KT-10 the 6-digit SAS is announced to screen readers digit by digit and available as
 *         audio. HR-13.1: a control nobody can perceive is a control that gets clicked
 *         through, and the SAS is what the entire pairing model rests on.
 *   KT-9  no Ctrl+Alt+Del control, ever. It cannot work (HR-14.3), and a button that
 *         cannot work is worse than an absent one.
 */
class MainActivity : Activity()
