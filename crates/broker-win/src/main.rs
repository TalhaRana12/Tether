//! Windows SYSTEM broker. **Phase 2**, not Phase 0.
//!
//! Why this crate exists at all, and why it is separate: spec §6.13 found that the
//! v3 design *could not capture the screen*. Services run in session 0, and DXGI
//! Desktop Duplication requires a process in the interactive session with an open
//! desktop handle — so the specified program did not function. This is not a
//! weakness that was hardened; it is a component that did not work.
//!
//! The resolution (spec §4.10) is a split where the privileged half holds nothing:
//!
//!   broker (SYSTEM, session 0)     worker (user session, UNPRIVILEGED)
//!   - launches the worker          - DXGI capture, encode, WebRTC, Noise
//!     via CreateProcessAsUser      - consent UI
//!   - handles WTS_SESSION_*        - holds ALL session keys
//!   - restarts a crashed worker    - dies with the session
//!   - NO keys, NO network,
//!     NO capture, NO input
//!
//! T8's intent survives because the process with the framebuffer and the socket is
//! still the unprivileged one. Build it in Phase 2, not later: retrofitting after
//! Phase 5 means rewriting the capture path (spec §6.13).

fn main() {
    eprintln!("tether-broker-win: not implemented until Phase 2 (HR-7.1, spec §4.10)");
    std::process::exit(1);
}
