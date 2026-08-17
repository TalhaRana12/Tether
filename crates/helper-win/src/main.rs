//! Windows input-injection helper. **Phase 7**, not Phase 0.
//!
//! Present now only so the workspace shape of spec Phase 0 exists and the crate
//! boundary is enforced from the first commit. It deliberately does nothing.
//!
//! When Phase 7 fills this in, HR-7.4 requires **all four** layers:
//!   - pipe SDDL `D:(A;;GA;;;<agent-sid>)(D;;GA;;;WD)`
//!   - `GetNamedPipeClientProcessId` -> image path -> Authenticode chain to our cert
//!   - process **creation time** compared alongside the PID (HR-7.4, spec §6.31 —
//!     PID reuse is a real race, not a theoretical one)
//!   - a session-bound capability token, expiry on a **monotonic** clock (HR-6.1)
//!
//! And the property that matters most (HR-7.4): **outside an authorized session this
//! helper is inert.** The escalation primitive must not exist when nobody is
//! connected. Spec §6.2's attack was exploitable with no remote session at all.
//!
//! It must never touch the secure desktop. `elevate` was removed from the protocol
//! (spec §6.14), so there is no code path that tries — see HR-14.2.

fn main() {
    eprintln!("tether-helper-win: not implemented until Phase 7 (HR-7.3, HR-7.4)");
    std::process::exit(1);
}
