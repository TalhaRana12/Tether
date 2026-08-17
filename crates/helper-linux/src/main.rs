//! Linux input-injection helper. **Phase 7**, not Phase 0.
//!
//! Present now only so the workspace shape of spec Phase 0 exists. It does nothing.
//!
//! Phase 7 requirements (HR-7.4, HR-7.5, spec §6.9):
//!   - systemd **system** unit as user `tether-input`, `DeviceAllow=/dev/uinput rw`,
//!     `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateNetwork=yes`
//!   - Unix socket with `SO_PEERCRED` + `/proc/<pid>/exe` verification
//!   - `/proc/<pid>` **starttime** compared with the handle held open across the
//!     check (spec §6.31 — closes the PID-reuse window entirely)
//!   - the same session-bound capability token, monotonic expiry
//!   - inert outside an authorized session
//!
//! HR-7.5, and it is absolute: **no udev rule grants `/dev/uinput` to the login
//! user. Ever.** That is the Wayland sandbox escape this helper exists to prevent —
//! otherwise any process running as that user, a Flatpak app or a compromised
//! browser tab, can synthesize keystrokes on a machine where tether is merely
//! installed (spec §6.9, T23).

fn main() {
    eprintln!("tether-helper-linux: not implemented until Phase 7 (HR-7.3, HR-7.4)");
    std::process::exit(1);
}
