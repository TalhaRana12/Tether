//! Linux agent. **Phase 2 onward.**
//!
//! HR-7.2: a systemd **user** unit, unprivileged, dies with the session. The Windows
//! broker/worker split has no equivalent here because the constraint is milder — but
//! the greeter is still out of reach (HR-14.2, spec §6.15), and that is a documented
//! hard limitation rather than something to work around.

fn main() {
    println!(
        "tether-agent-linux {} · protocol v{} (floor v{})",
        env!("CARGO_PKG_VERSION"),
        tether_proto::CURRENT_PROTOCOL_VERSION,
        tether_proto::MIN_PROTOCOL_VERSION,
    );
}
