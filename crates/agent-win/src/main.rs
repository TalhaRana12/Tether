//! Windows per-session worker. **Phase 2 onward.**
//!
//! HR-7.1: unprivileged, holds all session keys, dies with the session. Launched by
//! `tether-broker-win` into the active console session.
//!
//! Phase 0 requires only that the workspace shape exists and that the protocol and
//! release-verification crates compile into it — hence the version banner below and
//! nothing else. Phase 2's exit criterion explicitly requires that **no capture,
//! input, or helper code is compiled in** at that point.

fn main() {
    println!(
        "tether-agent-win {} · protocol v{} (floor v{})",
        env!("CARGO_PKG_VERSION"),
        tether_proto::CURRENT_PROTOCOL_VERSION,
        tether_proto::MIN_PROTOCOL_VERSION,
    );
}
