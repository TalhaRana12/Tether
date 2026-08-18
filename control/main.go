// Command control is the tether control plane. Spec Phase 1.
//
// Present at Phase 0 only so the Go module of spec Phase 0 exists and `go vet` and
// `govulncheck` have something to run against. It deliberately does nothing.
//
// WHAT THIS SERVICE IS FOR, and the framing that makes its rules unusual: T1 assumes
// this code is fully compromised. Its job is to relay opaque bytes and issue tokens, and
// to be *unable* to do more. See docs/engineering/go-hard-rules.md.
//
// The three rules Phase 1 must not get wrong:
//
//   GO-1  WS /v1/signal treats every payload as []byte. The server must not parse,
//         inspect, validate, log, or store the contents (HR-11.2). No protobuf import
//         in the signaling path — a parser here is a place to have a bug and a
//         temptation to add a feature that reads a session.
//
//   GO-4  JWT verification requires alg == "EdDSA" and NEVER reads alg from the token
//         to select the algorithm (HR-5.3). That blocks the classic confusion attack
//         where an attacker flips to HS256 and signs using your *public* key as the
//         HMAC secret.
//
//   GO-15 The monotonic revocation epoch is read at startup from off-box append-only
//         storage. A value lower than the last known epoch means REFUSE TO SERVE and
//         alert — never start degraded (HR-5.6, T30, BLK-8's resolution). A restored
//         backup that silently un-revokes devices is the failure this makes loud.
//
// And the one that is absent rather than guarded: there is no code path by which this
// service can originate, approve, or observe a session, or modify a host's allowlist or
// capabilities (HR-0.1, HR-1.1). The panel is a client of this service, and this service
// has no authority over any host (HR-5.4).
package main

import (
	"fmt"
	"os"
)

// Set at link time in release builds; "dev" locally.
var version = "dev"

func main() {
	fmt.Fprintf(os.Stderr, "tether-control %s: not implemented until Phase 1\n", version)
	os.Exit(1)
}
