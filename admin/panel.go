// Package admin is the tether administration panel. Spec Phase 4.
//
// Present at Phase 0 only so the Go module of spec Phase 0 exists. It deliberately does
// nothing.
//
// WHAT THIS PANEL CANNOT DO, BY PROTOCOL RATHER THAN BY PERMISSION (HR-9.8)
//
// There is no endpoint to disable, no flag to flip, and no role to escalate into, because
// the wire messages do not exist (HR-1.1). The panel cannot:
//
//	start, join, or observe a session on any host
//	add a key to any host allowlist
//	grant or modify any capability
//	read or write files, clipboard, or screen content
//	change host settings, or wipe or reconfigure a host
//	recover or export any private key
//	read audit entries its own hardware key cannot unwrap
//	approve a connection on a user's behalf, or change a device's access mode
//	set or clear a backup credential
//	sign a release or rollback manifest
//
// HR-9.9 is the test every new panel operation must pass: **every admin operation reduces
// access. None expands it, and none is irreversible.** An operation that fails that test
// does not ship.
//
// Three rules Phase 4 must not get wrong:
//
//	HR-9.1  Served from a SEPARATE REGISTRABLE DOMAIN, not admin.example.com. SameSite
//	        and cookie scope operate on the registrable domain, so a subdomain leaves an
//	        API-side XSS same-site with the panel session (§6.16, T27). BLK-9 is
//	        descoped but its constraint is retained: the domain must be fixed before any
//	        WebAuthn credential is registered, because registration freezes the RP ID.
//
//	HR-9.5  The WebAuthn session is the authority, NOT the `role` claim. Middleware
//	        asserts the authenticated credential belongs to a registered admin. A forged
//	        `role: admin` gets the panel, not a desktop (HR-5.4).
//
//	HR-9.7  Untrusted strings — device labels, display names, invite notes — are
//	        validated at ingest and REJECTED, NOT SANITISED, then rendered as text nodes
//	        only: never in an attribute, never adjacent to an hx-* directive, never in an
//	        hx-vals payload. §6.3 was a critical finding, and the audit key it targeted
//	        is now prf-wrapped so XSS steals a session rather than a durable decryption
//	        capability.
package admin

// Version is set at link time in release builds.
const Version = "dev"
