// Module path uses the GitHub ID confirmed by the author (TalhaRana12).
//
// Stdlib only, deliberately. Spec §3 chose Go for the control plane because
// "Stdlib + single-binary deploy makes this a weekend", and T1 assumes this service is
// fully compromised — so every dependency added here is code inside a component the
// threat model already treats as hostile. Adding one is a decision, not a convenience.
module github.com/TalhaRana12/tether

go 1.22
