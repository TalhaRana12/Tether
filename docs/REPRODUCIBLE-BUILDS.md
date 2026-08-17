# Reproducible builds

**HR-12.5:** *"Builds are reproducible: two builds of the same commit are byte-identical, and the
procedure is documented so a third party can verify binaries against source."*

This document is the second half of that rule. Without it the first half is unverifiable by anyone
but the person who built it, which defeats the point — the property exists so that someone who does
not trust you can check that the binary you shipped is the source you published.

---

## Why this matters here specifically

Spec §0 rule 2: nothing online can sign a release. That stops a stolen CI token shipping a backdoor
(T16). But signing only proves *who* built it, never *what they built from*. Reproducibility is the
control that closes the remaining gap: with it, anyone can rebuild the published commit and confirm
the signed artifact contains nothing that is not in the source.

## Verified state — 2026-08-17

| Property | Status | Evidence |
|---|---|---|
| Two clean release builds, **same source path**, byte-identical | **PASS** | `cargo build --release` twice with `cargo clean -p` between; SHA-256 identical both times |
| Two builds from **different source paths** identical | **NOT YET** | needs `--remap-path-prefix`; see below |

## What had to be fixed, and what it teaches

The default configuration is **not** reproducible. Measured, not assumed: two consecutive clean
release builds of identical source produced different SHA-256 digests.

**Cause: the PE `TimeDateStamp`.** MSVC's `link.exe` writes the wall-clock time of the link into the
PE header. Two builds a second apart therefore differ, and no amount of dependency pinning fixes it —
the nondeterminism is downstream of everything Cargo controls.

**Fix:** `-Clink-arg=/Brepro` in [`.cargo/config.toml`](../.cargo/config.toml). `/Brepro` makes
link.exe derive that field from a hash of its input rather than from the clock, so it becomes a
function of the content.

The general lesson is worth keeping: reproducibility fails at the *last* tool in the chain as
readily as the first. Pinning `rustc`, `Cargo.lock`, and every dependency version still left a
timestamp injected by a Microsoft linker two steps past where anyone was looking.

## The remaining gap: absolute source paths

`rustc` embeds the source directory into panic messages and debug info, so a verifier who clones to
`C:\verify` will not match a binary built in `C:\Users\...\Tether` even with an identical commit and
toolchain.

`trim-paths = "all"` is the clean fix and **is not stabilized in Cargo 1.97.1** — setting it in a
profile is a hard error, not a warning. Until it stabilizes, the release build must pass
`--remap-path-prefix` explicitly, which depends on the build path and so cannot live in
`.cargo/config.toml`.

**Release build command** (until `trim-paths` stabilizes):

```bash
# From the repository root. Maps the real source path to a fixed synthetic one, so
# the output does not depend on where the tree happens to sit.
RUSTFLAGS="-Clink-arg=/Brepro --remap-path-prefix=$(pwd)=/tether" \
  cargo build --release --workspace
```

```powershell
# PowerShell equivalent
$env:RUSTFLAGS = "-Clink-arg=/Brepro --remap-path-prefix=$($PWD.Path)=/tether"
cargo build --release --workspace
```

This is not yet verified end-to-end across two different source paths. Doing so is a Phase 0 exit
item and is recorded as outstanding in the phase 0.1 gate file rather than assumed to work.

## Verifying a published binary as a third party

```bash
git clone <repo> && cd <repo> && git checkout <tag>
# rust-toolchain.toml pins the compiler; rustup honours it automatically.
RUSTFLAGS="-Clink-arg=/Brepro --remap-path-prefix=$(pwd)=/tether" \
  cargo build --release --workspace
sha256sum target/release/tether-agent-win.exe
# Compare against the digest in the signed release manifest.
```

If the digests match, the signed manifest describes this source. If they do not, either the
procedure drifted or the artifact is not what the commit produces — and both are worth an
explanation before anyone installs it.

## What is pinned, and why each matters

| Pinned | Where | Breaks reproducibility if floating |
|---|---|---|
| Compiler version | [`rust-toolchain.toml`](../rust-toolchain.toml) | rustc codegen is not stable across versions |
| Dependency versions + hashes | `Cargo.lock` (committed) | a patch release upstream changes output |
| `codegen-units = 1` | [`Cargo.toml`](../Cargo.toml) | LLVM's work partitioning across threads is not guaranteed stable between runs |
| `incremental = false` | `Cargo.toml` | incremental artifacts leak prior-build state into output |
| `strip = "symbols"`, `debug = false` | `Cargo.toml` | debug info carries paths and ordering that vary |
| PE timestamp | `/Brepro` in `.cargo/config.toml` | wall-clock time, differs every build |
| Line endings | [`.gitattributes`](../.gitattributes) (`eol=lf`) | a CRLF checkout is not the same bytes as an LF one |

`Cargo.lock` is committed deliberately and [`.gitignore`](../.gitignore) says so at the point
someone would be tempted to add it.
