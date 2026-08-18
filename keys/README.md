# keys/

**Public halves only. No private key is ever committed here, or anywhere.**

HR-0.3: every long-term secret lives in hardware or is 256 bits of CSPRNG output. Nothing
in this directory is secret; everything in it is meant to be pinned, published, and read
by strangers.

| File | What it is | Where the private half lives |
|---|---|---|
| `release-signing-key.pub` | Ed25519 public key. Agents verify update manifests against this (HR-12.2 check 1) | seed sealed under a non-exportable TPM RSA key on the maintainer machine — `tools/tpm-seal.ps1` |
| `admin-audit-keys.json` | Epoch-stamped list of accepted admin X25519 audit keys (HR-4.8) | generated in-browser, wrapped three independent ways, never leaves the browser (HR-4.5) |

## What is deliberately NOT here

`release-seed.tpm-sealed` is **gitignored**. It is safe in the sense that it only opens on
one machine's TPM, but it is machine-specific state, not source. Committing it would
invite someone to think a checkout is enough to sign, which it is not.

## Rotating the release key

There is no rotation path that does not go through a signed release, by design. Agents
verify against the key **compiled into the binary** (HR-12.2), so a new key reaches them
only inside an update signed by the old one. Lose the sealed seed and you lose the ability
to ship to existing installs — that is the same shape as HR-4.5's terminal failure, and it
is deliberate: a key that can be replaced remotely is a key an attacker can replace
remotely.

## Rotating the admin audit key

HR-4.8: agents pin an **epoch-stamped list**, changed only through the signed release
channel. Hosts seal to the highest-epoch key they know and keep the previous key valid for
exactly one release cycle, so entries are appended, never edited.
