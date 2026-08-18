//! Release manifest signing. **Operator tool — never ships to a user's machine.**
//!
//! # Why this exists, and the constraint that shaped it
//!
//! HR-0.2, a governing rule: *"Nothing online can sign a release. The release key is
//! offline hardware requiring a physical touch."* Spec §6.1 names the attack — steal a
//! CI token, trigger a release, CI signs, every agent auto-updates to a backdoored build
//! with a **valid** signature (T16).
//!
//! The intended hardware is a YubiKey. This build is zero-budget, so the key is instead
//! **sealed to this machine's TPM**. One fact forced the design:
//!
//! > **The Windows TPM cannot hold an Ed25519 key.** Verified, not assumed:
//! > `CngKey.Create(ED25519, "Microsoft Platform Crypto Provider")` returns
//! > *"The requested operation is not supported."* The TPM offers RSA.
//!
//! Two ways out, and the choice matters:
//!
//! | Option | Cost |
//! |---|---|
//! | Sign with a TPM **RSA** key | Non-exportable — but breaks HR-4.1's pinned EdDSA and forces a rewrite of the already-tested verifier |
//! | Keep **Ed25519**, seal the seed to the TPM | Algorithm preserved; the seed is briefly in memory while signing |
//!
//! **This tool takes the second.** The 32-byte Ed25519 seed is CSPRNG output (HR-0.3
//! satisfied — "256 bits of CSPRNG output"), sealed at rest under a **non-exportable TPM
//! RSA key**, and never written to disk unsealed. See `tools/tpm-seal.ps1`.
//!
//! ## What that keeps, and what it costs — stated because "equivalent" would be a lie
//!
//! - **CI cannot sign** — kept in full. This is the property that carries the weight.
//! - **The key is useless on another machine** — kept. The sealed blob only opens on this
//!   TPM. Copying the repo, or the blob, gets an attacker nothing.
//! - **The key cannot be extracted by malware running as you** — *lost*. During a signing
//!   run the seed exists in this process's memory. A YubiKey never exposes it.
//! - **Physical touch per signature** — *lost*. See HR-0.2's deviation note.
//!
//! The seed is zeroized before exit, which narrows the window but does not close it.
//!
//! ## Reading the seed from stdin, not argv
//!
//! Command-line arguments are visible to every process on the machine via the process
//! list. A secret passed as `--seed abc123` is a secret published to any local process
//! that cares to look. stdin is not enumerable that way.

use std::io::{Read, Write};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const SEED_LEN: usize = 32;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    let result = match cmd {
        "keygen" => keygen(),
        "sign" => sign(args.get(2).map(String::as_str)),
        "verify" => verify(
            args.get(2).map(String::as_str),
            args.get(3).map(String::as_str),
            args.get(4).map(String::as_str),
        ),
        _ => Err(usage()),
    };

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn usage() -> String {
    concat!(
        "tether-sign-release — operator tool (HR-0.2)\n\n",
        "  keygen\n",
        "      Generate an Ed25519 release keypair. Prints the public key to stdout and\n",
        "      the 32-byte seed to stderr, so a shell redirect cannot silently capture\n",
        "      the secret into the same file as the public half.\n\n",
        "  sign <manifest-path>          (seed hex on stdin)\n",
        "      Ed25519 signature over the manifest bytes AS READ. Prints hex signature.\n\n",
        "  verify <manifest> <sig-hex> <pubkey-hex>\n",
        "      Independent check of a signature. Use it before publishing.\n"
    )
    .to_string()
}

/// Generate a release keypair.
///
/// Public key to **stdout**, seed to **stderr**, deliberately. A careless
/// `keygen > release.pub` then captures only the public half; the secret stays on the
/// terminal where it must be handled deliberately. Redirecting both into one file is
/// then an explicit act rather than an accident.
fn keygen() -> Result<(), String> {
    let mut seed = [0u8; SEED_LEN];
    getrandom_seed(&mut seed)?;

    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    println!("{}", hex::encode(vk.to_bytes()));
    eprintln!("{}", hex::encode(seed));
    eprintln!();
    eprintln!("Seed printed above. Seal it to the TPM now:");
    eprintln!("    tools/tpm-seal.ps1 -Seal");
    eprintln!("Then commit ONLY the public key. HR-0.3: this seed is 256 bits of CSPRNG");
    eprintln!("output and is the entire release identity — there is no recovery copy.");

    seed.fill(0);
    Ok(())
}

/// Sign a manifest with a seed supplied on stdin.
///
/// The signature covers the manifest **bytes as read**, never a re-serialised structure.
/// `crates/agent-core/src/release.rs` verifies the same way, and the reason is the same:
/// re-serialising invites a canonicalisation bug, and two distinct manifests that
/// serialise identically is a forgery.
fn sign(manifest_path: Option<&str>) -> Result<(), String> {
    let path = manifest_path.ok_or_else(usage)?;
    let manifest = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;

    let mut seed = read_seed_from_stdin()?;
    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(&manifest);
    seed.fill(0);

    println!("{}", hex::encode(sig.to_bytes()));

    eprintln!("manifest : {path}");
    eprintln!("sha256   : {}", hex::encode(Sha256::digest(&manifest)));
    eprintln!("pubkey   : {}", hex::encode(sk.verifying_key().to_bytes()));
    Ok(())
}

/// Verify before publishing.
///
/// Uses `verify_strict`, matching the agent. The permissive `verify` accepts small-order
/// and non-canonical public keys, which would let one signature be valid under more than
/// one key — exactly the ambiguity a release channel must not have.
fn verify(
    manifest_path: Option<&str>,
    sig_hex: Option<&str>,
    pub_hex: Option<&str>,
) -> Result<(), String> {
    let (path, sig_hex, pub_hex) = match (manifest_path, sig_hex, pub_hex) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err(usage()),
    };

    let manifest = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;

    let pk: [u8; 32] = hex::decode(pub_hex.trim())
        .map_err(|e| format!("public key not hex: {e}"))?
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let sg: [u8; 64] = hex::decode(sig_hex.trim())
        .map_err(|e| format!("signature not hex: {e}"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;

    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("bad public key: {e}"))?;
    vk.verify_strict(&manifest, &Signature::from_bytes(&sg))
        .map_err(|_| "SIGNATURE DOES NOT VERIFY".to_string())?;

    println!("ok");
    Ok(())
}

fn read_seed_from_stdin() -> Result<[u8; SEED_LEN], String> {
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .map_err(|e| format!("cannot read seed from stdin: {e}"))?;

    // Keep only hex digits. `trim()` is not enough: PowerShell prepends a UTF-8 BOM
    // (U+FEFF) when piping to a native command, and Rust does not classify U+FEFF as
    // whitespace, so the BOM survives and hex decoding fails with "odd number of
    // digits" — a confusing error a long way from its cause.
    //
    // Liberal in what is accepted, strict about the result: the length check below is
    // what actually guards correctness, so filtering noise here loses nothing.
    let filtered: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    let raw = hex::decode(&filtered).map_err(|e| format!("seed is not hex: {e}"))?;
    if raw.len() != SEED_LEN {
        return Err(format!(
            "seed must be exactly {SEED_LEN} bytes ({} hex chars); got {} bytes",
            SEED_LEN * 2,
            raw.len()
        ));
    }
    raw.try_into()
        .map_err(|_| "seed length check failed".to_string())
}

/// 256 bits from the OS CSPRNG (HR-0.3).
fn getrandom_seed(buf: &mut [u8; SEED_LEN]) -> Result<(), String> {
    use rand_core::RngCore;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|e| format!("CSPRNG failed: {e}"))?;
    // A CSPRNG that returns all zeros is broken, and signing with a zero seed would
    // produce a valid-looking key anyone can reproduce. Cheap check, catastrophic miss.
    if buf.iter().all(|&b| b == 0) {
        return Err("CSPRNG returned all zeros; refusing to generate a key".into());
    }
    let _ = std::io::stdout().flush();
    Ok(())
}
