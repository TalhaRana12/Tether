// Admin audit keypair generation — the recovery-secret wrap of HR-4.5.
//
// HR-4.5 requires the X25519 audit key to be wrapped THREE times INDEPENDENTLY:
// authenticator A, authenticator B, and HKDF(recovery_secret) where recovery_secret is
// 256 CSPRNG bits on paper. Any one opens it; losing all three is the intended terminal
// failure, and there is no fourth copy anywhere.
//
// This file implements the THIRD path only. The two WebAuthn `prf` wraps need physical
// authenticators and are Phase 0.3. They are also blocked on the panel domain (BLK-9's
// retained precondition): registering a credential freezes the RP ID, and changing it
// later kills both hardware wraps and leaves only this one.
//
// HR-4.6, and it is absolute: there is NO passphrase anywhere in this chain, so there is
// no offline brute-force target. §6.8 was a HIGH finding — dump the database, guess
// passphrases, confirm against a known ciphertext, recover every audit log on rented
// GPUs. The fix was structural: remove the guessable input. Do not reintroduce one,
// "including just for development" (HR-4.6, verbatim).
'use strict';

const RECOVERY_BITS = 256;
const RECOVERY_BYTES = RECOVERY_BITS / 8;

// HKDF context. A distinct label per purpose, so a key derived here can never collide
// with one derived for another use even from the same input.
const HKDF_INFO = new TextEncoder().encode('tether-audit-key-wrap-v1');
const AES_NONCE_BYTES = 12;

// HR-4.5: "Register the same prf salt on both authenticators." A FIXED salt is what makes
// two different authenticators produce two different keys for the SAME purpose - the salt
// names the purpose, the authenticator supplies the secret. Varying it per registration
// would mean an authenticator could not re-derive its own wrapping key later.
const PRF_SALT = new TextEncoder().encode('tether-audit-key-wrap-v1-prf-salt');

/** In-memory only. HR-4.7: memory-only, cleared on navigation. Never persisted. */
let session = null;

const $ = (id) => document.getElementById(id);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function unhex(s) {
  const clean = s.trim().toLowerCase().replace(/\s+/g, '');
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('not hex');
  }
  return new Uint8Array(clean.match(/../g)?.map((p) => parseInt(p, 16)) ?? []);
}

const b64uToBytes = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

// ---------------------------------------------------------------------------
// Key wrap
// ---------------------------------------------------------------------------

/**
 * recovery secret -> AES-GCM wrapping key, via HKDF.
 *
 * HKDF rather than using the 32 bytes directly: the recovery secret is already uniformly
 * random, so extraction is not strictly required, but deriving through a labelled HKDF
 * means this key is domain-separated from any other use of the same secret. Costs
 * nothing and removes a footgun.
 */
async function wrappingKey(secret) {
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: HKDF_INFO },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** Wrapped blob = nonce || AES-GCM(key_material). Authenticated, so tampering is caught. */
async function wrap(secret, material) {
  const key = await wrappingKey(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(AES_NONCE_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, material)
  );
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

async function unwrap(secret, blob) {
  if (blob.length <= AES_NONCE_BYTES) throw new Error('blob too short');
  const key = await wrappingKey(secret);
  // Throws on a wrong key OR a tampered ciphertext — AES-GCM's tag check does both, and
  // it must be allowed to throw rather than be caught into a "maybe" result.
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.slice(0, AES_NONCE_BYTES) },
    key,
    blob.slice(AES_NONCE_BYTES)
  );
  return new Uint8Array(pt);
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

async function generate() {
  // HR-4.1 pins X25519 for audit sealing (HPKE, RFC 9180, X25519 + ChaCha20-Poly1305).
  // Fail loudly if the browser cannot do it rather than silently substituting a curve.
  let pair;
  try {
    pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  } catch (e) {
    $('public-key').textContent =
      'X25519 unavailable in this browser. HR-4.1 pins X25519 and no substitute is ' +
      'acceptable. Use a current Chromium or Firefox. (' + e.message + ')';
    return;
  }

  // JWK exposes the raw scalar `d` and the public `x`. There is no 'raw' export for a
  // private X25519 key in WebCrypto, and PKCS#8 would mean parsing DER here.
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const d = b64uToBytes(jwk.d);
  const x = b64uToBytes(jwk.x);
  if (d.length !== 32 || x.length !== 32) throw new Error('unexpected X25519 key size');

  // Wrap d || x — fixed 64 bytes, no JSON, so there is nothing to canonicalise. The
  // public half rides along so an unwrap can prove it recovered THIS keypair rather
  // than merely producing 32 plausible bytes.
  const material = new Uint8Array(64);
  material.set(d, 0);
  material.set(x, 32);

  const secret = crypto.getRandomValues(new Uint8Array(RECOVERY_BYTES));
  const blob = await wrap(secret, material);

  // The key material is RETAINED IN MEMORY for the rest of this page load, because the
  // other two wraps of HR-4.5 need the same key. That is exactly what HR-4.7 permits —
  // "all in browser memory, cleared on navigation" — and no further: it is never written
  // to storage, and a reload discards it (asserted by two tests).
  session = { publicKey: hex(x), material };

  $('public-key').textContent = session.publicKey;
  $('recovery-mnemonic').textContent = window.tetherWordlist.bytesToWords(secret);
  $('wrapped-blob').textContent = hex(blob);

  d.fill(0);
  secret.fill(0);
}

// ---------------------------------------------------------------------------
// Verify the recovery path
// ---------------------------------------------------------------------------

async function verifyUnwrap() {
  const out = $('unwrap-result');
  try {
    const secret = window.tetherWordlist.wordsToBytes($('unwrap-mnemonic').value);
    if (secret.length !== RECOVERY_BYTES) {
      throw new Error(`expected ${RECOVERY_BYTES} words, got ${secret.length}`);
    }
    const material = await unwrap(secret, unhex($('unwrap-blob').value));
    if (material.length !== 64) throw new Error('unexpected key material length');

    out.textContent = `ok — recovered public key ${hex(material.slice(32))}`;
    material.fill(0);
    secret.fill(0);
  } catch (e) {
    // Deliberately does not distinguish "wrong secret" from "tampered blob". Both mean
    // this path will not open the key, and saying which would tell an attacker holding
    // the blob whether a guess was structurally closer.
    out.textContent = `failed — this secret does not open this blob (${e.message})`;
  }
}

// ---------------------------------------------------------------------------
// HR-4.5 wraps 1 and 2 — the two authenticators, via the WebAuthn prf extension
// ---------------------------------------------------------------------------

/**
 * Ask an authenticator to evaluate the prf extension and return 32 bytes.
 *
 * The prf output is derived INSIDE the authenticator from a secret that never leaves it.
 * That is the property HR-4.5 buys: a wrapping key that cannot be extracted from the
 * device, only exercised on it. It is also why there is no passphrase anywhere in this
 * chain (HR-4.6) — there is nothing guessable to attack offline (spec §6.8).
 *
 * Registration and evaluation are two steps because the prf output is only available from
 * an ASSERTION, never from the credential creation itself.
 */
async function prfBits({ register }) {
  if (register) {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'tether admin audit key' },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'audit-key-custodian',
          displayName: 'audit key custodian',
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'required',
        },
        extensions: { prf: {} },
      },
    });
    if (!cred) throw new Error('registration cancelled');
    if (cred.getClientExtensionResults()?.prf?.enabled === false) {
      throw new Error('this authenticator does not support the prf extension');
    }
  }

  // Discoverable credential, so no allowCredentials list is needed — and a DIFFERENT
  // authenticator simply finds nothing, which is what makes each wrap independent.
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'required',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  if (!assertion) throw new Error('assertion cancelled');

  const first = assertion.getClientExtensionResults()?.prf?.results?.first;
  if (!first) throw new Error('authenticator returned no prf output');
  return new Uint8Array(first);
}

async function wrapWithAuthenticator() {
  const status = $('authenticator-status');
  try {
    if (!session?.material) {
      status.textContent = 'generate a keypair first';
      return;
    }
    status.textContent = 'touch your authenticator...';

    const bits = await prfBits({ register: true });
    // Same HKDF and AES-GCM as the paper path. Only the input secret differs, which is
    // exactly what "independent wraps" means: three different keys over one plaintext.
    const blob = await wrap(bits, session.material);
    bits.fill(0);

    $('authenticator-blob').textContent = hex(blob);
    status.textContent = `wrapped — ${blob.length} bytes. Now repeat with your SECOND authenticator.`;
  } catch (e) {
    status.textContent = `failed — ${e.message}`;
  }
}

async function unwrapWithAuthenticator() {
  const out = $('unwrap-result');
  try {
    const blob = unhex($('unwrap-authenticator-blob').value);
    const bits = await prfBits({ register: false });
    const material = await unwrap(bits, blob);
    bits.fill(0);
    if (material.length !== 64) throw new Error('unexpected key material length');

    out.textContent = `ok — recovered public key ${hex(material.slice(32))}`;
    material.fill(0);
  } catch (e) {
    // Same deliberate vagueness as the paper path: a wrong authenticator and a tampered
    // blob are not distinguished, so whoever holds the blob learns nothing from the error.
    out.textContent = `failed — this authenticator does not open this blob (${e.message})`;
  }
}

// Published for the tests, and for anyone auditing the scheme without reading the code.
window.tetherRecoveryScheme = {
  bits: RECOVERY_BITS,
  words: RECOVERY_BYTES,
  wordlistSize: 256,
  wrap: 'HKDF-SHA256 -> AES-256-GCM',
  note: 'no passphrase anywhere in this chain (HR-4.6)',
};

document.addEventListener('DOMContentLoaded', () => {
  $('generate').addEventListener('click', () => {
    generate().catch((e) => {
      $('public-key').textContent = `error: ${e.message}`;
    });
  });
  $('unwrap').addEventListener('click', () => {
    verifyUnwrap();
  });
  $('wrap-authenticator').addEventListener('click', () => {
    wrapWithAuthenticator();
  });
  $('unwrap-authenticator').addEventListener('click', () => {
    unwrapWithAuthenticator();
  });
});
