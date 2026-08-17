// Browser tests for the admin audit keypair generator.
//
// WHY THIS EXISTS AND WHY IT IS PLAYWRIGHT
//
// Spec Phase 0: "Generate the admin audit keypair in-browser, random, wrapped three
// ways — authenticator A, authenticator B, and a 256-bit paper recovery secret."
// HR-4.5 requires all three wraps to be INDEPENDENT: any one opens the key, and losing
// all three is the intended terminal failure with no fourth copy anywhere.
//
// Wraps 1 and 2 need physical WebAuthn authenticators. **Wrap 3 does not** — it is
// HKDF over 256 CSPRNG bits that live on paper. So this is the one part of that Phase 0
// bullet reachable with no hardware, and it runs in a browser, which is exactly what
// Playwright is for.
//
// Several properties below CANNOT be checked by a unit test, which is the real argument
// for a browser test here rather than a token one:
//   - that no password or passphrase input exists anywhere in the DOM (HR-4.6)
//   - that the private key never reaches localStorage or sessionStorage (HR-4.7)
//   - that the page makes no external request at all (HR-9.7 — no CDN, CSP 'self')
//   - that navigating away actually clears the key from memory (HR-4.7)
//
// Those are properties of a real page in a real browser, and a Rust test cannot see them.

const { test, expect } = require('@playwright/test');

const PAGE = '/audit-keygen.html';

/** Read the recovery secret the page generated, as displayed. */
async function mnemonic(page) {
  return (await page.locator('#recovery-mnemonic').innerText()).trim();
}

// ---------------------------------------------------------------------------
// HR-0.3 / HR-4.6 — no secret is derivable from anything guessable
// ---------------------------------------------------------------------------

// GATE 3, SECOND PASS — this test was rewritten, deliberately and before any
// implementation was written. Recorded here rather than quietly edited, because
// workflow §3.2 warns that a corrected specification of intent and a moved goalpost
// look identical in a diff.
//
// The first version asserted `words.length === 24`. That number is not arbitrary: 24
// words carrying 256 bits implies ~10.67 bits per word, which means a 2048-word list,
// which means BIP-39. Embedding a BIP-39 wordlist I cannot verify byte-for-byte would
// be guessing at a shape (WORKING-AGREEMENT §4), and a single wrong word makes a
// printed recovery secret silently unreadable — with no fourth copy behind it (HR-4.5).
//
// The deeper defect: word count is an encoding detail. The security property is **256
// bits of CSPRNG entropy**. The original test over-specified the first and never
// asserted the second. This version asserts the property and derives the count from the
// scheme the page publishes.
test('recovery secret carries 256 bits of entropy in documented words', async ({ page }) => {
  await page.goto(PAGE);
  await page.click('#generate');
  await expect(page.locator('#recovery-mnemonic')).not.toBeEmpty();

  const scheme = await page.evaluate(() => window.tetherRecoveryScheme);
  expect(scheme).toBeTruthy();

  // The property HR-4.5 actually requires.
  expect(scheme.bits).toBe(256);
  expect(scheme.wordlistSize * scheme.words).toBeGreaterThanOrEqual(0);
  expect(Math.log2(scheme.wordlistSize) * scheme.words).toBe(256);

  const words = (await mnemonic(page)).split(/\s+/);
  expect(words.length).toBe(scheme.words);

  // Every word must come from the documented list, or a transcription cannot be
  // checked when someone reads it back off paper.
  // Gate 3, third pass, mechanical: `page.evaluate` returns JSON-serialisable values, so
  // returning the function itself yielded `undefined` and failed against a working page.
  // The assertion is unchanged in intent — check for the accessor — only the mechanism
  // was wrong.
  const known = await page.evaluate(() => typeof window.tetherWordlistHas === 'function');
  expect(known).toBe(true);
  const unknown = await page.evaluate(
    (ws) => ws.filter((w) => !window.tetherWordlistHas(w)),
    words
  );
  expect(unknown).toEqual([]);

  // No duplicate-prefix ambiguity: distinct words must stay distinct at 4 characters,
  // which is what makes a handwritten secret recoverable.
  const prefixes = new Set(words.map((w) => w.slice(0, 4)));
  expect(new Set(words).size).toBe(prefixes.size);
});

test('two generations produce different secrets', async ({ page }) => {
  await page.goto(PAGE);
  await page.click('#generate');
  const first = await mnemonic(page);

  await page.reload();
  await page.click('#generate');
  const second = await mnemonic(page);

  expect(second).not.toBe(first);
  // Guards against a hardcoded phrase, a seeded PRNG, or Math.random with a
  // coarse-grained time seed. HR-0.3: every long-term secret is 256 bits of CSPRNG
  // output or lives in hardware.
});

test('no password or passphrase input exists anywhere on the page', async ({ page }) => {
  await page.goto(PAGE);

  // HR-4.6: "There is no passphrase anywhere in the audit key chain, so there is no
  // offline brute-force target. Never reintroduce one, including just for development."
  // §6.8 was a HIGH finding: dump the DB, guess passphrases, GPU-farm the answer.
  // The fix was structural — remove the guessable input. This asserts it stayed removed.
  await expect(page.locator('input[type="password"]')).toHaveCount(0);

  const suspicious = await page.locator('input, textarea').evaluateAll((els) =>
    els
      .map((e) => `${e.id} ${e.name} ${e.placeholder} ${e.getAttribute('aria-label') || ''}`.toLowerCase())
      .filter((s) => /pass(word|phrase)|pin\b|secret phrase/.test(s))
  );
  expect(suspicious).toEqual([]);
});

// ---------------------------------------------------------------------------
// HR-4.5 — the recovery-secret wrap, and its independence
// ---------------------------------------------------------------------------

test('the correct recovery secret unwraps the key', async ({ page }) => {
  await page.goto(PAGE);
  await page.click('#generate');

  const pub = await page.locator('#public-key').innerText();
  expect(pub).toMatch(/^[0-9a-f]{64}$/);

  const secret = await mnemonic(page);
  const wrapped = await page.locator('#wrapped-blob').innerText();

  await page.reload();
  await page.fill('#unwrap-mnemonic', secret);
  await page.fill('#unwrap-blob', wrapped);
  await page.click('#unwrap');

  await expect(page.locator('#unwrap-result')).toHaveText(/^ok /);
  // The recovered public key must match the one generated, which is what proves this
  // wrap really is an independent path to the SAME key rather than a new one.
  await expect(page.locator('#unwrap-result')).toContainText(pub);
});

test('a wrong recovery secret fails to unwrap', async ({ page }) => {
  await page.goto(PAGE);
  await page.click('#generate');
  const wrapped = await page.locator('#wrapped-blob').innerText();

  await page.reload();
  await page.click('#generate');
  const otherSecret = await mnemonic(page);

  await page.reload();
  await page.fill('#unwrap-mnemonic', otherSecret);
  await page.fill('#unwrap-blob', wrapped);
  await page.click('#unwrap');

  await expect(page.locator('#unwrap-result')).toHaveText(/^failed/);
  // AES-GCM is authenticated, so a wrong key must fail the tag check rather than
  // return garbage. Returning garbage would mean an attacker could not tell a wrong
  // guess from a right one — which is only reassuring until you notice it also means
  // WE cannot tell, and would happily hand a corrupt key to HPKE.
});

test('a tampered wrapped blob fails to unwrap', async ({ page }) => {
  await page.goto(PAGE);
  await page.click('#generate');
  const secret = await mnemonic(page);
  const wrapped = await page.locator('#wrapped-blob').innerText();

  // Flip one hex nibble in the ciphertext.
  const i = wrapped.length - 8;
  const flipped =
    wrapped.slice(0, i) + (wrapped[i] === '0' ? '1' : '0') + wrapped.slice(i + 1);
  expect(flipped).not.toBe(wrapped);

  await page.reload();
  await page.fill('#unwrap-mnemonic', secret);
  await page.fill('#unwrap-blob', flipped);
  await page.click('#unwrap');

  await expect(page.locator('#unwrap-result')).toHaveText(/^failed/);
  // HR-4.5 says the wrapped blob may sit in the database. That is only safe if
  // tampering with it is detected rather than silently producing a different key.
});

// ---------------------------------------------------------------------------
// HR-4.7 — memory-only, cleared on navigation
// ---------------------------------------------------------------------------

test('the private key never reaches localStorage or sessionStorage', async ({ page }) => {
  await page.goto(PAGE);
  await page.click('#generate');

  const stored = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));

  // HR-4.7: unwrap happens "all in browser memory, cleared on navigation". Web
  // storage survives navigation and is readable by any script on the origin, so a
  // key there would be exactly the durable secret §6.3 says XSS must not be able
  // to steal.
  expect(stored.local).toEqual([]);
  expect(stored.session).toEqual([]);
});

test('reloading clears the generated key from the page', async ({ page }) => {
  await page.goto(PAGE);
  await page.click('#generate');
  await expect(page.locator('#public-key')).not.toBeEmpty();

  await page.reload();
  await expect(page.locator('#public-key')).toBeEmpty();
  await expect(page.locator('#recovery-mnemonic')).toBeEmpty();
});

// ---------------------------------------------------------------------------
// HR-9.7 — served locally, no CDN, no inline script
// ---------------------------------------------------------------------------

test('the page makes no external network request', async ({ page }) => {
  const external = [];
  page.on('request', (r) => {
    const url = r.url();
    if (!url.startsWith('http://127.0.0.1') && !url.startsWith('http://localhost')) {
      external.push(url);
    }
  });

  await page.goto(PAGE);
  await page.click('#generate');

  // HR-9.7 requires CSP `default-src 'self'` with htmx and Tailwind served locally.
  // This page generates a key that decrypts every user's audit log; a single CDN
  // request is a third party who can replace the crypto.
  expect(external).toEqual([]);
});

test('crypto comes from WebCrypto, not a bundled library', async ({ page }) => {
  await page.goto(PAGE);

  const ok = await page.evaluate(
    () => window.isSecureContext && typeof crypto?.subtle?.deriveBits === 'function'
  );
  expect(ok).toBe(true);
  // WebCrypto only exists in a secure context, and its CSPRNG is the platform's.
  // A hand-rolled or bundled implementation here would be a new cryptographic
  // primitive in the one component that decrypts every audit log.
});
