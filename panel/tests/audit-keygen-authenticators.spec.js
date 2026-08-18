// HR-4.5's two HARDWARE wrap paths, tested with no hardware.
//
// "The X25519 private key is wrapped independently, three times: once under HKDF(prf)
// from authenticator A, once from authenticator B, and once under HKDF(recovery_secret)
// [...] Any one of the three opens it. Losing all three means every audit log is
// permanently unreadable, and that is the intended failure mode - there is no fourth
// copy anywhere."
//
// The recovery-secret path is covered in audit-keygen.spec.js. This file covers the other
// two, using Chrome's VIRTUAL AUTHENTICATOR over CDP - probed and confirmed to support the
// prf extension, so the property "three independent paths open the same key" is provable
// on a machine with no security keys plugged into it.
//
// What a virtual authenticator does NOT prove: that a particular real device implements
// prf, or that the user actually holds two of them. Registering the real ones is a human
// action. What it does prove is that OUR code derives, wraps, and unwraps correctly - and
// that is the half that can silently be wrong.

const { test, expect } = require('@playwright/test');

const PAGE = '/audit-keygen.html';

/** Attach a virtual authenticator and return its CDP handle. */
async function addAuthenticator(page) {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      hasPrf: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { client, authenticatorId };
}

test('an authenticator wrap opens the same key the recovery secret opens', async ({ page }) => {
  await addAuthenticator(page);
  await page.goto(PAGE);
  await page.click('#generate');

  const pub = await page.locator('#public-key').innerText();
  const recoveryBlob = await page.locator('#wrapped-blob').innerText();
  const mnemonic = (await page.locator('#recovery-mnemonic').innerText()).trim();

  // Wrap the SAME key under an authenticator.
  await page.click('#wrap-authenticator');
  await expect(page.locator('#authenticator-status')).toHaveText(/^wrapped /, { timeout: 15000 });
  const authBlob = await page.locator('#authenticator-blob').innerText();

  expect(authBlob).toMatch(/^[0-9a-f]+$/);
  // Independence: the two wraps must be different ciphertexts. Identical blobs would mean
  // one wrapping key was reused, and "three independent wraps" would be one wrap in a hat.
  expect(authBlob).not.toBe(recoveryBlob);

  // Path 1: the authenticator opens it.
  await page.reload();
  await page.fill('#unwrap-authenticator-blob', authBlob);
  await page.click('#unwrap-authenticator');
  await expect(page.locator('#unwrap-result')).toHaveText(/^ok /, { timeout: 15000 });
  await expect(page.locator('#unwrap-result')).toContainText(pub);

  // Path 2: the paper secret opens the SAME key. This is the property HR-4.5 actually
  // asserts - not that three wraps exist, but that any one of them yields the same key.
  await page.reload();
  await page.fill('#unwrap-mnemonic', mnemonic);
  await page.fill('#unwrap-blob', recoveryBlob);
  await page.click('#unwrap');
  await expect(page.locator('#unwrap-result')).toHaveText(/^ok /);
  await expect(page.locator('#unwrap-result')).toContainText(pub);
});

test('a second authenticator wraps the same key independently', async ({ page }) => {
  const a = await addAuthenticator(page);
  await page.goto(PAGE);
  await page.click('#generate');
  const pub = await page.locator('#public-key').innerText();

  await page.click('#wrap-authenticator');
  await expect(page.locator('#authenticator-status')).toHaveText(/^wrapped /, { timeout: 15000 });
  const blobA = await page.locator('#authenticator-blob').innerText();

  // HR-9.2 requires at least TWO authenticators registered, because one is a single point
  // of failure for an account with no password fallback.
  await a.client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: a.authenticatorId });
  await addAuthenticator(page);

  await page.click('#wrap-authenticator');
  await expect(page.locator('#authenticator-status')).toHaveText(/^wrapped /, { timeout: 15000 });
  const blobB = await page.locator('#authenticator-blob').innerText();

  expect(blobB).not.toBe(blobA);

  // B opens the key on its own, without A present.
  await page.reload();
  await page.fill('#unwrap-authenticator-blob', blobB);
  await page.click('#unwrap-authenticator');
  await expect(page.locator('#unwrap-result')).toHaveText(/^ok /, { timeout: 15000 });
  await expect(page.locator('#unwrap-result')).toContainText(pub);
});

// GATE 3, SECOND PASS — this test was REWRITTEN because mutation testing proved the first
// version had no teeth. Recorded rather than quietly fixed: workflow §3.2 warns that a
// corrected intent and a moved goalpost look identical in a diff.
//
// The original removed authenticator A, added a fresh B, and tried A's blob. It passed —
// and it passed even when the wrapping key was replaced by a CONSTANT, which should have
// made every wrap openable by anything. The reason: the fresh authenticator held no
// credential at all, so navigator.credentials.get() found nothing and threw before any
// decryption was attempted. The test was asserting "a device with no credential cannot
// produce an assertion", which is true, trivial, and not the property HR-4.5 needs.
//
// The property that matters is: authenticator B, holding a perfectly good credential of
// its own, still cannot open A's wrap — because its prf output is different. So B now
// registers first, and the failure has to come from the AES-GCM tag check.
test('an authenticator with its OWN credential still cannot open another wrap', async ({ page }) => {
  const a = await addAuthenticator(page);
  await page.goto(PAGE);
  await page.click('#generate');
  await page.click('#wrap-authenticator');
  await expect(page.locator('#authenticator-status')).toHaveText(/^wrapped /, { timeout: 15000 });
  const blobA = await page.locator('#authenticator-blob').innerText();

  // Swap in a different authenticator and give it a real, working credential.
  await a.client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: a.authenticatorId });
  await addAuthenticator(page);

  await page.reload();
  await page.click('#generate');
  await page.click('#wrap-authenticator');
  await expect(page.locator('#authenticator-status')).toHaveText(/^wrapped /, { timeout: 15000 });
  const blobB = await page.locator('#authenticator-blob').innerText();

  // Sanity: B really can open its own wrap, so the failure below cannot be blamed on B
  // being unable to assert.
  await page.fill('#unwrap-authenticator-blob', blobB);
  await page.click('#unwrap-authenticator');
  await expect(page.locator('#unwrap-result')).toHaveText(/^ok /, { timeout: 15000 });

  // The real assertion: B asserts successfully, derives ITS prf output, and the AES-GCM
  // tag check rejects A's ciphertext.
  await page.fill('#unwrap-authenticator-blob', blobA);
  await page.click('#unwrap-authenticator');
  await expect(page.locator('#unwrap-result')).toHaveText(/^failed/, { timeout: 15000 });
});

test('the prf output never reaches web storage', async ({ page }) => {
  await addAuthenticator(page);
  await page.goto(PAGE);
  await page.click('#generate');
  await page.click('#wrap-authenticator');
  await expect(page.locator('#authenticator-status')).toHaveText(/^wrapped /, { timeout: 15000 });

  const stored = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));
  // HR-4.7: memory only, cleared on navigation. A prf output in web storage is a durable
  // decryption capability sitting where any script on the origin can read it - exactly
  // what §6.3's XSS finding must not be able to steal.
  expect(stored.local).toEqual([]);
  expect(stored.session).toEqual([]);
});
