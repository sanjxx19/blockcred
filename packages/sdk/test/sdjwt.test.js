import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { exportPublicJwk, generateKeyPair, signerFromCryptoKey } from '../src/jws.js';
import { decodeSdJwt, issueSdJwt, parseSdJwt, presentSdJwt, verifySdJwt } from '../src/sdjwt.js';
import { b64urlJson, nowSeconds } from '../src/util.js';

async function setup() {
  const issuerKeys = await generateKeyPair();
  const holderKeys = await generateKeyPair();
  const issuerSigner = signerFromCryptoKey(issuerKeys.privateKey, { kid: 'did:web:issuer.test#key-1' });
  const holderSigner = signerFromCryptoKey(holderKeys.privateKey);
  const holderJwk = await exportPublicJwk(holderKeys.publicKey);
  const now = nowSeconds();
  const { sdJwt } = await issueSdJwt({
    claims: {
      iss: 'did:web:issuer.test',
      iat: now,
      exp: now + 3600,
      vct: 'urn:test',
      cnf: { jwk: holderJwk },
      name: 'Asha Rao',
      degree: 'B.Tech',
      cgpa: 8.7,
    },
    disclosable: ['name', 'degree', 'cgpa'],
    signer: issuerSigner,
    decoys: 2,
  });
  return { issuerKeys, holderKeys, holderSigner, sdJwt };
}

describe('SD-JWT', () => {
  it('hides disclosable claims from the signed payload', async () => {
    const { sdJwt } = await setup();
    const { payload, claims, disclosures } = decodeSdJwt(sdJwt);
    assert.equal(payload.cgpa, undefined);
    assert.equal(payload._sd.length, 5); // 3 real + 2 decoys
    assert.equal(disclosures.length, 3);
    assert.equal(claims.cgpa, 8.7);
  });

  it('verifies a selective presentation with key binding', async () => {
    const { issuerKeys, holderSigner, sdJwt } = await setup();
    const presentation = await presentSdJwt({ sdJwt, disclose: ['degree'], holderSigner, aud: 'verifier-1', nonce: 'n-123' });
    const res = await verifySdJwt(presentation, {
      issuerKey: issuerKeys.publicKey,
      requireKeyBinding: true,
      expectedAud: 'verifier-1',
      expectedNonce: 'n-123',
    });
    assert.deepEqual(res.disclosed, { degree: 'B.Tech' });
    assert.equal(res.claims.cgpa, undefined, 'CGPA must not be revealed');
    assert.ok(res.keyBinding.holderThumbprint);
  });

  it('rejects a replayed presentation (wrong nonce)', async () => {
    const { issuerKeys, holderSigner, sdJwt } = await setup();
    const presentation = await presentSdJwt({ sdJwt, disclose: [], holderSigner, aud: 'v', nonce: 'old' });
    await assert.rejects(
      verifySdJwt(presentation, { issuerKey: issuerKeys.publicKey, expectedAud: 'v', expectedNonce: 'new' }),
      { code: 'INVALID_NONCE' },
    );
  });

  it('rejects a presentation for another audience', async () => {
    const { issuerKeys, holderSigner, sdJwt } = await setup();
    const presentation = await presentSdJwt({ sdJwt, disclose: [], holderSigner, aud: 'evil', nonce: 'n' });
    await assert.rejects(verifySdJwt(presentation, { issuerKey: issuerKeys.publicKey, expectedAud: 'v' }), {
      code: 'INVALID_AUDIENCE',
    });
  });

  it('rejects a disclosure that was added after key binding (sd_hash)', async () => {
    const { issuerKeys, holderSigner, sdJwt } = await setup();
    const presentation = await presentSdJwt({ sdJwt, disclose: ['degree'], holderSigner, aud: 'v', nonce: 'n' });
    const { disclosures } = parseSdJwt(sdJwt);
    const parts = presentation.split('~');
    const tampered = [parts[0], parts[1], disclosures[0], parts[2]].join('~');
    await assert.rejects(verifySdJwt(tampered, { issuerKey: issuerKeys.publicKey }), (err) =>
      ['HOLDER_BINDING_FAILED', 'INVALID_FORMAT'].includes(err.code),
    );
  });

  it('rejects a forged disclosure', async () => {
    const { issuerKeys, sdJwt } = await setup();
    const { jwt } = parseSdJwt(sdJwt);
    const forged = `${jwt}~${b64urlJson(['salt', 'cgpa', 10])}~`;
    await assert.rejects(verifySdJwt(forged, { issuerKey: issuerKeys.publicKey }), { code: 'INVALID_SIGNATURE' });
  });

  it('rejects a credential signed by another key', async () => {
    const { sdJwt } = await setup();
    const other = await generateKeyPair();
    await assert.rejects(verifySdJwt(sdJwt, { issuerKey: other.publicKey }), { code: 'INVALID_SIGNATURE' });
  });

  it('rejects KB-JWT signed by a key other than cnf.jwk', async () => {
    const { issuerKeys, sdJwt } = await setup();
    const thief = await generateKeyPair();
    const presentation = await presentSdJwt({
      sdJwt,
      disclose: [],
      holderSigner: signerFromCryptoKey(thief.privateKey),
      aud: 'v',
      nonce: 'n',
    });
    await assert.rejects(verifySdJwt(presentation, { issuerKey: issuerKeys.publicKey }), {
      code: 'HOLDER_BINDING_FAILED',
    });
  });

  it('requires key binding when asked', async () => {
    const { issuerKeys, sdJwt } = await setup();
    await assert.rejects(verifySdJwt(sdJwt, { issuerKey: issuerKeys.publicKey, requireKeyBinding: true }), {
      code: 'HOLDER_BINDING_REQUIRED',
    });
  });

  it('rejects expired credentials and stale presentations', async () => {
    const { issuerKeys, holderSigner, sdJwt } = await setup();
    await assert.rejects(verifySdJwt(sdJwt, { issuerKey: issuerKeys.publicKey, now: nowSeconds() + 7200 }), {
      code: 'EXPIRED',
    });
    const presentation = await presentSdJwt({
      sdJwt,
      disclose: [],
      holderSigner,
      aud: 'v',
      nonce: 'n',
      iat: nowSeconds() - 3600,
    });
    await assert.rejects(verifySdJwt(presentation, { issuerKey: issuerKeys.publicKey }), {
      code: 'STALE_PRESENTATION',
    });
  });
});
