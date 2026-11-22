import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { exportPrivateJwk, generateKeyPair } from '../src/jws.js';
import { deriveAuthSecret, unwrapPrivateJwk, wrapPrivateJwk } from '../src/keywrap.js';

describe('keywrap', () => {
  it('derives a stable auth secret independent of email case', async () => {
    const a = await deriveAuthSecret('Asha@Example.com ', 'correct horse');
    const b = await deriveAuthSecret('asha@example.com', 'correct horse');
    const c = await deriveAuthSecret('asha@example.com', 'wrong');
    assert.equal(a, b);
    assert.notEqual(a, c);
    assert.ok(!a.includes('correct'));
  });

  it('wraps and unwraps a private key, rejecting the wrong password', async () => {
    const kp = await generateKeyPair({ extractable: true });
    const jwk = await exportPrivateJwk(kp.privateKey);
    const wrapped = await wrapPrivateJwk(jwk, 'pa55word!');
    assert.ok(!JSON.stringify(wrapped).includes(jwk.d));
    assert.deepEqual(await unwrapPrivateJwk(wrapped, 'pa55word!'), jwk);
    await assert.rejects(unwrapPrivateJwk(wrapped, 'nope'), { code: 'WRONG_PASSWORD' });
  });
});
