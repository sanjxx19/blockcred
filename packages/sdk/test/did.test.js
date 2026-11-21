import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildDidWebDocument, DidWebResolver, didWebFromUrl, didWebToUrl, keyFromDidDocument } from '../src/did.js';

const jwk = (x) => ({ kty: 'EC', crv: 'P-256', x, y: 'y' });

describe('did:web', () => {
  it('maps DIDs to URLs', () => {
    assert.equal(didWebToUrl('did:web:example.com'), 'https://example.com/.well-known/did.json');
    assert.equal(didWebToUrl('did:web:localhost%3A4000'), 'https://localhost:4000/.well-known/did.json');
    assert.equal(didWebToUrl('did:web:user.github.io:college-a'), 'https://user.github.io/college-a/did.json');
    assert.equal(
      didWebToUrl('did:web:localhost%3A4000', { allowHttpHosts: ['localhost:4000'] }),
      'http://localhost:4000/.well-known/did.json',
    );
    assert.equal(
      didWebToUrl('did:web:localhost%3A4000', { hostOverrides: { 'localhost:4000': 'http://issuer:4000' } }),
      'http://issuer:4000/.well-known/did.json',
    );
  });

  it('rejects path traversal and malformed hosts', () => {
    assert.throws(() => didWebToUrl('did:web:evil.com%2F..'), { code: 'INVALID_DID' });
    assert.throws(() => didWebToUrl('did:web:a.com:..'), { code: 'INVALID_DID' });
    assert.throws(() => didWebToUrl('did:key:z6Mk'), { code: 'UNSUPPORTED_DID' });
  });

  it('round-trips URLs', () => {
    assert.equal(didWebFromUrl('http://localhost:4000'), 'did:web:localhost%3A4000');
    assert.equal(didWebFromUrl('https://u.github.io/college-a/'), 'did:web:u.github.io:college-a');
  });

  it('only returns keys authorised for assertionMethod and drops revoked keys', () => {
    const did = 'did:web:x.test';
    const doc = buildDidWebDocument({
      did,
      keys: [
        { id: 'key-1', publicJwk: jwk('a'), status: 'retired' },
        { id: 'key-2', publicJwk: jwk('b'), status: 'active' },
        { id: 'key-0', publicJwk: jwk('c'), status: 'revoked' },
      ],
    });
    assert.equal(keyFromDidDocument(doc, `${did}#key-1`).x, 'a');
    assert.equal(keyFromDidDocument(doc, '#key-2').x, 'b');
    assert.throws(() => keyFromDidDocument(doc, `${did}#key-0`), { code: 'KEY_NOT_AUTHORIZED' });
    assert.throws(() => keyFromDidDocument(doc, 'did:web:other.test#key-1'), { code: 'KEY_NOT_FOUND' });
  });

  it('resolves, validates id and caches', async () => {
    let calls = 0;
    const did = 'did:web:x.test';
    const resolver = new DidWebResolver({
      fetch: async () => {
        calls++;
        return { ok: true, status: 200, json: async () => ({ id: did }) };
      },
    });
    await resolver.resolve(did);
    await resolver.resolve(did);
    assert.equal(calls, 1);

    const bad = new DidWebResolver({ fetch: async () => ({ ok: true, json: async () => ({ id: 'did:web:evil' }) }) });
    await assert.rejects(bad.resolve(did), { code: 'DID_RESOLUTION_FAILED' });
  });
});
