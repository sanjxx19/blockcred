import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DEGREE_DISCLOSABLE_CLAIMS, DEGREE_VCT, buildDegreeClaims } from '../src/credential.js';
import { DidWebResolver, buildDidWebDocument } from '../src/did.js';
import { exportPublicJwk, generateKeyPair, signerFromCryptoKey } from '../src/jws.js';
import { issueSdJwt, presentSdJwt } from '../src/sdjwt.js';
import { nowSeconds } from '../src/util.js';
import { BlockCredVerifier, Verdict } from '../src/verify.js';

const DID = 'did:web:college.test';
const REGISTRY = '0x5FbDB2315678afecb367f032d93F642f64180aa3';

function mockChain(state = {}) {
  return {
    chainId: 31337,
    addresses: { RevocationRegistry: REGISTRY },
    isAccredited: async () => state.accredited ?? true,
    isSchemaRegistered: async () => state.schema ?? true,
    isRevoked: async () => state.revoked ?? false,
    anchoredAt: async () => 0,
  };
}

async function fixture({ registry = REGISTRY } = {}) {
  const issuerKeys = await generateKeyPair();
  const holderKeys = await generateKeyPair();
  const issuerJwk = await exportPublicJwk(issuerKeys.publicKey);
  const doc = buildDidWebDocument({ did: DID, keys: [{ id: 'key-1', publicJwk: issuerJwk, status: 'active' }] });
  const didResolver = new DidWebResolver({ fetch: async () => ({ ok: true, json: async () => doc }) });
  const now = nowSeconds();
  const claims = buildDegreeClaims({
    issuerDid: DID,
    issuerName: 'College',
    credentialId: '00000000-0000-4000-8000-000000000001',
    holderJwk: await exportPublicJwk(holderKeys.publicKey),
    statusIndex: 42,
    chainId: 31337,
    revocationRegistry: registry,
    subject: { student_id: 'S1', name: 'Asha', degree: 'B.Tech', cgpa: 9.1, graduation_date: '2026-06-01' },
    issuedAt: now,
    expiresAt: now + 3600,
  });
  const { sdJwt } = await issueSdJwt({
    claims,
    disclosable: DEGREE_DISCLOSABLE_CLAIMS,
    signer: signerFromCryptoKey(issuerKeys.privateKey, { kid: `${DID}#key-1` }),
  });
  const presentation = await presentSdJwt({
    sdJwt,
    disclose: ['degree'],
    holderSigner: signerFromCryptoKey(holderKeys.privateKey),
    aud: 'verifier',
    nonce: 'n1',
  });
  return { didResolver, presentation };
}

describe('BlockCredVerifier', () => {
  it('returns VALID with only disclosed claims', async () => {
    const { didResolver, presentation } = await fixture();
    const v = new BlockCredVerifier({ chain: mockChain(), didResolver, audience: 'verifier' });
    const res = await v.verify(presentation, { nonce: 'n1' });
    assert.equal(res.verdict, Verdict.VALID, res.error);
    assert.deepEqual(res.disclosed, { degree: 'B.Tech' });
    assert.equal(res.credential.type, DEGREE_VCT);
  });

  it('maps on-chain state to verdicts', async () => {
    const { didResolver, presentation } = await fixture();
    const verdict = async (state) =>
      (await new BlockCredVerifier({ chain: mockChain(state), didResolver, audience: 'verifier' }).verify(presentation, { nonce: 'n1' })).verdict;
    assert.equal(await verdict({ revoked: true }), Verdict.REVOKED);
    assert.equal(await verdict({ accredited: false }), Verdict.UNTRUSTED_ISSUER);
    assert.equal(await verdict({ schema: false }), Verdict.UNKNOWN_SCHEMA);
  });

  it('detects replay via nonce', async () => {
    const { didResolver, presentation } = await fixture();
    const v = new BlockCredVerifier({ chain: mockChain(), didResolver, audience: 'verifier' });
    assert.equal((await v.verify(presentation, { nonce: 'other' })).verdict, Verdict.REPLAY_DETECTED);
  });

  it('rejects credentials pointing at an attacker-controlled status registry', async () => {
    const { didResolver, presentation } = await fixture({ registry: '0x000000000000000000000000000000000000dEaD' });
    const v = new BlockCredVerifier({ chain: mockChain(), didResolver, audience: 'verifier' });
    assert.equal((await v.verify(presentation, { nonce: 'n1' })).verdict, Verdict.WRONG_STATUS_REGISTRY);
  });
});
