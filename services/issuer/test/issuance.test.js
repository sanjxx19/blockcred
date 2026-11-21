import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { exportPublicJwk, generateKeyPair, signJws, signerFromCryptoKey } from '@blockcred/sdk/jws';
import { nowSeconds } from '@blockcred/sdk/util';
import { PROOF_TYP, mapDigiLockerDocument, parseRecords, verifyHolderProof } from '../src/issuance.js';

describe('issuance helpers', () => {
  it('parses CSV and validates rows', () => {
    const csv = readFileSync(new URL('../../../samples/students.csv', import.meta.url), 'utf8');
    const rows = parseRecords(csv, 'text/csv');
    assert.ok(rows.length >= 3);
    assert.equal(typeof rows[0].cgpa, 'number');
    assert.throws(() => parseRecords('student_id,name\nS1,A', 'text/csv'), /Record 1/);
  });

  it('maps mocked DigiLocker documents', () => {
    const { documents } = JSON.parse(readFileSync(new URL('../../../samples/digilocker-mock.json', import.meta.url), 'utf8'));
    const subject = mapDigiLockerDocument(documents[0]);
    assert.match(subject.graduation_date, /^\d{4}-\d{2}-\d{2}$/);
  });

  it('verifies holder proof of possession', async () => {
    const kp = await generateKeyPair();
    const jwk = await exportPublicJwk(kp.publicKey);
    const signer = signerFromCryptoKey(kp.privateKey);
    const proof = await signJws({ typ: PROOF_TYP, jwk }, { aud: 'did:web:i', nonce: 'code', iat: nowSeconds() }, signer);
    assert.deepEqual(await verifyHolderProof(proof, { issuerDid: 'did:web:i', code: 'code' }), jwk);
    await assert.rejects(verifyHolderProof(proof, { issuerDid: 'did:web:other', code: 'code' }), { code: 'INVALID_PROOF' });
    await assert.rejects(verifyHolderProof(proof, { issuerDid: 'did:web:i', code: 'other' }), { code: 'INVALID_PROOF' });
  });
});
