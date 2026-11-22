import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { mapDigiLockerDocument, parseRecords } from '../src/credentials.js';
import { createSecretBox, hashSecret, verifySecret } from '../src/crypto.js';

describe('api helpers', () => {
  it('parses the sample CSV', () => {
    const csv = readFileSync(new URL('../../../samples/students.csv', import.meta.url), 'utf8');
    const rows = parseRecords(csv, 'text/csv');
    assert.ok(rows.length >= 3);
    assert.match(rows[0].student_email, /@/);
    assert.equal(typeof rows[0].cgpa, 'number');
    assert.throws(() => parseRecords('student_email,name\nx@y.z,A', 'text/csv'), /Row 1/);
  });

  it('maps mocked DigiLocker documents', () => {
    const { documents } = JSON.parse(readFileSync(new URL('../../../samples/digilocker-mock.json', import.meta.url), 'utf8'));
    assert.match(mapDigiLockerDocument(documents[0]).graduation_date, /^\d{4}-\d{2}-\d{2}$/);
  });

  it('seals and opens secrets', () => {
    const box = createSecretBox(randomBytes(32).toString('base64'));
    const sealed = box.seal({ d: 'secret' });
    assert.ok(!sealed.includes('secret'));
    assert.deepEqual(box.open(sealed), { d: 'secret' });
    const other = createSecretBox(randomBytes(32).toString('base64'));
    assert.throws(() => other.open(sealed));
  });

  it('hashes and verifies auth secrets', async () => {
    const h = await hashSecret('abc');
    assert.equal(await verifySecret('abc', h), true);
    assert.equal(await verifySecret('abd', h), false);
  });
});
