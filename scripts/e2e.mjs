#!/usr/bin/env node
// End-to-end scenario through the public API, using four separate accounts:
//   admin approves university -> university issues to a student e-mail -> student signs up and
//   receives it -> employer requests -> student shares selectively -> VALID -> replay rejected
//   -> university revokes -> REVOKED
// Usage: npm run e2e   (against a running stack; reads ADMIN_* from .env)

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { exportPrivateJwk, exportPublicJwk, generateKeyPair, signJws, signerFromCryptoKey } from '@blockcred/sdk/jws';
import { deriveAuthSecret, wrapPrivateJwk } from '@blockcred/sdk/keywrap';
import { decodeSdJwt, presentSdJwt } from '@blockcred/sdk/sdjwt';
import { nowSeconds } from '@blockcred/sdk/util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
dotenv.config({ path: path.join(root, '.env') });
const BASE = (process.env.E2E_API_URL || process.env.PUBLIC_URL || 'http://localhost:4000').replace(/\/+$/, '');

let step = 0;
const log = (m) => console.log(`\n[${++step}] ${m}`);
const ok = (m) => console.log(`    ✓ ${m}`);

/** A logged-in actor with its own cookie jar. */
function actor() {
  let cookie = '';
  return async function call(p, { method = 'GET', body, expect = [200, 201] } = {}) {
    const res = await fetch(`${BASE}/api${p}`, {
      method,
      headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const data = await res.json().catch(() => ({}));
    if (!expect.includes(res.status)) throw new Error(`${method} ${p} -> ${res.status} ${JSON.stringify(data)}`);
    return data;
  };
}

const run = Date.now().toString(36);
const pw = 'demo-password-123';

async function main() {
  const admin = actor();
  const uni = actor();
  const student = actor();
  const employer = actor();

  log('Admin logs in');
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@blockcred.local').toLowerCase();
  await admin('/auth/login', { method: 'POST', body: { email: adminEmail, password: await deriveAuthSecret(adminEmail, process.env.ADMIN_PASSWORD) } });
  ok(adminEmail);

  log('University signs up and is approved on-chain');
  const uniEmail = `registrar-${run}@uni.example`;
  const me = await uni('/auth/signup', { method: 'POST', body: { role: 'university', email: uniEmail, name: `E2E University ${run}`, password: await deriveAuthSecret(uniEmail, pw) } });
  const ov = await admin('/admin/overview');
  const issuerRow = ov.issuers.find((i) => i.did === me.issuer.did);
  const approved = await admin(`/admin/issuers/${issuerRow.id}/approve`, { method: 'POST', body: {} });
  ok(`${me.issuer.did} -> ${approved.status} (tx ${approved.txHash})`);

  log('University issues a degree to a student who has no account yet');
  const studentEmail = `student-${run}@example.com`;
  const added = await uni('/university/credentials', {
    method: 'POST',
    body: { records: [{ student_email: studentEmail, student_id: `R${run}`, name: 'E2E Student', degree: 'B.Tech', major: 'CS', cgpa: 9.1, graduation_date: '2026-06-15' }] },
  });
  ok(`added=${added.added} awaiting=${added.awaitingSignup}`);

  log('Student signs up (wallet key generated client-side) and receives it automatically');
  const kp = await generateKeyPair({ extractable: true });
  const publicJwk = await exportPublicJwk(kp.publicKey);
  const holderSigner = signerFromCryptoKey(kp.privateKey);
  await student('/auth/signup', {
    method: 'POST',
    body: {
      role: 'student',
      email: studentEmail,
      name: 'E2E Student',
      password: await deriveAuthSecret(studentEmail, pw),
      holderPublicJwk: publicJwk,
      wrappedKey: await wrapPrivateJwk(await exportPrivateJwk(kp.privateKey), pw),
      holderProof: await signJws({ typ: 'blockcred-holder-proof+jwt', jwk: publicJwk }, { aud: 'blockcred-signup', nonce: studentEmail, iat: nowSeconds() }, holderSigner),
    },
  });
  const { credentials } = await student('/student/credentials');
  if (credentials.length !== 1) throw new Error('credential was not delivered');
  ok(`received ${decodeSdJwt(credentials[0].sdJwt).claims.degree} from ${credentials[0].issuer.name}`);

  log('University anchors the batch on-chain');
  const anchored = await uni('/university/anchor', { method: 'POST', body: {} });
  ok(JSON.stringify(anchored));

  log('Employer requests degree only');
  const empEmail = `hr-${run}@corp.example`;
  await employer('/auth/signup', { method: 'POST', body: { role: 'employer', email: empEmail, name: `E2E Corp ${run}`, password: await deriveAuthSecret(empEmail, pw) } });
  const created = await employer('/employer/requests', { method: 'POST', body: { studentEmail, fields: ['degree'], purpose: 'E2E hiring check' } });
  ok(`request ${created.id}`);

  log('Student sees it in the inbox and shares only the degree');
  const share = async () => {
    const { requests } = await student('/student/requests');
    const req = requests.find((r) => r.status === 'pending');
    const [cred] = (await student('/student/credentials')).credentials;
    const presentation = await presentSdJwt({ sdJwt: cred.sdJwt, disclose: ['degree'], holderSigner, aud: req.aud, nonce: req.nonce });
    const anchorProof = cred.anchor ? { root: cred.anchor.root, proof: cred.anchor.proof } : undefined;
    return { req, body: { presentation, anchorProof }, res: await student(`/student/requests/${req.id}/respond`, { method: 'POST', body: { presentation, anchorProof } }) };
  };
  const first = await share();
  if (first.res.verdict !== 'VALID') throw new Error(`expected VALID, got ${JSON.stringify(first.res)}`);
  const view = (await employer('/employer/requests')).requests.find((r) => r.id === created.id);
  if ('cgpa' in view.result.disclosed) throw new Error('CGPA leaked');
  ok(`employer sees ${view.verdict}: ${JSON.stringify(view.result.disclosed)} checks=${JSON.stringify(view.result.checks)}`);

  log('Replay: re-submitting the same presentation');
  await student(`/student/requests/${first.req.id}/respond`, { method: 'POST', body: first.body, expect: [409] });
  ok('rejected (request already answered)');

  log('University revokes; a new verification shows REVOKED');
  await uni(`/university/credentials/${credentials[0].id}/revoke`, { method: 'POST', body: { reason: 'E2E' } });
  await employer('/employer/requests', { method: 'POST', body: { studentEmail, fields: ['degree'], purpose: 'E2E re-check' } });
  const second = await share();
  if (second.res.verdict !== 'REVOKED') throw new Error(`expected REVOKED, got ${second.res.verdict}`);
  ok('REVOKED');

  console.log('\nAll end-to-end checks passed.');
}

main().catch((err) => {
  console.error(`\n✗ ${err.message}`);
  process.exit(1);
});
