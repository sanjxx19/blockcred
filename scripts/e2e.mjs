#!/usr/bin/env node
// End-to-end scenario against running services (local or docker-compose):
//   issue -> redeem (holder binding) -> anchor -> selective disclosure -> VALID
//   -> replay attack -> REPLAY_DETECTED -> revoke -> REVOKED
// Usage: npm run e2e

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { exportPublicJwk, generateKeyPair, signJws, signerFromCryptoKey } from '@blockcred/sdk/jws';
import { decodeSdJwt, presentSdJwt } from '@blockcred/sdk/sdjwt';
import { nowSeconds } from '@blockcred/sdk/util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
dotenv.config({ path: path.join(root, '.env') });

const ISSUER = process.env.E2E_ISSUER_URL || process.env.ISSUER_PUBLIC_URL || 'http://localhost:4000';
const VERIFIER = process.env.E2E_VERIFIER_URL || process.env.VERIFIER_PUBLIC_URL || 'http://localhost:5000';
const ADMIN = process.env.ISSUER_ADMIN_API_KEY;

let step = 0;
const log = (msg) => console.log(`\n[${++step}] ${msg}`);
const ok = (msg) => console.log(`    ✓ ${msg}`);

async function http(url, { method = 'GET', body, headers = {}, expect = [200, 201] } = {}) {
  const res = await fetch(url, {
    method,
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!expect.includes(res.status)) throw new Error(`${method} ${url} -> ${res.status} ${JSON.stringify(data)}`);
  return data;
}
const admin = { authorization: `Bearer ${ADMIN}` };

async function newRequest(fields) {
  return http(`${VERIFIER}/requests`, { method: 'POST', body: { fields, purpose: 'E2E test' } });
}

async function main() {
  if (!ADMIN) throw new Error('ISSUER_ADMIN_API_KEY missing (run npm run setup)');

  log('Issuer creates a credential offer');
  const studentId = `E2E${Date.now()}`;
  const { offers } = await http(`${ISSUER}/admin/offers`, {
    method: 'POST',
    headers: admin,
    body: { records: [{ student_id: studentId, name: 'E2E Student', degree: 'B.Tech', major: 'CS', cgpa: 9.05, graduation_date: '2026-06-15' }] },
  });
  ok(`offer ${offers[0].offerId}`);

  log('Holder redeems the offer with proof of key possession');
  const holder = await generateKeyPair();
  const holderJwk = await exportPublicJwk(holder.publicKey);
  const holderSigner = signerFromCryptoKey(holder.privateKey);
  const did = (await http(`${ISSUER}/.well-known/did.json`)).id;
  const proof = await signJws({ typ: 'openid4vci-proof+jwt', jwk: holderJwk }, { aud: did, nonce: offers[0].offerCode, iat: nowSeconds() }, holderSigner);
  const issued = await http(`${ISSUER}/offers/${offers[0].offerCode}/redeem`, { method: 'POST', body: { proof } });
  const decoded = decodeSdJwt(issued.credential);
  ok(`credential ${issued.credentialId}, status index ${issued.statusIndex}, ${decoded.disclosures.length} hidden claims`);

  log('Offer codes are single-use');
  await http(`${ISSUER}/offers/${offers[0].offerCode}/redeem`, { method: 'POST', body: { proof }, expect: [409] });
  ok('second redemption rejected');

  log('Issuer anchors the pending batch on-chain');
  const anchor = await http(`${ISSUER}/admin/anchor`, { method: 'POST', headers: admin, body: {} });
  ok(anchor.root ? `root ${anchor.root} (${anchor.anchored} leaves, tx ${anchor.txHash})` : JSON.stringify(anchor));
  const anchorProof = await http(`${ISSUER}/credentials/${issued.credentialId}/anchor-proof`, { expect: [200, 202] });

  log('Verifier requests degree only; holder discloses degree (CGPA stays hidden)');
  const req1 = await newRequest(['degree']);
  const presentation = await presentSdJwt({
    sdJwt: issued.credential,
    disclose: ['degree'],
    holderSigner,
    aud: req1.request.aud,
    nonce: req1.request.nonce,
  });
  const body = { presentation, ...(anchorProof.root ? { anchorProof: { root: anchorProof.root, proof: anchorProof.proof } } : {}) };
  const r1 = await http(req1.request.response_uri, { method: 'POST', body, expect: [200, 422] });
  if (r1.verdict !== 'VALID') throw new Error(`expected VALID, got ${JSON.stringify(r1)}`);
  const view = await http(`${VERIFIER}/requests/${req1.id}`, { headers: { 'x-poll-token': req1.pollToken } });
  ok(`verdict VALID, verifier saw ${JSON.stringify(view.result.disclosed)}; checks ${JSON.stringify(view.result.checks)}`);
  if ('cgpa' in view.result.disclosed) throw new Error('CGPA leaked');

  log('Replay: resubmitting the same presentation');
  const r2 = await http(req1.request.response_uri, { method: 'POST', body, expect: [409] });
  ok(`rejected: ${r2.verdict}`);
  const req2 = await newRequest(['degree']);
  const r3 = await http(req2.request.response_uri, { method: 'POST', body, expect: [422] });
  ok(`replay into a fresh request rejected: ${r3.verdict}`);

  log('Issuer revokes the credential on-chain');
  const rev = await http(`${ISSUER}/admin/credentials/${issued.credentialId}/revoke`, { method: 'POST', headers: admin, body: { reason: 'E2E' } });
  ok(`tx ${rev.txHash}`);

  log('Verifier now sees REVOKED immediately');
  const req3 = await newRequest(['degree']);
  const p3 = await presentSdJwt({ sdJwt: issued.credential, disclose: ['degree'], holderSigner, aud: req3.request.aud, nonce: req3.request.nonce });
  const r4 = await http(req3.request.response_uri, { method: 'POST', body: { presentation: p3 }, expect: [422] });
  if (r4.verdict !== 'REVOKED') throw new Error(`expected REVOKED, got ${r4.verdict}`);
  ok('REVOKED');

  console.log('\nAll end-to-end checks passed.');
}

main().catch((err) => {
  console.error(`\n✗ ${err.message}`);
  process.exit(1);
});
