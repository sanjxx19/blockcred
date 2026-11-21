// Browser holder wallet. The private key is a NON-EXTRACTABLE WebCrypto key kept
// in IndexedDB: page scripts can use it to sign but can never read it out.
// (Production: hardware-backed keys in a native wallet — see docs/ARCHITECTURE.md.)

import { exportPublicJwk, generateKeyPair, jwkThumbprint, signJws, signerFromCryptoKey } from '@blockcred/sdk/jws';
import { decodeSdJwt, presentSdJwt } from '@blockcred/sdk/sdjwt';
import { nowSeconds } from '@blockcred/sdk/util';
import { api } from './api.js';

const DB_NAME = 'blockcred-wallet';
const DB_VERSION = 1;

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore('keys');
      db.createObjectStore('credentials', { keyPath: 'id' });
      db.createObjectStore('consents', { keyPath: 'id', autoIncrement: true });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run(storeName, mode, fn) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode);
    const request = fn(tx.objectStore(storeName));
    tx.oncomplete = () => {
      db.close();
      resolve(request?.result);
    };
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

export async function getHolderKey({ create = true } = {}) {
  const existing = await run('keys', 'readonly', (s) => s.get('holder'));
  if (existing || !create) return existing ?? null;
  const { privateKey, publicKey } = await generateKeyPair({ extractable: false });
  const publicJwk = await exportPublicJwk(publicKey);
  const record = { privateKey, publicKey, publicJwk, thumbprint: await jwkThumbprint(publicJwk), createdAt: new Date().toISOString() };
  await run('keys', 'readwrite', (s) => s.put(record, 'holder'));
  return record;
}

export async function listCredentials() {
  const all = (await run('credentials', 'readonly', (s) => s.getAll())) ?? [];
  return all
    .map((c) => ({ ...c, decoded: decodeSdJwt(c.sdJwt) }))
    .sort((a, b) => b.receivedAt.localeCompare(a.receivedAt));
}

export const deleteCredential = (id) => run('credentials', 'readwrite', (s) => s.delete(id));

/** Redeems an issuer offer: proves possession of the holder key, receives a bound SD-JWT VC. */
export async function redeemOffer(issuerUrl, code) {
  const base = issuerUrl.replace(/\/+$/, '');
  const holder = await getHolderKey();
  const didDoc = await api(base, '/.well-known/did.json');
  const proof = await signJws(
    { typ: 'openid4vci-proof+jwt', jwk: holder.publicJwk },
    { aud: didDoc.id, nonce: code, iat: nowSeconds() },
    signerFromCryptoKey(holder.privateKey),
  );
  const res = await api(base, `/offers/${encodeURIComponent(code)}/redeem`, { method: 'POST', body: { proof } });
  const decoded = decodeSdJwt(res.credential);
  if (decoded.payload.iss !== didDoc.id) throw new Error('Issuer returned a credential for a different DID');
  if ((await jwkThumbprint(decoded.payload.cnf.jwk)) !== holder.thumbprint) {
    throw new Error('Credential is not bound to this wallet key');
  }
  const record = {
    id: res.credentialId,
    sdJwt: res.credential,
    issuerUrl: base,
    issuerDid: didDoc.id,
    receivedAt: new Date().toISOString(),
    anchorProof: null,
  };
  await run('credentials', 'readwrite', (s) => s.put(record));
  return record;
}

export async function refreshAnchorProof(credential) {
  const res = await api(credential.issuerUrl, `/credentials/${credential.id}/anchor-proof`);
  if (res.status !== 'anchored') return null;
  const { decoded, ...stored } = credential;
  const updated = { ...stored, anchorProof: { root: res.root, proof: res.proof, txHash: res.txHash, anchoredAt: res.anchoredAt } };
  await run('credentials', 'readwrite', (s) => s.put(updated));
  return updated.anchorProof;
}

export function parseRequest(input) {
  const req = typeof input === 'string' ? JSON.parse(input) : input;
  if (req?.type !== 'blockcred-presentation-request' || !req.nonce || !req.aud || !req.response_uri) {
    throw new Error('Not a BlockCred presentation request');
  }
  if (new Date(req.expires_at) < new Date()) throw new Error('This request has expired');
  const uri = new URL(req.response_uri);
  if (uri.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(uri.hostname)) {
    throw new Error('Refusing to send credentials over plain HTTP');
  }
  return req;
}

/** Creates a key-bound presentation with only the chosen fields and submits it to the verifier. */
export async function presentToVerifier(credential, request, fields) {
  const holder = await getHolderKey({ create: false });
  if (!holder) throw new Error('Wallet key missing');
  const presentation = await presentSdJwt({
    sdJwt: credential.sdJwt,
    disclose: fields,
    holderSigner: signerFromCryptoKey(holder.privateKey),
    aud: request.aud,
    nonce: request.nonce,
  });
  const anchorProof = credential.anchorProof ? { root: credential.anchorProof.root, proof: credential.anchorProof.proof } : undefined;
  const res = await fetch(request.response_uri, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ presentation, anchorProof }),
  });
  const result = await res.json().catch(() => ({ verdict: `HTTP_${res.status}` }));
  await run('consents', 'readwrite', (s) =>
    s.add({
      at: new Date().toISOString(),
      verifier: request.verifier?.name ?? request.aud,
      audience: request.aud,
      purpose: request.purpose,
      credentialId: credential.id,
      fields,
      verdict: result.verdict,
    }),
  );
  return result;
}

export async function listConsents() {
  const all = (await run('consents', 'readonly', (s) => s.getAll())) ?? [];
  return all.reverse();
}

/** Right to erasure for the holder's copy: deletes keys, credentials and consent history. */
export function wipeWallet() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
}
