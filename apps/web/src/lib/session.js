// Account + wallet-key handling in the browser.
//
// - The raw password never leaves the browser: we send deriveAuthSecret(email, password).
// - Students: a P-256 wallet key is generated here. The server receives only the public key
//   and a copy of the private key encrypted with the password (for multi-device login).
//   On this device the key is stored NON-EXTRACTABLE in IndexedDB and removed on logout.

import {
  exportPrivateJwk,
  exportPublicJwk,
  generateKeyPair,
  importPrivateJwk,
  jwkThumbprint,
  signJws,
  signerFromCryptoKey,
  toPublicJwk,
} from '@blockcred/sdk/jws';
import { deriveAuthSecret, unwrapPrivateJwk, wrapPrivateJwk } from '@blockcred/sdk/keywrap';
import { nowSeconds } from '@blockcred/sdk/util';
import { api } from './api.js';

const DB = 'blockcred-keys';

function idb(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction('keys', mode);
      const req = fn(tx.objectStore('keys'));
      tx.oncomplete = () => {
        db.close();
        resolve(req?.result);
      };
      tx.onerror = () => reject(tx.error);
    };
  });
}

export const getHolderKey = (userId) => idb('readonly', (s) => s.get(userId));
const removeHolderKey = (userId) => idb('readwrite', (s) => s.delete(userId));

async function storeHolderKey(userId, privateJwk) {
  const privateKey = await importPrivateJwk(privateJwk); // non-extractable from here on
  const publicJwk = toPublicJwk(privateJwk);
  const record = { privateKey, publicJwk, thumbprint: await jwkThumbprint(publicJwk) };
  await idb('readwrite', (s) => s.put(record, userId));
  return record;
}

export const holderSigner = (key) => signerFromCryptoKey(key.privateKey);
const norm = (email) => email.trim().toLowerCase();

export async function signup({ role, email, password, name }) {
  const e = norm(email);
  const body = { role, email: e, name, password: await deriveAuthSecret(e, password) };
  let privateJwk = null;
  if (role === 'student') {
    const kp = await generateKeyPair({ extractable: true });
    privateJwk = await exportPrivateJwk(kp.privateKey);
    const publicJwk = await exportPublicJwk(kp.publicKey);
    body.holderPublicJwk = publicJwk;
    body.wrappedKey = await wrapPrivateJwk(privateJwk, password);
    body.holderProof = await signJws(
      { typ: 'blockcred-holder-proof+jwt', jwk: publicJwk },
      { aud: 'blockcred-signup', nonce: e, iat: nowSeconds() },
      signerFromCryptoKey(kp.privateKey),
    );
  }
  const me = await api('/auth/signup', { method: 'POST', body });
  if (privateJwk) await storeHolderKey(me.user.id, privateJwk);
  return me;
}

export async function unlockWallet(me, password) {
  const existing = await getHolderKey(me.user.id);
  if (existing && existing.thumbprint === me.student.thumbprint) return existing;
  return storeHolderKey(me.user.id, await unwrapPrivateJwk(me.student.wrappedKey, password));
}

export async function login({ email, password }) {
  const e = norm(email);
  const me = await api('/auth/login', { method: 'POST', body: { email: e, password: await deriveAuthSecret(e, password) } });
  if (me.user.role === 'student') await unlockWallet(me, password);
  return me;
}

export async function logout(me) {
  await api('/auth/logout', { method: 'POST' }).catch(() => {});
  if (me?.user?.role === 'student') await removeHolderKey(me.user.id).catch(() => {});
}

export async function currentUser() {
  try {
    return await api('/auth/me');
  } catch {
    return null;
  }
}

export async function forgetLocalKey(userId) {
  await removeHolderKey(userId).catch(() => {});
}
