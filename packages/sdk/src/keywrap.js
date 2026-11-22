// Password-based helpers used by the web app (and any other client):
//
//  deriveAuthSecret(email, password)
//    -> the value sent to the server instead of the password. The server never
//       learns the password itself, so it cannot derive the wallet-wrapping key.
//
//  wrapPrivateJwk / unwrapPrivateJwk
//    -> the student's holder key is encrypted IN THE BROWSER with a key derived
//       from the password (PBKDF2 + AES-GCM). The server only stores the
//       ciphertext, so the student can log in from any device while the
//       platform can never use their key.

import { BlockCredError, b64urlDecode, b64urlEncode, fromUtf8, randomBytes, utf8 } from './util.js';

export const AUTH_ITERATIONS = 100_000;
export const WRAP_ITERATIONS = 310_000;

const normaliseEmail = (email) => String(email).trim().toLowerCase();

async function pbkdf2(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', utf8(String(password).normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256));
}

export async function deriveAuthSecret(email, password) {
  const salt = utf8(`blockcred-auth-v1:${normaliseEmail(email)}`);
  return b64urlEncode(await pbkdf2(password, salt, AUTH_ITERATIONS));
}

async function wrappingKey(password, salt, iterations) {
  const bits = await pbkdf2(password, salt, iterations);
  return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function wrapPrivateJwk(privateJwk, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await wrappingKey(password, salt, WRAP_ITERATIONS);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8(JSON.stringify(privateJwk))));
  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: WRAP_ITERATIONS,
    salt: b64urlEncode(salt),
    iv: b64urlEncode(iv),
    ciphertext: b64urlEncode(ct),
  };
}

export async function unwrapPrivateJwk(wrapped, password) {
  if (!wrapped || wrapped.v !== 1 || wrapped.kdf !== 'PBKDF2-SHA256') {
    throw new BlockCredError('INVALID_FORMAT', 'Unsupported wrapped key format');
  }
  const key = await wrappingKey(password, b64urlDecode(wrapped.salt), wrapped.iterations);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlDecode(wrapped.iv) }, key, b64urlDecode(wrapped.ciphertext));
    return JSON.parse(fromUtf8(new Uint8Array(pt)));
  } catch {
    throw new BlockCredError('WRONG_PASSWORD', 'Could not unlock the wallet key with this password');
  }
}
