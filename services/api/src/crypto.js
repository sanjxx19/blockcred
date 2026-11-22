import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');
export const newToken = (bytes = 32) => randomBytes(bytes).toString('base64url');

/**
 * Envelope encryption for secrets at rest (issuer signing keys, controller keys).
 * Production: replace with a cloud KMS / HSM (same seal/open interface).
 */
export function createSecretBox(masterKeyB64) {
  const key = Buffer.from(masterKeyB64, 'base64');
  if (key.length !== 32) throw new Error('MASTER_ENCRYPTION_KEY must be 32 bytes, base64-encoded');
  return {
    seal(value) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
      return ['v1', iv.toString('base64url'), ct.toString('base64url'), cipher.getAuthTag().toString('base64url')].join('.');
    },
    open(sealed) {
      const [v, iv, ct, tag] = sealed.split('.');
      if (v !== 'v1') throw new Error('Unknown secret format');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8'));
    },
  };
}

/** Hashes the client-derived auth secret (never the raw password) with scrypt. */
export async function hashSecret(secret) {
  const salt = randomBytes(16);
  const dk = await scryptAsync(secret, salt, 64, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64url')}$${dk.toString('base64url')}`;
}

export async function verifySecret(secret, stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(hash, 'base64url');
  const dk = await scryptAsync(secret, Buffer.from(salt, 'base64url'), expected.length, {
    N: Number(N),
    r: Number(r),
    p: Number(p),
    maxmem: SCRYPT.maxmem,
  });
  return timingSafeEqual(dk, expected);
}
