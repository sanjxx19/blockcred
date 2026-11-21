// Minimal, strict JWS (compact serialization) for ES256 on WebCrypto.
// Only ES256 (ECDSA P-256 / SHA-256) is accepted: no `alg` confusion, no `none`.

import {
  BlockCredError,
  b64urlDecode,
  b64urlEncode,
  b64urlJson,
  parseB64urlJson,
  sha256,
  utf8,
} from './util.js';

const EC_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_PARAMS = { name: 'ECDSA', hash: 'SHA-256' };
export const SUPPORTED_ALG = 'ES256';

function assertP256Jwk(jwk, needPrivate = false) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new BlockCredError('UNSUPPORTED_KEY', 'Only EC P-256 JWKs are supported');
  }
  if (needPrivate && typeof jwk.d !== 'string') {
    throw new BlockCredError('UNSUPPORTED_KEY', 'Private JWK is missing "d"');
  }
}

const isCryptoKey = (k) => typeof CryptoKey !== 'undefined' && k instanceof CryptoKey;

/** Returns only the public members of a JWK (never leaks `d`). */
export function toPublicJwk(jwk) {
  assertP256Jwk(jwk);
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

export async function importPublicJwk(jwk) {
  return crypto.subtle.importKey('jwk', { ...toPublicJwk(jwk), ext: true }, EC_PARAMS, true, ['verify']);
}

export async function importPrivateJwk(jwk) {
  assertP256Jwk(jwk, true);
  const { kty, crv, x, y, d } = jwk;
  return crypto.subtle.importKey('jwk', { kty, crv, x, y, d }, EC_PARAMS, false, ['sign']);
}

/** Generates a P-256 key pair. Keep `extractable=false` for wallets. */
export async function generateKeyPair({ extractable = false } = {}) {
  return crypto.subtle.generateKey(EC_PARAMS, extractable, ['sign', 'verify']);
}

export async function exportPublicJwk(publicKey) {
  return toPublicJwk(await crypto.subtle.exportKey('jwk', publicKey));
}

export async function exportPrivateJwk(privateKey) {
  const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', privateKey);
  return { kty, crv, x, y, d };
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export async function jwkThumbprint(jwk) {
  const { crv, kty, x, y } = toPublicJwk(jwk);
  return b64urlEncode(await sha256(JSON.stringify({ crv, kty, x, y })));
}

/**
 * A Signer is the only thing that touches private key material:
 *   { alg: 'ES256', kid?: string, sign(data: Uint8Array): Promise<Uint8Array /* r||s, 64 bytes *\/> }
 * Swap in an HSM / cloud-KMS backed implementation in production
 * (convert DER signatures to raw r||s if your KMS returns DER).
 */
export function signerFromCryptoKey(privateKey, { kid } = {}) {
  return {
    alg: SUPPORTED_ALG,
    kid,
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS, privateKey, data));
    },
  };
}

export async function signerFromJwk(privateJwk, opts) {
  return signerFromCryptoKey(await importPrivateJwk(privateJwk), opts);
}

export async function signJws(header, payload, signer) {
  if (signer.alg !== SUPPORTED_ALG) throw new BlockCredError('UNSUPPORTED_ALG', `Unsupported alg ${signer.alg}`);
  const protectedHeader = { ...header, alg: signer.alg };
  if (signer.kid && !protectedHeader.kid && !protectedHeader.jwk) protectedHeader.kid = signer.kid;
  const signingInput = `${b64urlJson(protectedHeader)}.${b64urlJson(payload)}`;
  const signature = await signer.sign(utf8(signingInput));
  return `${signingInput}.${b64urlEncode(signature)}`;
}

/** Decodes WITHOUT verifying. Never trust the result before verifyJws(). */
export function decodeJws(jws) {
  if (typeof jws !== 'string') throw new BlockCredError('INVALID_FORMAT', 'JWS must be a string');
  const parts = jws.split('.');
  if (parts.length !== 3) throw new BlockCredError('INVALID_FORMAT', 'JWS must have 3 parts');
  const header = parseB64urlJson(parts[0]);
  const payload = parseB64urlJson(parts[1]);
  if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') {
    throw new BlockCredError('INVALID_FORMAT', 'JWS header and payload must be JSON objects');
  }
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: b64urlDecode(parts[2]) };
}

/** Verifies an ES256 JWS against a CryptoKey or public JWK. Throws INVALID_SIGNATURE on failure. */
export async function verifyJws(jws, publicKey) {
  const decoded = decodeJws(jws);
  if (decoded.header.alg !== SUPPORTED_ALG) {
    throw new BlockCredError('UNSUPPORTED_ALG', `Unsupported alg ${decoded.header.alg}`);
  }
  if (decoded.header.crit !== undefined) {
    throw new BlockCredError('INVALID_FORMAT', 'Critical header parameters are not supported');
  }
  if (decoded.signature.length !== 64) throw new BlockCredError('INVALID_SIGNATURE', 'Malformed ES256 signature');
  const key = isCryptoKey(publicKey) ? publicKey : await importPublicJwk(publicKey);
  const ok = await crypto.subtle.verify(SIGN_PARAMS, key, decoded.signature, utf8(decoded.signingInput));
  if (!ok) throw new BlockCredError('INVALID_SIGNATURE', 'Signature verification failed');
  return decoded;
}
