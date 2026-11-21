// SD-JWT (IETF Selective Disclosure for JWTs) + SD-JWT VC, ES256 only.
// Supports top-level selectively-disclosable claims, decoy digests and
// Key Binding JWTs (holder binding + replay protection via aud/nonce).

import { decodeJws, jwkThumbprint, signJws, verifyJws } from './jws.js';
import { BlockCredError, b64urlEncode, b64urlJson, nowSeconds, parseB64urlJson, randomBytes, sha256 } from './util.js';

export const SD_JWT_TYP = 'dc+sd-jwt';
const LEGACY_SD_JWT_TYP = 'vc+sd-jwt';
export const KB_JWT_TYP = 'kb+jwt';
const RESERVED_NAMES = new Set(['_sd', '_sd_alg', '...']);

const digestOf = async (encodedDisclosure) => b64urlEncode(await sha256(encodedDisclosure));

export async function createDisclosure(name, value) {
  if (RESERVED_NAMES.has(name)) throw new BlockCredError('INVALID_FORMAT', `Reserved claim name ${name}`);
  const salt = b64urlEncode(randomBytes(16));
  const encoded = b64urlJson([salt, name, value]);
  return { salt, name, value, encoded, digest: await digestOf(encoded) };
}

export function decodeDisclosure(encoded) {
  const arr = parseB64urlJson(encoded);
  if (!Array.isArray(arr) || arr.length !== 3 || typeof arr[0] !== 'string' || typeof arr[1] !== 'string') {
    throw new BlockCredError('INVALID_FORMAT', 'Unsupported disclosure (only object-property disclosures are supported)');
  }
  if (RESERVED_NAMES.has(arr[1])) throw new BlockCredError('INVALID_FORMAT', `Reserved claim name ${arr[1]}`);
  return { salt: arr[0], name: arr[1], value: arr[2], encoded };
}

/**
 * Issues an SD-JWT.
 * @param {object} p
 * @param {object} p.claims       all claims (both always-visible and disclosable)
 * @param {string[]} p.disclosable names of claims to make selectively disclosable
 * @param {object} p.signer       issuer signer (see jws.js)
 * @param {object} [p.header]     extra protected header params (e.g. kid)
 * @param {number} [p.decoys=0]   decoy digests to hide the real number of claims
 */
export async function issueSdJwt({ claims, disclosable = [], signer, header = {}, decoys = 0 }) {
  const payload = {};
  const disclosures = [];
  const digests = [];
  for (const [name, value] of Object.entries(claims)) {
    if (RESERVED_NAMES.has(name)) throw new BlockCredError('INVALID_FORMAT', `Reserved claim name ${name}`);
    if (value === undefined) continue;
    if (disclosable.includes(name)) {
      const d = await createDisclosure(name, value);
      disclosures.push(d);
      digests.push(d.digest);
    } else {
      payload[name] = value;
    }
  }
  for (let i = 0; i < decoys; i++) digests.push(b64urlEncode(await sha256(randomBytes(32))));
  if (digests.length) {
    payload._sd = digests.sort(); // sorting hides claim order
    payload._sd_alg = 'sha-256';
  }
  const jwt = await signJws({ typ: SD_JWT_TYP, ...header }, payload, signer);
  return { sdJwt: `${[jwt, ...disclosures.map((d) => d.encoded)].join('~')}~`, jwt, disclosures };
}

export function parseSdJwt(compact) {
  if (typeof compact !== 'string' || !compact.includes('~')) {
    throw new BlockCredError('INVALID_FORMAT', 'Not an SD-JWT (missing "~" separator)');
  }
  const parts = compact.split('~');
  const last = parts[parts.length - 1];
  const disclosures = parts.slice(1, -1);
  if (disclosures.some((d) => d === '')) throw new BlockCredError('INVALID_FORMAT', 'Empty disclosure');
  return { jwt: parts[0], disclosures, kbJwt: last === '' ? null : last };
}

/** Decodes an SD-JWT WITHOUT verification (for wallet display only). */
export function decodeSdJwt(compact) {
  const { jwt, disclosures, kbJwt } = parseSdJwt(compact);
  const { header, payload } = decodeJws(jwt);
  const decoded = disclosures.map(decodeDisclosure);
  const claims = { ...payload };
  delete claims._sd;
  delete claims._sd_alg;
  for (const d of decoded) claims[d.name] = d.value;
  return { header, payload, claims, disclosures: decoded, kbJwt };
}

/**
 * Builds a presentation: keeps only the chosen disclosures and (optionally)
 * appends a Key Binding JWT bound to the verifier's audience + nonce.
 */
export async function presentSdJwt({ sdJwt, disclose = [], holderSigner, aud, nonce, iat }) {
  const { jwt, disclosures } = parseSdJwt(sdJwt);
  const selected = disclosures.map(decodeDisclosure).filter((d) => disclose.includes(d.name));
  const base = `${[jwt, ...selected.map((d) => d.encoded)].join('~')}~`;
  if (!holderSigner) return base;
  if (!aud || !nonce) throw new BlockCredError('INVALID_REQUEST', 'aud and nonce are required for key binding');
  const sdHash = b64urlEncode(await sha256(base));
  const kb = await signJws({ typ: KB_JWT_TYP }, { iat: iat ?? nowSeconds(), aud, nonce, sd_hash: sdHash }, holderSigner);
  return base + kb;
}

/**
 * Verifies an SD-JWT (optionally with KB-JWT).
 * @param {string} compact
 * @param {object} opts
 * @param {CryptoKey|object} [opts.issuerKey]          issuer public key
 * @param {(header, payload) => Promise<object>} [opts.resolveIssuerKey] alternative key lookup
 * @param {boolean} [opts.requireKeyBinding=false]
 * @param {string}  [opts.expectedAud]
 * @param {string}  [opts.expectedNonce]
 * @param {number}  [opts.now]                          unix seconds
 * @param {number}  [opts.clockSkewSec=60]
 * @param {number}  [opts.kbMaxAgeSec=300]
 */
export async function verifySdJwt(compact, opts = {}) {
  const { requireKeyBinding = false, expectedAud, expectedNonce, clockSkewSec = 60, kbMaxAgeSec = 300 } = opts;
  const now = opts.now ?? nowSeconds();
  const { jwt, disclosures, kbJwt } = parseSdJwt(compact);

  const unverified = decodeJws(jwt);
  if (![SD_JWT_TYP, LEGACY_SD_JWT_TYP].includes(unverified.header.typ)) {
    throw new BlockCredError('INVALID_FORMAT', `Unexpected typ ${unverified.header.typ}`);
  }
  const key = opts.issuerKey ?? (await opts.resolveIssuerKey?.(unverified.header, unverified.payload));
  if (!key) throw new BlockCredError('UNTRUSTED_ISSUER', 'No issuer key available');
  const { header, payload } = await verifyJws(jwt, key);

  if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256') {
    throw new BlockCredError('INVALID_FORMAT', `Unsupported _sd_alg ${payload._sd_alg}`);
  }
  const sdDigests = new Set(Array.isArray(payload._sd) ? payload._sd : []);
  const claims = { ...payload };
  delete claims._sd;
  delete claims._sd_alg;
  const disclosed = {};
  const seen = new Set();
  for (const encoded of disclosures) {
    const d = decodeDisclosure(encoded);
    const digest = await digestOf(encoded);
    if (seen.has(digest)) throw new BlockCredError('INVALID_FORMAT', 'Duplicate disclosure');
    seen.add(digest);
    if (!sdDigests.has(digest)) throw new BlockCredError('INVALID_SIGNATURE', 'Disclosure not covered by issuer signature');
    if (Object.hasOwn(claims, d.name)) throw new BlockCredError('INVALID_FORMAT', `Claim ${d.name} disclosed twice`);
    claims[d.name] = d.value;
    disclosed[d.name] = d.value;
  }

  if (typeof payload.exp === 'number' && now > payload.exp + clockSkewSec) {
    throw new BlockCredError('EXPIRED', 'Credential has expired');
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now + clockSkewSec) {
    throw new BlockCredError('NOT_YET_VALID', 'Credential is not yet valid');
  }
  if (typeof payload.iat === 'number' && payload.iat > now + clockSkewSec) {
    throw new BlockCredError('NOT_YET_VALID', 'Credential issued in the future');
  }

  let keyBinding = null;
  if (kbJwt) {
    const holderJwk = payload.cnf?.jwk;
    if (!holderJwk) throw new BlockCredError('HOLDER_BINDING_FAILED', 'Credential has no cnf.jwk');
    let kb;
    try {
      kb = await verifyJws(kbJwt, holderJwk);
    } catch (err) {
      throw new BlockCredError('HOLDER_BINDING_FAILED', `Key binding JWT invalid: ${err.message}`);
    }
    if (kb.header.typ !== KB_JWT_TYP) throw new BlockCredError('HOLDER_BINDING_FAILED', 'KB-JWT has wrong typ');
    const expectedSdHash = b64urlEncode(await sha256(compact.slice(0, compact.length - kbJwt.length)));
    if (kb.payload.sd_hash !== expectedSdHash) {
      throw new BlockCredError('HOLDER_BINDING_FAILED', 'KB-JWT sd_hash mismatch (presentation was altered)');
    }
    if (expectedAud !== undefined && kb.payload.aud !== expectedAud) {
      throw new BlockCredError('INVALID_AUDIENCE', 'Presentation was created for a different verifier');
    }
    if (expectedNonce !== undefined && kb.payload.nonce !== expectedNonce) {
      throw new BlockCredError('INVALID_NONCE', 'Nonce mismatch (possible replay)');
    }
    const iat = kb.payload.iat;
    if (typeof iat !== 'number' || iat > now + clockSkewSec || now - iat > kbMaxAgeSec) {
      throw new BlockCredError('STALE_PRESENTATION', 'Key binding JWT is too old or from the future');
    }
    keyBinding = { aud: kb.payload.aud, nonce: kb.payload.nonce, iat, holderThumbprint: await jwkThumbprint(holderJwk) };
  } else if (requireKeyBinding) {
    throw new BlockCredError('HOLDER_BINDING_REQUIRED', 'Presentation must include a key binding JWT');
  }

  return { header, payload, claims, disclosed, keyBinding, issuerJwt: jwt };
}
