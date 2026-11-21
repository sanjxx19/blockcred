// did:web resolution (https://w3c-ccg.github.io/did-method-web/) with a
// bounded TTL cache, timeouts, and optional dev-only overrides.

import { BlockCredError } from './util.js';

/** did:web:example.com:path -> https://example.com/path/did.json */
export function didWebToUrl(did, { hostOverrides = {}, allowHttpHosts = [] } = {}) {
  if (typeof did !== 'string' || !did.startsWith('did:web:')) {
    throw new BlockCredError('UNSUPPORTED_DID', `Unsupported DID method: ${did}`);
  }
  const id = did.slice('did:web:'.length).split('#')[0].split('?')[0];
  const segments = id.split(':').map((s) => decodeURIComponent(s));
  const host = segments[0];
  if (!host || /[/?#@\s]/.test(host) || segments.some((s) => s === '' || s === '.' || s === '..' || s.includes('/'))) {
    throw new BlockCredError('INVALID_DID', `Malformed did:web identifier: ${did}`);
  }
  const base = hostOverrides[host] ?? `${allowHttpHosts.includes(host) ? 'http' : 'https'}://${host}`;
  const path = segments.slice(1);
  return path.length
    ? `${base}/${path.map(encodeURIComponent).join('/')}/did.json`
    : `${base}/.well-known/did.json`;
}

/** https://example.com:8443/a/b -> did:web:example.com%3A8443:a:b */
export function didWebFromUrl(url) {
  const u = new URL(url);
  const host = u.port ? `${u.hostname}%3A${u.port}` : u.hostname;
  const path = u.pathname.split('/').filter(Boolean).map(encodeURIComponent);
  return ['did:web', host, ...path].join(':');
}

const absolutize = (did, ref) => (ref.startsWith('#') ? `${did}${ref}` : ref);

/**
 * Returns the public JWK for `kid` only if it is authorised for the given
 * verification relationship (default: assertionMethod, i.e. credential issuance).
 */
export function keyFromDidDocument(doc, kid, relationship = 'assertionMethod') {
  const did = doc.id;
  if (!kid) throw new BlockCredError('KEY_NOT_FOUND', 'Missing kid');
  const fullKid = absolutize(did, kid);
  if (!fullKid.startsWith(`${did}#`)) throw new BlockCredError('KEY_NOT_FOUND', 'kid does not belong to issuer DID');
  const methods = [...(doc.verificationMethod ?? [])];
  const authorised = new Set();
  for (const ref of doc[relationship] ?? []) {
    if (typeof ref === 'string') authorised.add(absolutize(did, ref));
    else if (ref?.id) {
      authorised.add(absolutize(did, ref.id));
      methods.push(ref);
    }
  }
  if (!authorised.has(fullKid)) throw new BlockCredError('KEY_NOT_AUTHORIZED', `Key ${fullKid} not in ${relationship}`);
  const vm = methods.find((m) => absolutize(did, m.id) === fullKid);
  if (!vm?.publicKeyJwk) throw new BlockCredError('KEY_NOT_FOUND', `No publicKeyJwk for ${fullKid}`);
  if (vm.publicKeyJwk.d) throw new BlockCredError('KEY_NOT_FOUND', 'DID document leaks private key material');
  return vm.publicKeyJwk;
}

/**
 * Builds a did:web DID document.
 * keys: [{ id: 'key-1', publicJwk, status: 'active'|'retired'|'revoked' }]
 * - active + retired keys are published (retired keys keep old credentials verifiable)
 * - revoked (compromised) keys are removed, so every credential they signed fails verification
 */
export function buildDidWebDocument({ did, keys, services = [] }) {
  const published = keys.filter((k) => k.status !== 'revoked');
  const verificationMethod = published.map((k) => ({
    id: `${did}#${k.id}`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: { kty: k.publicJwk.kty, crv: k.publicJwk.crv, x: k.publicJwk.x, y: k.publicJwk.y },
  }));
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod,
    assertionMethod: verificationMethod.map((v) => v.id),
    ...(services.length ? { service: services } : {}),
  };
}

export class DidWebResolver {
  /**
   * @param {object} [o]
   * @param {typeof fetch} [o.fetch]
   * @param {number} [o.cacheTtlMs=300000]  set 0 to disable caching
   * @param {number} [o.timeoutMs=5000]
   * @param {number} [o.maxCacheEntries=1000]
   * @param {Record<string,string>} [o.hostOverrides] DEV ONLY: host -> base URL
   * @param {string[]} [o.allowHttpHosts]           DEV ONLY: hosts resolved over http
   */
  constructor(o = {}) {
    this.fetch = o.fetch ?? globalThis.fetch.bind(globalThis);
    this.cacheTtlMs = o.cacheTtlMs ?? 300_000;
    this.timeoutMs = o.timeoutMs ?? 5000;
    this.maxCacheEntries = o.maxCacheEntries ?? 1000;
    this.urlOptions = { hostOverrides: o.hostOverrides ?? {}, allowHttpHosts: o.allowHttpHosts ?? [] };
    this.cache = new Map();
  }

  async resolve(did) {
    const cached = this.cache.get(did);
    if (cached && cached.expires > Date.now()) return cached.doc;
    const url = didWebToUrl(did, this.urlOptions);
    let res;
    try {
      res = await this.fetch(url, {
        headers: { accept: 'application/did+json, application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new BlockCredError('DID_RESOLUTION_FAILED', `Could not fetch ${url}: ${err.message}`);
    }
    if (!res.ok) throw new BlockCredError('DID_RESOLUTION_FAILED', `${url} returned HTTP ${res.status}`);
    let doc;
    try {
      doc = await res.json();
    } catch {
      throw new BlockCredError('DID_RESOLUTION_FAILED', `${url} did not return JSON`);
    }
    if (doc?.id !== did) throw new BlockCredError('DID_RESOLUTION_FAILED', 'DID document id does not match DID');
    if (this.cacheTtlMs > 0) {
      if (this.cache.size >= this.maxCacheEntries) this.cache.delete(this.cache.keys().next().value);
      this.cache.set(did, { doc, expires: Date.now() + this.cacheTtlMs });
    }
    return doc;
  }

  invalidate(did) {
    this.cache.delete(did);
  }

  /** Resolve the issuer key referenced by a JWT header `kid`. */
  async resolveKey(did, kid, relationship = 'assertionMethod') {
    const doc = await this.resolve(did);
    return keyFromDidDocument(doc, kid, relationship);
  }
}
