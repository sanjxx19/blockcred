// Isomorphic helpers (Node >= 20 and modern browsers). No dependencies.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (str) => encoder.encode(str);
export const fromUtf8 = (bytes) => decoder.decode(bytes);

export function b64urlEncode(input) {
  const bytes = typeof input === 'string' ? utf8(input) : new Uint8Array(input);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new BlockCredError('INVALID_FORMAT', 'Invalid base64url input');
  }
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export const b64urlJson = (obj) => b64urlEncode(utf8(JSON.stringify(obj)));

export function parseB64urlJson(str) {
  try {
    return JSON.parse(fromUtf8(b64urlDecode(str)));
  } catch (err) {
    if (err instanceof BlockCredError) throw err;
    throw new BlockCredError('INVALID_FORMAT', 'Invalid base64url-encoded JSON');
  }
}

export async function sha256(data) {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function sha256Hex(data) {
  return [...(await sha256(data))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export const randomToken = (n = 32) => b64urlEncode(randomBytes(n));

export const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * Error with a stable machine-readable `code`. Every failure the SDK raises
 * uses one of these codes, so callers can map them to verdicts.
 */
export class BlockCredError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'BlockCredError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}
