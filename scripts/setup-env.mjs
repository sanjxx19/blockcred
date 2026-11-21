#!/usr/bin/env node
// Creates .env from .env.example and fills in freshly generated secrets:
//   - ISSUER_KEYS            (P-256 signing key for credentials)
//   - ISSUER_ADMIN_API_KEY   (issuer admin API)
//   - VERIFIER_API_KEY       (verifier back-end API)
// Usage: npm run setup [-- --force]

import { randomBytes, webcrypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');
const examplePath = path.join(root, '.env.example');
const force = process.argv.includes('--force');

if (fs.existsSync(envPath) && !force) {
  console.log('.env already exists. Re-run with `npm run setup -- --force` to regenerate (this replaces your keys).');
  process.exit(0);
}

async function generateIssuerKey(id) {
  const { privateKey } = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { kty, crv, x, y, d } = await webcrypto.subtle.exportKey('jwk', privateKey);
  return { id, status: 'active', privateJwk: { kty, crv, x, y, d } };
}

export function setEnvValue(text, key, value) {
  const line = `${key}=${value}`;
  const re = new RegExp(`^${key}=.*$`, 'm');
  return re.test(text) ? text.replace(re, () => line) : `${text.trimEnd()}\n${line}\n`;
}

let env = fs.readFileSync(examplePath, 'utf8');
const keys = [await generateIssuerKey('key-1')];
env = setEnvValue(env, 'ISSUER_KEYS', `'${JSON.stringify(keys)}'`);
env = setEnvValue(env, 'ISSUER_ADMIN_API_KEY', randomBytes(24).toString('base64url'));
env = setEnvValue(env, 'VERIFIER_API_KEY', randomBytes(24).toString('base64url'));
fs.writeFileSync(envPath, env, { mode: 0o600 });

console.log('Created .env with fresh issuer signing key and API keys.');
console.log('Issuer admin API key (also in .env):', env.match(/^ISSUER_ADMIN_API_KEY=(.*)$/m)[1]);
