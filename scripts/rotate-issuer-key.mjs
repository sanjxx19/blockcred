#!/usr/bin/env node
// Rotates the issuer signing key in .env.
//   npm run rotate-issuer-key                 -> old active key becomes "retired" (old credentials still verify)
//   npm run rotate-issuer-key -- --compromised -> old active key becomes "revoked" (removed from the DID document,
//                                                 so EVERY credential it signed stops verifying)
// Restart the issuer service afterwards. If the DID document is hosted statically
// (GitHub Pages), re-export it with `npm run export-did -w services/issuer`.

import { webcrypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');
const compromised = process.argv.includes('--compromised');

let env = fs.readFileSync(envPath, 'utf8');
const match = env.match(/^ISSUER_KEYS=(.*)$/m);
if (!match) throw new Error('ISSUER_KEYS not found in .env (run npm run setup)');
const keys = JSON.parse(match[1].replace(/^'|'$/g, ''));

const nextNumber = Math.max(...keys.map((k) => Number(k.id.split('-')[1]) || 0)) + 1;
for (const k of keys) if (k.status === 'active') k.status = compromised ? 'revoked' : 'retired';

const { privateKey } = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
const { kty, crv, x, y, d } = await webcrypto.subtle.exportKey('jwk', privateKey);
keys.push({ id: `key-${nextNumber}`, status: 'active', privateJwk: { kty, crv, x, y, d } });

env = env.replace(/^ISSUER_KEYS=.*$/m, () => `ISSUER_KEYS='${JSON.stringify(keys)}'`);
fs.writeFileSync(envPath, env, { mode: 0o600 });
console.log(keys.map((k) => `${k.id}: ${k.status}`).join('\n'));
console.log('Restart the issuer service to publish the new DID document.');
