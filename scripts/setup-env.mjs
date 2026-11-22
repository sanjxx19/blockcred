#!/usr/bin/env node
// Creates .env from .env.example with freshly generated secrets:
//   MASTER_ENCRYPTION_KEY  (encrypts university keys at rest)
//   ADMIN_PASSWORD         (accreditation-admin login)
// Usage: npm run setup [-- --force]

import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(root, '.env');
const force = process.argv.includes('--force');

if (fs.existsSync(envPath) && !force) {
  const env = fs.readFileSync(envPath, 'utf8');
  if (!/^MASTER_ENCRYPTION_KEY=\S+/m.test(env)) {
    console.log('Your .env is from BlockCred v1. Re-run with `npm run setup -- --force` to upgrade it.');
  } else {
    console.log('.env already exists (use `npm run setup -- --force` to regenerate).');
    console.log(`Admin login: ${env.match(/^ADMIN_EMAIL=(.*)$/m)?.[1]} / ${env.match(/^ADMIN_PASSWORD=(.*)$/m)?.[1]}`);
  }
  process.exit(0);
}

const set = (text, key, value) => {
  const re = new RegExp(`^${key}=.*$`, 'm');
  return re.test(text) ? text.replace(re, () => `${key}=${value}`) : `${text.trimEnd()}\n${key}=${value}\n`;
};

let env = fs.readFileSync(path.join(root, '.env.example'), 'utf8');
const adminPassword = randomBytes(9).toString('base64url');
env = set(env, 'MASTER_ENCRYPTION_KEY', randomBytes(32).toString('base64'));
env = set(env, 'ADMIN_PASSWORD', adminPassword);
fs.writeFileSync(envPath, env, { mode: 0o600 });

console.log('Created .env');
console.log(`Accreditation admin login: ${env.match(/^ADMIN_EMAIL=(.*)$/m)[1]} / ${adminPassword}`);
