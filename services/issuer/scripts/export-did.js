// Prints (or writes) the issuer's DID document so it can be hosted statically,
// e.g. on GitHub Pages for did:web:<user>.github.io:<repo>.
//
//   npm run export-did -w services/issuer                  # print to stdout
//   npm run export-did -w services/issuer -- ./site/did.json
//
// Only public keys are exported. Requires ISSUER_KEYS (and ISSUER_DID or ISSUER_PUBLIC_URL).

import fs from 'node:fs';
import path from 'node:path';
import { buildDidWebDocument, didWebFromUrl, didWebToUrl } from '@blockcred/sdk/did';
import { toPublicJwk } from '@blockcred/sdk/jws';
import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
dotenv.config({ path: path.join(root, '.env') });

const did = process.env.ISSUER_DID || didWebFromUrl(process.env.ISSUER_PUBLIC_URL || 'http://localhost:4000');
const keys = JSON.parse(process.env.ISSUER_KEYS || '[]');
if (!keys.length) {
  console.error('ISSUER_KEYS is empty. Run `npm run setup` first.');
  process.exit(1);
}
const doc = buildDidWebDocument({
  did,
  keys: keys.map((k) => ({ id: k.id, status: k.status, publicJwk: toPublicJwk(k.privateJwk) })),
});
const json = `${JSON.stringify(doc, null, 2)}\n`;
const out = process.argv[2];
if (out) {
  fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  fs.writeFileSync(out, json);
  console.error(`Wrote ${out}. Host it at: ${didWebToUrl(did)}`);
} else {
  process.stdout.write(json);
  console.error(`Host this at: ${didWebToUrl(did)}`);
}
