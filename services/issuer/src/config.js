import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';
import { didWebFromUrl } from '@blockcred/sdk/did';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
dotenv.config({ path: path.join(REPO_ROOT, '.env') });

const bool = (def) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? def : ['1', 'true', 'yes'].includes(v.toLowerCase())));
const int = (def) => z.coerce.number().int().positive().default(def);
const optionalString = z
  .string()
  .optional()
  .transform((v) => (v ? v : undefined));

const keySchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9._-]+$/),
  status: z.enum(['active', 'retired', 'revoked']),
  privateJwk: z.object({ kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string(), y: z.string(), d: z.string() }),
});

const envSchema = z.object({
  NODE_ENV: z.string().default('development'),
  LOG_LEVEL: z.string().default('info'),
  ISSUER_PORT: int(4000),
  ISSUER_PUBLIC_URL: z.string().url().default('http://localhost:4000'),
  ISSUER_DID: optionalString,
  ISSUER_NAME: z.string().default('Demo Institute of Technology'),
  ISSUER_KEYS: optionalString,
  ISSUER_KEYS_FILE: optionalString,
  ISSUER_ADMIN_API_KEY: z.string().min(24, 'ISSUER_ADMIN_API_KEY must be at least 24 chars (run `npm run setup`)'),
  ISSUER_CONTROLLER_PRIVATE_KEY: z.string().regex(/^0x[0-9a-fA-F]{64}$/, 'ISSUER_CONTROLLER_PRIVATE_KEY must be 0x + 64 hex'),
  DATABASE_URL: z.string().default('postgres://blockcred:blockcred@127.0.0.1:5432/blockcred'),
  DATABASE_POOL_SIZE: int(10),
  RPC_URL: z.string().default('http://127.0.0.1:8545'),
  CHAIN_ID: z.coerce.number().int().positive().default(31337),
  TX_CONFIRMATIONS: int(1),
  DEPLOYMENTS_FILE: optionalString,
  ISSUER_REGISTRY_ADDRESS: optionalString,
  REVOCATION_REGISTRY_ADDRESS: optionalString,
  MERKLE_ANCHOR_ADDRESS: optionalString,
  CREDENTIAL_TTL_DAYS: int(1825),
  OFFER_TTL_HOURS: int(72),
  PURGE_OFFER_CLAIMS: bool(true),
  DECOY_DIGESTS: z.coerce.number().int().min(0).max(20).default(3),
  STATUS_INDEX_SPACE: int(1_048_576),
  ANCHOR_INTERVAL_SEC: int(60),
  ANCHOR_MAX_BATCH: int(2000),
  WALLET_URL: z.string().default('http://localhost:5173'),
  CORS_ORIGINS: z.string().default('http://localhost:5173'),
  TRUST_PROXY: z.string().default('loopback'),
});

function loadContracts(env) {
  if (env.ISSUER_REGISTRY_ADDRESS && env.REVOCATION_REGISTRY_ADDRESS && env.MERKLE_ANCHOR_ADDRESS) {
    return {
      IssuerRegistry: env.ISSUER_REGISTRY_ADDRESS,
      RevocationRegistry: env.REVOCATION_REGISTRY_ADDRESS,
      MerkleAnchor: env.MERKLE_ANCHOR_ADDRESS,
    };
  }
  if (!env.DEPLOYMENTS_FILE) {
    throw new Error('Set contract addresses or DEPLOYMENTS_FILE (e.g. contracts/deployments/localhost.json)');
  }
  const file = path.resolve(REPO_ROOT, env.DEPLOYMENTS_FILE);
  if (!fs.existsSync(file)) throw new Error(`Deployments file not found: ${file}. Deploy the contracts first.`);
  const deployment = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (Number(deployment.chainId) !== env.CHAIN_ID) {
    throw new Error(`CHAIN_ID ${env.CHAIN_ID} does not match deployment chainId ${deployment.chainId}`);
  }
  return deployment.contracts;
}

function loadKeys(env) {
  const raw = env.ISSUER_KEYS_FILE ? fs.readFileSync(path.resolve(REPO_ROOT, env.ISSUER_KEYS_FILE), 'utf8') : env.ISSUER_KEYS;
  if (!raw) throw new Error('ISSUER_KEYS or ISSUER_KEYS_FILE is required (run `npm run setup`)');
  const keys = z.array(keySchema).min(1).parse(JSON.parse(raw));
  const active = keys.filter((k) => k.status === 'active');
  if (active.length !== 1) throw new Error('Exactly one issuer key must have status "active"');
  if (new Set(keys.map((k) => k.id)).size !== keys.length) throw new Error('Issuer key ids must be unique');
  return keys;
}

export function loadConfig(source = process.env) {
  // Treat empty values (e.g. `FOO=` in .env) as unset.
  const cleaned = Object.fromEntries(Object.entries(source).filter(([, v]) => v !== ''));
  const env = envSchema.parse(cleaned);
  const publicUrl = env.ISSUER_PUBLIC_URL.replace(/\/+$/, '');
  return {
    env: env.NODE_ENV,
    isProduction: env.NODE_ENV === 'production',
    logLevel: env.LOG_LEVEL,
    port: env.ISSUER_PORT,
    publicUrl,
    did: env.ISSUER_DID ?? didWebFromUrl(publicUrl),
    issuerName: env.ISSUER_NAME,
    keys: loadKeys(env),
    adminApiKey: env.ISSUER_ADMIN_API_KEY,
    controllerPrivateKey: env.ISSUER_CONTROLLER_PRIVATE_KEY,
    databaseUrl: env.DATABASE_URL,
    databasePoolSize: env.DATABASE_POOL_SIZE,
    rpcUrl: env.RPC_URL,
    chainId: env.CHAIN_ID,
    txConfirmations: env.TX_CONFIRMATIONS,
    contracts: loadContracts(env),
    credentialTtlDays: env.CREDENTIAL_TTL_DAYS,
    offerTtlHours: env.OFFER_TTL_HOURS,
    purgeOfferClaims: env.PURGE_OFFER_CLAIMS,
    decoyDigests: env.DECOY_DIGESTS,
    statusIndexSpace: env.STATUS_INDEX_SPACE,
    anchorIntervalSec: env.ANCHOR_INTERVAL_SEC,
    anchorMaxBatch: env.ANCHOR_MAX_BATCH,
    walletUrl: env.WALLET_URL.replace(/\/+$/, ''),
    corsOrigins: env.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
    trustProxy: env.TRUST_PROXY,
  };
}
