import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
dotenv.config({ path: path.join(REPO_ROOT, '.env') });

const int = (def) => z.coerce.number().int().positive().default(def);
const bool = (def) => z.string().optional().transform((v) => (v === undefined ? def : ['1', 'true', 'yes'].includes(v.toLowerCase())));
const hexKey = z.string().regex(/^0x[0-9a-fA-F]{64}$/, 'must be 0x + 64 hex characters');

const envSchema = z.object({
  NODE_ENV: z.string().default('development'),
  LOG_LEVEL: z.string().default('info'),
  API_PORT: int(4000),
  PUBLIC_URL: z.string().url().default('http://localhost:4000'),
  MASTER_ENCRYPTION_KEY: z.string().min(40, 'MASTER_ENCRYPTION_KEY missing (run `npm run setup`)'),
  ADMIN_EMAIL: z.string().email().default('admin@blockcred.local'),
  ADMIN_PASSWORD: z.string().min(8, 'ADMIN_PASSWORD missing (run `npm run setup`)'),
  ADMIN_NAME: z.string().default('National Accreditation Board (demo)'),
  PLATFORM_GOVERNOR_PRIVATE_KEY: hexKey,
  ISSUER_FUNDING_ETH: z.string().default('1'),
  DATABASE_URL: z.string().default('postgres://blockcred:blockcred@127.0.0.1:5432/blockcred'),
  DATABASE_POOL_SIZE: int(10),
  RPC_URL: z.string().default('http://127.0.0.1:8545'),
  CHAIN_ID: z.coerce.number().int().positive().default(31337),
  TX_CONFIRMATIONS: int(1),
  DEPLOYMENTS_FILE: z.string().optional(),
  ISSUER_REGISTRY_ADDRESS: z.string().optional(),
  REVOCATION_REGISTRY_ADDRESS: z.string().optional(),
  MERKLE_ANCHOR_ADDRESS: z.string().optional(),
  SESSION_TTL_HOURS: int(12),
  COOKIE_SECURE: bool(false),
  CREDENTIAL_TTL_DAYS: int(1825),
  DECOY_DIGESTS: z.coerce.number().int().min(0).max(20).default(3),
  STATUS_INDEX_SPACE: int(1_048_576),
  ANCHOR_INTERVAL_SEC: int(60),
  ANCHOR_MAX_BATCH: int(2000),
  REQUEST_TTL_HOURS: int(168),
  RESULT_RETENTION_HOURS: int(720),
  DID_CACHE_TTL_SEC: z.coerce.number().int().min(0).default(60),
  DID_WEB_ALLOW_HTTP_HOSTS: z.string().default(''),
  DID_WEB_HOST_OVERRIDES: z.string().default('{}'),
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
  if (!env.DEPLOYMENTS_FILE) throw new Error('Set contract addresses or DEPLOYMENTS_FILE (e.g. contracts/deployments/localhost.json)');
  const file = path.resolve(REPO_ROOT, env.DEPLOYMENTS_FILE);
  if (!fs.existsSync(file)) throw new Error(`Deployments file not found: ${file}. Deploy the contracts first.`);
  const deployment = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (Number(deployment.chainId) !== env.CHAIN_ID) {
    throw new Error(`CHAIN_ID ${env.CHAIN_ID} does not match deployment chainId ${deployment.chainId}`);
  }
  return deployment.contracts;
}

export function loadConfig(source = process.env) {
  const cleaned = Object.fromEntries(Object.entries(source).filter(([, v]) => v !== ''));
  const env = envSchema.parse(cleaned);
  const isProduction = env.NODE_ENV === 'production';
  const allowHttpHosts = env.DID_WEB_ALLOW_HTTP_HOSTS.split(',').map((s) => s.trim()).filter(Boolean);
  const hostOverrides = z.record(z.string().url()).parse(JSON.parse(env.DID_WEB_HOST_OVERRIDES));
  if (isProduction && (allowHttpHosts.length || Object.keys(hostOverrides).length)) {
    throw new Error('DID_WEB_ALLOW_HTTP_HOSTS / DID_WEB_HOST_OVERRIDES are development-only');
  }
  return {
    isProduction,
    logLevel: env.LOG_LEVEL,
    port: env.API_PORT,
    publicUrl: env.PUBLIC_URL.replace(/\/+$/, ''),
    masterKey: env.MASTER_ENCRYPTION_KEY,
    admin: { email: env.ADMIN_EMAIL.toLowerCase(), password: env.ADMIN_PASSWORD, name: env.ADMIN_NAME },
    governorPrivateKey: env.PLATFORM_GOVERNOR_PRIVATE_KEY,
    issuerFundingEth: env.ISSUER_FUNDING_ETH,
    databaseUrl: env.DATABASE_URL,
    databasePoolSize: env.DATABASE_POOL_SIZE,
    rpcUrl: env.RPC_URL,
    chainId: env.CHAIN_ID,
    txConfirmations: env.TX_CONFIRMATIONS,
    contracts: loadContracts(env),
    sessionTtlHours: env.SESSION_TTL_HOURS,
    cookieSecure: env.COOKIE_SECURE || isProduction,
    credentialTtlDays: env.CREDENTIAL_TTL_DAYS,
    decoyDigests: env.DECOY_DIGESTS,
    statusIndexSpace: env.STATUS_INDEX_SPACE,
    anchorIntervalSec: env.ANCHOR_INTERVAL_SEC,
    anchorMaxBatch: env.ANCHOR_MAX_BATCH,
    requestTtlHours: env.REQUEST_TTL_HOURS,
    resultRetentionHours: env.RESULT_RETENTION_HOURS,
    didCacheTtlMs: env.DID_CACHE_TTL_SEC * 1000,
    allowHttpHosts,
    hostOverrides,
    trustProxy: env.TRUST_PROXY,
  };
}
