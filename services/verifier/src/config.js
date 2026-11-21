import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
dotenv.config({ path: path.join(REPO_ROOT, '.env') });

const int = (def) => z.coerce.number().int().positive().default(def);
const bool = (def) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined ? def : ['1', 'true', 'yes'].includes(v.toLowerCase())));

const envSchema = z.object({
  NODE_ENV: z.string().default('development'),
  LOG_LEVEL: z.string().default('info'),
  VERIFIER_PORT: int(5000),
  VERIFIER_PUBLIC_URL: z.string().url().default('http://localhost:5000'),
  VERIFIER_ID: z.string().optional(),
  VERIFIER_NAME: z.string().default('Demo Employer Inc.'),
  VERIFIER_API_KEY: z.string().min(24, 'VERIFIER_API_KEY must be at least 24 chars (run `npm run setup`)'),
  DATABASE_URL: z.string().default('postgres://blockcred:blockcred@127.0.0.1:5432/blockcred'),
  DATABASE_POOL_SIZE: int(10),
  RPC_URL: z.string().default('http://127.0.0.1:8545'),
  CHAIN_ID: z.coerce.number().int().positive().default(31337),
  DEPLOYMENTS_FILE: z.string().optional(),
  ISSUER_REGISTRY_ADDRESS: z.string().optional(),
  REVOCATION_REGISTRY_ADDRESS: z.string().optional(),
  MERKLE_ANCHOR_ADDRESS: z.string().optional(),
  REQUEST_TTL_SEC: int(300),
  RESULT_RETENTION_SEC: int(3600),
  REQUIRE_ANCHOR: bool(false),
  DID_CACHE_TTL_SEC: z.coerce.number().int().min(0).default(300),
  DID_WEB_ALLOW_HTTP_HOSTS: z.string().default(''),
  DID_WEB_HOST_OVERRIDES: z.string().default('{}'),
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
  if (!env.DEPLOYMENTS_FILE) throw new Error('Set contract addresses or DEPLOYMENTS_FILE');
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
  const publicUrl = env.VERIFIER_PUBLIC_URL.replace(/\/+$/, '');
  const isProduction = env.NODE_ENV === 'production';
  const allowHttpHosts = env.DID_WEB_ALLOW_HTTP_HOSTS.split(',').map((s) => s.trim()).filter(Boolean);
  const hostOverrides = z.record(z.string().url()).parse(JSON.parse(env.DID_WEB_HOST_OVERRIDES));
  if (isProduction && (allowHttpHosts.length || Object.keys(hostOverrides).length)) {
    throw new Error('DID_WEB_ALLOW_HTTP_HOSTS / DID_WEB_HOST_OVERRIDES are development-only and must be empty in production');
  }
  return {
    isProduction,
    logLevel: env.LOG_LEVEL,
    port: env.VERIFIER_PORT,
    publicUrl,
    verifierId: env.VERIFIER_ID ?? publicUrl,
    verifierName: env.VERIFIER_NAME,
    apiKey: env.VERIFIER_API_KEY,
    databaseUrl: env.DATABASE_URL,
    databasePoolSize: env.DATABASE_POOL_SIZE,
    rpcUrl: env.RPC_URL,
    chainId: env.CHAIN_ID,
    contracts: loadContracts(env),
    requestTtlSec: env.REQUEST_TTL_SEC,
    resultRetentionSec: env.RESULT_RETENTION_SEC,
    requireAnchor: env.REQUIRE_ANCHOR,
    didCacheTtlMs: env.DID_CACHE_TTL_SEC * 1000,
    allowHttpHosts,
    hostOverrides,
    corsOrigins: env.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean),
    trustProxy: env.TRUST_PROXY,
  };
}
