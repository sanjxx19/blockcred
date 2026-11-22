import pino from 'pino';
import { DEGREE_VCT } from '@blockcred/sdk/credential';
import { DidWebResolver } from '@blockcred/sdk/did';
import { BlockCredVerifier } from '@blockcred/sdk/verify';
import { createApp } from './app.js';
import { ensureAdmin } from './auth.js';
import { createPlatformChain } from './chain.js';
import { loadConfig } from './config.js';
import { startAnchorWorker } from './credentials.js';
import { createSecretBox } from './crypto.js';
import { createPool, migrate } from './db.js';
import { startPurgeWorker } from './verification.js';

const config = loadConfig();
const logger = pino({ level: config.logLevel, base: { service: 'api' } });

const pool = createPool(config);
pool.on('error', (err) => logger.error({ err }, 'postgres pool error'));
await migrate(pool, logger);

const box = createSecretBox(config.masterKey);
const chain = createPlatformChain(config, pool, logger);
const didResolver = new DidWebResolver({
  cacheTtlMs: config.didCacheTtlMs,
  allowHttpHosts: config.allowHttpHosts,
  hostOverrides: config.hostOverrides,
});
// Verification uses the SAME public checks any outside verifier would: did:web over HTTP + chain reads.
const verifier = new BlockCredVerifier({
  chain: chain.reader,
  didResolver,
  policy: { requireKeyBinding: true, allowedVcts: [DEGREE_VCT] },
});

const ctx = { config, pool, logger, box, chain, didResolver, verifier };
await ensureAdmin(ctx);

try {
  const status = await chain.status();
  if (!status.governorAuthorized) logger.warn({ governor: status.governor }, 'platform governor key lacks GOVERNOR_ROLE; issuer approvals will fail');
  logger.info({ chainId: status.chainId, governor: status.governor, balance: status.governorBalance }, 'chain status');
} catch (err) {
  logger.warn({ err: err.message }, 'could not read chain status at startup');
}

const stopAnchor = startAnchorWorker(ctx);
const stopPurge = startPurgeWorker(ctx);
const server = createApp(ctx).listen(config.port, () => {
  logger.info({ port: config.port, admin: config.admin.email }, 'BlockCred API listening');
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, 'shutting down');
  stopAnchor();
  stopPurge();
  server.close();
  setTimeout(() => process.exit(1), 10_000).unref();
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
