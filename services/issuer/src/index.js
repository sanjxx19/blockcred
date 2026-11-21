import pino from 'pino';
import { startAnchorWorker } from './anchor.js';
import { createApp } from './app.js';
import { createIssuerChain } from './chain.js';
import { loadConfig } from './config.js';
import { createPool, migrate } from './db.js';
import { loadIssuerKeys } from './keys.js';

const config = loadConfig();
const logger = pino({ level: config.logLevel, base: { service: 'issuer' } });

const pool = createPool(config);
pool.on('error', (err) => logger.error({ err }, 'postgres pool error'));
await migrate(pool, logger);

const keys = await loadIssuerKeys(config);
const chain = createIssuerChain(config, pool, logger);
const ctx = { config, pool, chain, keys, logger };

try {
  const status = await chain.status();
  if (!status.accredited) logger.warn({ did: config.did }, 'issuer DID is NOT accredited on-chain; verifiers will reject its credentials');
  if (!status.controllerAuthorized) logger.warn({ controller: status.controller }, 'controller account is not authorised for this issuer');
  logger.info({ did: config.did, chainId: status.chainId, controller: status.controller }, 'chain status');
} catch (err) {
  logger.warn({ err: err.message }, 'could not read chain status at startup');
}

const stopWorker = startAnchorWorker(ctx);
const server = createApp(ctx).listen(config.port, () => {
  logger.info({ port: config.port, did: config.did }, 'issuer service listening');
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, 'shutting down');
  stopWorker();
  server.close();
  setTimeout(() => process.exit(1), 10_000).unref();
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
