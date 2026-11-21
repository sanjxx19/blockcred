import pino from 'pino';
import { BlockCredChain, createProvider } from '@blockcred/sdk/chain';
import { DEGREE_VCT } from '@blockcred/sdk/credential';
import { DidWebResolver } from '@blockcred/sdk/did';
import { BlockCredVerifier } from '@blockcred/sdk/verify';
import { createApp, startPurgeWorker } from './app.js';
import { loadConfig } from './config.js';
import { createPool, migrate } from './db.js';

const config = loadConfig();
const logger = pino({ level: config.logLevel, base: { service: 'verifier' } });

const pool = createPool(config);
pool.on('error', (err) => logger.error({ err }, 'postgres pool error'));
await migrate(pool, logger);

const provider = createProvider(config.rpcUrl, config.chainId);
const chain = new BlockCredChain({ runner: provider, chainId: config.chainId, contracts: config.contracts });
chain.provider = provider;

const didResolver = new DidWebResolver({
  cacheTtlMs: config.didCacheTtlMs,
  allowHttpHosts: config.allowHttpHosts,
  hostOverrides: config.hostOverrides,
});

const verifier = new BlockCredVerifier({
  chain,
  didResolver,
  audience: config.verifierId,
  policy: { requireKeyBinding: true, requireAnchor: config.requireAnchor, allowedVcts: [DEGREE_VCT] },
});

const stopPurge = startPurgeWorker({ pool, config, logger });
const server = createApp({ config, pool, verifier, chain, logger }).listen(config.port, () => {
  logger.info({ port: config.port, verifierId: config.verifierId }, 'verifier service listening');
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, 'shutting down');
  stopPurge();
  server.close();
  setTimeout(() => process.exit(1), 10_000).unref();
  await pool.end().catch(() => {});
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
