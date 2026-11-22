import express from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import pinoHttp from 'pino-http';
import { z, ZodError } from 'zod';
import { BlockCredError } from '@blockcred/sdk/util';
import { sessionMiddleware } from './auth.js';
import { didDocumentFor } from './issuers.js';
import { adminRoutes } from './routes/admin.js';
import { authRoutes } from './routes/auth.js';
import { employerRoutes } from './routes/employer.js';
import { studentRoutes } from './routes/student.js';
import { universityRoutes } from './routes/university.js';

const ERROR_STATUS = {
  INVALID_REQUEST: 400,
  INVALID_FORMAT: 400,
  INVALID_PROOF: 400,
  UNSUPPORTED_KEY: 400,
  INVALID_CREDENTIALS: 401,
  ISSUER_NOT_ACTIVE: 403,
  NOT_FOUND: 404,
  EMAIL_TAKEN: 409,
  INVALID_STATE: 409,
  ALREADY_REVOKED: 409,
  REQUEST_CLOSED: 409,
};

export function createApp(ctx) {
  const { config, pool, logger } = ctx;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === '/health' } }));
  app.use(helmet());
  app.use(express.json({ limit: '2mb' }));
  app.use(express.text({ type: 'text/csv', limit: '5mb' }));

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/ready', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      await ctx.chain.provider.getBlockNumber();
      res.json({ status: 'ready' });
    } catch (err) {
      res.status(503).json({ status: 'unavailable', error: err.message });
    }
  });

  // did:web documents: did:web:<host>:issuers:<slug>  ->  /issuers/<slug>/did.json
  app.get('/issuers/:slug/did.json', async (req, res) => {
    const slug = z.string().regex(/^[a-z0-9-]{1,60}$/).parse(req.params.slug);
    const { rows } = await pool.query(`SELECT * FROM issuers WHERE slug = $1 AND status <> 'rejected'`, [slug]);
    if (!rows[0]) return res.status(404).json({ error: 'NOT_FOUND' });
    res.set('cache-control', 'public, max-age=60');
    res.set('access-control-allow-origin', '*');
    res.type('application/did+json').send(JSON.stringify(didDocumentFor(ctx, rows[0])));
  });

  const api = express.Router();
  api.use(rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: 'draft-7', legacyHeaders: false }));
  api.use(sessionMiddleware(ctx));

  // Public directory of accredited institutions.
  api.get('/issuers', async (_req, res) => {
    const { rows } = await pool.query(`SELECT name, slug, did, approved_at FROM issuers WHERE status = 'active' ORDER BY name`);
    res.json({ issuers: rows });
  });
  api.get('/config', (_req, res) => res.json({ chainId: config.chainId, contracts: config.contracts }));

  api.use('/auth', authRoutes(ctx));
  api.use('/admin', adminRoutes(ctx));
  api.use('/university', universityRoutes(ctx));
  api.use('/student', studentRoutes(ctx));
  api.use('/employer', employerRoutes(ctx));
  app.use('/api', api);

  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err instanceof ZodError) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.issues.map((i) => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ') });
    }
    if (err instanceof BlockCredError) return res.status(ERROR_STATUS[err.code] ?? 400).json({ error: err.code, message: err.message });
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
      return res.status(err.status ?? 400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
    req.log.error({ err }, 'unhandled error');
    const message = err.shortMessage ?? err.message;
    res.status(500).json({ error: 'INTERNAL', message: config.isProduction ? 'Internal error' : message });
  });

  return app;
}
