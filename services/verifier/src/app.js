import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import pinoHttp from 'pino-http';
import { z, ZodError } from 'zod';
import { DEGREE_DISCLOSABLE_CLAIMS } from '@blockcred/sdk/credential';
import { BlockCredError, randomToken } from '@blockcred/sdk/util';

const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');
const safeEqual = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

const anchorProofSchema = z
  .object({ root: z.string().regex(/^0x[0-9a-fA-F]{64}$/), proof: z.array(z.string().regex(/^0x[0-9a-fA-F]{64}$/)).max(64) })
  .optional();

export function createApp({ config, pool, verifier, chain, logger }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === '/health' } }));
  app.use(helmet());
  // Wallets post from any origin (other devices / apps), so only the response endpoint allows all origins.
  const openCors = cors({ origin: true, methods: ['POST'], allowedHeaders: ['content-type'] });
  const restrictedCors = cors({
    origin: config.corsOrigins,
    methods: ['GET', 'POST'],
    allowedHeaders: ['content-type', 'authorization', 'x-poll-token'],
  });
  app.use((req, res, next) =>
    /^\/requests\/[^/]+\/response$/.test(req.path) ? openCors(req, res, next) : restrictedCors(req, res, next),
  );
  app.use(express.json({ limit: '64kb' }));

  const limiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });

  function requireApiKey(req, res, next) {
    const header = req.get('authorization') ?? '';
    if (!header.startsWith('Bearer ') || !safeEqual(header.slice(7), config.apiKey)) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Missing or invalid API key' });
    }
    next();
  }

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/ready', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      await chain.provider.getBlockNumber();
      res.json({ status: 'ready' });
    } catch (err) {
      res.status(503).json({ status: 'unavailable', error: err.message });
    }
  });

  // 1. Relying party creates a nonce-bound presentation request.
  app.post('/requests', limiter, async (req, res) => {
    const body = z
      .object({
        fields: z.array(z.enum(DEGREE_DISCLOSABLE_CLAIMS)).max(DEGREE_DISCLOSABLE_CLAIMS.length).default(['degree']),
        purpose: z.string().trim().min(3).max(200).default('Employment background verification'),
      })
      .parse(req.body ?? {});
    const id = randomUUID();
    const nonce = randomToken(24);
    const pollToken = randomToken(24);
    const expiresAt = new Date(Date.now() + config.requestTtlSec * 1000);
    await pool.query(
      `INSERT INTO verifier_requests (id, nonce, poll_token_hash, audience, purpose, requested_fields, status, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)`,
      [id, nonce, sha256Hex(pollToken), config.verifierId, body.purpose, body.fields, expiresAt],
    );
    const request = {
      type: 'blockcred-presentation-request',
      version: 1,
      verifier: { id: config.verifierId, name: config.verifierName },
      aud: config.verifierId,
      nonce,
      fields: body.fields,
      purpose: body.purpose,
      response_uri: `${config.publicUrl}/requests/${id}/response`,
      expires_at: expiresAt.toISOString(),
    };
    res.status(201).json({ id, pollToken, expiresAt, request });
  });

  // 2. Relying party polls for the outcome (poll token prevents third parties reading results).
  app.get('/requests/:id', limiter, async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    const token = req.get('x-poll-token') ?? '';
    const { rows } = await pool.query(
      'SELECT status, verdict, result, expires_at, completed_at, poll_token_hash, claims_purged FROM verifier_requests WHERE id = $1',
      [id],
    );
    const row = rows[0];
    if (!row || !safeEqual(sha256Hex(token), row.poll_token_hash)) {
      return res.status(404).json({ error: 'NOT_FOUND', message: 'Unknown request' });
    }
    const status = row.status === 'pending' && row.expires_at < new Date() ? 'expired' : row.status;
    res.json({ status, verdict: row.verdict, result: row.result, completedAt: row.completed_at, claimsPurged: row.claims_purged });
  });

  // 3. Wallet submits the presentation (direct_post style). The nonce is consumed
  //    atomically, so a replayed or duplicated submission is always rejected.
  app.post('/requests/:id/response', limiter, async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    const { presentation, anchorProof } = z
      .object({ presentation: z.string().min(10).max(32_768), anchorProof: anchorProofSchema })
      .parse(req.body);

    const { rows } = await pool.query(
      `UPDATE verifier_requests SET status = 'processing'
        WHERE id = $1 AND status = 'pending' AND expires_at > now()
        RETURNING nonce, audience, purpose, requested_fields`,
      [id],
    );
    if (!rows[0]) {
      return res.status(409).json({
        valid: false,
        verdict: 'REPLAY_DETECTED',
        message: 'Request is unknown, expired or already answered',
      });
    }
    const request = rows[0];

    let result;
    try {
      result = await verifier.verify(presentation, { nonce: request.nonce, audience: request.audience, anchorProof });
    } catch (err) {
      await pool.query(`UPDATE verifier_requests SET status = 'failed', verdict = 'ERROR', completed_at = now() WHERE id = $1`, [id]);
      throw err;
    }

    const disclosedFields = Object.keys(result.disclosed ?? {});
    const missing = request.requested_fields.filter((f) => !disclosedFields.includes(f));
    const stored = { ...result, missingFields: missing };
    await pool.query(
      `UPDATE verifier_requests SET status = 'completed', verdict = $2, result = $3, completed_at = now() WHERE id = $1`,
      [id, result.verdict, stored],
    );
    await pool.query(
      `INSERT INTO verifier_consent_log (request_id, holder_thumbprint, issuer_did, disclosed_fields, purpose, verdict)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, result.holder?.thumbprint ?? null, result.issuer?.did ?? null, disclosedFields, request.purpose, result.verdict],
    );
    logger.info({ requestId: id, verdict: result.verdict }, 'presentation verified');
    // The wallet only learns the verdict, not anything else about the verifier's records.
    res.status(result.valid ? 200 : 422).json({ valid: result.valid, verdict: result.verdict, missingFields: missing });
  });

  // Stateless verification for back-end integrations (API key). Supply `nonce` to get replay protection.
  app.post('/verify', limiter, requireApiKey, async (req, res) => {
    const body = z
      .object({
        presentation: z.string().min(10).max(32_768),
        nonce: z.string().optional(),
        audience: z.string().optional(),
        anchorProof: anchorProofSchema,
      })
      .parse(req.body);
    const result = await verifier.verify(body.presentation, {
      nonce: body.nonce,
      audience: body.audience ?? config.verifierId,
      anchorProof: body.anchorProof,
    });
    res.status(result.valid ? 200 : 422).json(result);
  });

  app.get('/consent-log', limiter, requireApiKey, async (req, res) => {
    const limit = z.coerce.number().int().min(1).max(500).default(100).parse(req.query.limit);
    const { rows } = await pool.query('SELECT * FROM verifier_consent_log ORDER BY at DESC LIMIT $1', [limit]);
    res.json({ entries: rows });
  });

  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err instanceof ZodError) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ') });
    }
    if (err instanceof BlockCredError) return res.status(400).json({ error: err.code, message: err.message });
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
      return res.status(err.status ?? 400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
    req.log.error({ err }, 'unhandled error');
    res.status(503).json({ error: 'UNAVAILABLE', message: config.isProduction ? 'Verification temporarily unavailable' : err.message });
  });

  return app;
}

/** Removes disclosed claim values after the retention window (DPDP purpose limitation). */
export function startPurgeWorker({ pool, config, logger }) {
  const timer = setInterval(async () => {
    try {
      const { rowCount } = await pool.query(
        `UPDATE verifier_requests
            SET result = result - 'disclosed', claims_purged = true
          WHERE claims_purged = false AND completed_at IS NOT NULL
            AND completed_at < now() - make_interval(secs => $1)`,
        [config.resultRetentionSec],
      );
      if (rowCount) logger.info({ rowCount }, 'purged disclosed claims');
    } catch (err) {
      logger.error({ err }, 'purge worker failed');
    }
  }, 60_000);
  timer.unref();
  return () => clearInterval(timer);
}
