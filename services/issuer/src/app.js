import { timingSafeEqual } from 'node:crypto';
import cors from 'cors';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import pinoHttp from 'pino-http';
import { z, ZodError } from 'zod';
import { BlockCredError } from '@blockcred/sdk/util';
import { anchorPending } from './anchor.js';
import { audit, withTransaction } from './db.js';
import { createOffers, mapDigiLockerDocument, parseRecords, redeemOffer } from './issuance.js';

const ERROR_STATUS = {
  INVALID_REQUEST: 400,
  INVALID_FORMAT: 400,
  INVALID_PROOF: 400,
  UNSUPPORTED_KEY: 400,
  UNSUPPORTED_ALG: 400,
  INVALID_SIGNATURE: 400,
  OFFER_NOT_FOUND: 404,
  NOT_FOUND: 404,
  OFFER_REDEEMED: 409,
  ALREADY_REVOKED: 409,
  OFFER_EXPIRED: 410,
};

export function createApp(ctx) {
  const { config, pool, chain, keys, logger } = ctx;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === '/health' } }));
  app.use(helmet());
  app.use(cors({ origin: config.corsOrigins, methods: ['GET', 'POST'], allowedHeaders: ['content-type', 'authorization'] }));
  app.use(express.json({ limit: '2mb' }));
  app.use(express.text({ type: 'text/csv', limit: '5mb' }));

  const publicLimiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-7', legacyHeaders: false });
  const adminLimiter = rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false });

  const adminKey = Buffer.from(config.adminApiKey);
  function requireAdmin(req, res, next) {
    const header = req.get('authorization') ?? '';
    const supplied = Buffer.from(header.startsWith('Bearer ') ? header.slice(7) : '');
    if (supplied.length !== adminKey.length || !timingSafeEqual(supplied, adminKey)) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Missing or invalid admin API key' });
    }
    req.actor = 'admin';
    next();
  }

  // ------------------------------------------------------------- public

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

  // did:web document (also exportable for static hosting: npm run export-did)
  app.get('/.well-known/did.json', (_req, res) => {
    res.set('cache-control', 'public, max-age=300');
    res.type('application/did+json').send(JSON.stringify(keys.didDocument));
  });

  app.get('/.well-known/blockcred-issuer', (_req, res) => {
    res.json({
      issuer: config.did,
      name: config.issuerName,
      credential_endpoint: `${config.publicUrl}/offers/{code}/redeem`,
      proof_typ: 'openid4vci-proof+jwt',
      formats: ['dc+sd-jwt'],
      chain: { chainId: config.chainId, contracts: config.contracts },
    });
  });

  app.post('/offers/:code/redeem', publicLimiter, async (req, res) => {
    const { proof } = z.object({ proof: z.string().max(8192) }).parse(req.body);
    const code = z.string().min(16).max(128).parse(req.params.code);
    res.status(201).json(await redeemOffer(ctx, { code, proof }));
  });

  // Merkle inclusion proof for a credential (hashes only: no personal data).
  app.get('/credentials/:id/anchor-proof', publicLimiter, async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    const { rows } = await pool.query(
      `SELECT c.leaf, c.merkle_proof, b.merkle_root, b.tx_hash, b.anchored_at
         FROM issuer_credentials c LEFT JOIN issuer_batches b ON b.id = c.batch_id
        WHERE c.id = $1`,
      [id],
    );
    if (!rows[0]) throw new BlockCredError('NOT_FOUND', 'Unknown credential');
    const r = rows[0];
    if (!r.merkle_root) return res.status(202).json({ status: 'pending', message: 'Not yet anchored; retry later' });
    res.json({ status: 'anchored', root: r.merkle_root, proof: r.merkle_proof, leaf: r.leaf, txHash: r.tx_hash, anchoredAt: r.anchored_at });
  });

  // ------------------------------------------------------------- admin

  const admin = express.Router();
  admin.use(adminLimiter, requireAdmin);

  admin.get('/status', async (_req, res) => {
    const [chainStatus, counts] = await Promise.all([
      chain.status(),
      pool.query(`SELECT
          (SELECT count(*) FROM issuer_offers)::int AS offers,
          (SELECT count(*) FROM issuer_offers WHERE redeemed_at IS NULL AND expires_at > now())::int AS open_offers,
          (SELECT count(*) FROM issuer_credentials)::int AS credentials,
          (SELECT count(*) FROM issuer_credentials WHERE revoked_at IS NOT NULL)::int AS revoked,
          (SELECT count(*) FROM issuer_credentials WHERE batch_id IS NULL AND leaf IS NOT NULL)::int AS pending_anchor,
          (SELECT count(*) FROM issuer_batches WHERE status = 'anchored')::int AS batches`),
    ]);
    res.json({ issuer: { did: config.did, name: config.issuerName, activeKid: keys.activeKid }, chain: chainStatus, stats: counts.rows[0] });
  });

  admin.post('/offers', async (req, res) => {
    const subjects = parseRecords(req.body, req.get('content-type'));
    const offers = await createOffers(ctx, subjects, { actor: req.actor, source: req.is('text/csv') ? 'csv' : 'admin' });
    res.status(201).json({ offers });
  });

  // Mocked DigiLocker import (real integration requires DigiLocker partner onboarding).
  admin.post('/import/digilocker', async (req, res) => {
    const { documents } = z.object({ documents: z.array(z.unknown()).min(1).max(1000) }).parse(req.body);
    const subjects = documents.map(mapDigiLockerDocument);
    const offers = await createOffers(ctx, subjects, { actor: req.actor, source: 'digilocker-mock' });
    res.status(201).json({ offers });
  });

  admin.get('/offers', async (req, res) => {
    const { limit, offset } = pageSchema.parse(req.query);
    const { rows } = await pool.query(
      `SELECT id, subject_ref, source, created_at, expires_at, redeemed_at, credential_id
         FROM issuer_offers ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset],
    );
    res.json({ offers: rows });
  });

  admin.get('/credentials', async (req, res) => {
    const { limit, offset, subject } = pageSchema.extend({ subject: z.string().optional() }).parse(req.query);
    const { rows } = await pool.query(
      `SELECT c.id, c.subject_ref, c.status_index, c.signing_kid, c.issued_at, c.expires_at,
              c.revoked_at, c.revocation_reason, c.revocation_tx, b.merkle_root, b.tx_hash AS anchor_tx
         FROM issuer_credentials c LEFT JOIN issuer_batches b ON b.id = c.batch_id
        WHERE c.leaf IS NOT NULL AND ($3::text IS NULL OR c.subject_ref = $3)
        ORDER BY c.issued_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset, subject ?? null],
    );
    res.json({ credentials: rows });
  });

  async function revoke(credentialIds, reason, actor) {
    const { rows } = await pool.query(
      'SELECT id, status_index, revoked_at FROM issuer_credentials WHERE id = ANY($1::uuid[]) AND leaf IS NOT NULL',
      [credentialIds],
    );
    if (rows.length !== new Set(credentialIds).size) throw new BlockCredError('NOT_FOUND', 'One or more credentials not found');
    const toRevoke = rows.filter((r) => !r.revoked_at);
    if (!toRevoke.length) throw new BlockCredError('ALREADY_REVOKED', 'Credential(s) already revoked');

    const receipt = await chain.revokeBatch(toRevoke.map((r) => BigInt(r.status_index)));
    await withTransaction(pool, async (db) => {
      await db.query(
        `UPDATE issuer_credentials SET revoked_at = now(), revocation_reason = $2, revocation_tx = $3 WHERE id = ANY($1::uuid[])`,
        [toRevoke.map((r) => r.id), reason ?? null, receipt.hash],
      );
      await audit(db, actor, 'credentials.revoke', { ids: toRevoke.map((r) => r.id), reason, tx: receipt.hash });
    });
    return { revoked: toRevoke.map((r) => r.id), txHash: receipt.hash };
  }

  const reasonSchema = z.string().max(500).optional();

  admin.post('/revocations', async (req, res) => {
    const { credentialIds, reason } = z
      .object({ credentialIds: z.array(z.string().uuid()).min(1).max(512), reason: reasonSchema })
      .parse(req.body);
    res.json(await revoke(credentialIds, reason, req.actor));
  });

  admin.post('/credentials/:id/revoke', async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    const reason = reasonSchema.parse(req.body?.reason);
    res.json(await revoke([id], reason, req.actor));
  });

  admin.post('/anchor', async (_req, res) => {
    res.json(await anchorPending(ctx));
  });

  app.use('/admin', admin);

  // ------------------------------------------------------------- errors

  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND', message: 'Route not found' }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    if (err instanceof ZodError) {
      return res.status(400).json({ error: 'INVALID_REQUEST', message: err.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ') });
    }
    if (err instanceof BlockCredError) {
      return res.status(ERROR_STATUS[err.code] ?? 400).json({ error: err.code, message: err.message });
    }
    if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
      return res.status(err.status ?? 400).json({ error: 'INVALID_REQUEST', message: err.message });
    }
    req.log.error({ err }, 'unhandled error');
    res.status(500).json({ error: 'INTERNAL', message: config.isProduction ? 'Internal error' : err.message });
  });

  return app;
}

const pageSchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(100),
  offset: z.coerce.number().int().min(0).default(0),
});
