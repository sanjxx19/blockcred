import express from 'express';
import { z } from 'zod';
import { requireRole } from '../auth.js';
import { addRecords, anchorIssuer, mapDigiLockerDocument, parseRecords, revokeCredentials } from '../credentials.js';
import { controllerFor, getIssuerByUser, issuerKeys, rotateSigningKey } from '../issuers.js';

export function universityRoutes(ctx) {
  const r = express.Router();
  r.use(requireRole('university'));
  r.use(async (req, _res, next) => {
    req.issuer = await getIssuerByUser(ctx.pool, req.user.id);
    next();
  });

  r.get('/overview', async (req, res) => {
    const i = req.issuer;
    const [stats, balance, onChain] = await Promise.all([
      ctx.pool.query(
        `SELECT
           count(*) FILTER (WHERE status = 'awaiting_student')::int AS awaiting,
           count(*) FILTER (WHERE status = 'issued')::int AS issued,
           count(*) FILTER (WHERE status = 'revoked')::int AS revoked,
           count(*) FILTER (WHERE leaf IS NOT NULL AND batch_id IS NULL)::int AS pending_anchor
         FROM credentials WHERE issuer_id = $1`,
        [i.id],
      ),
      controllerFor(ctx, i).balance().catch(() => null),
      ctx.chain.issuerOnChain(i.did).catch(() => ({ status: 'unknown' })),
    ]);
    res.json({
      issuer: {
        name: i.name,
        slug: i.slug,
        did: i.did,
        status: i.status,
        didDocumentUrl: `${ctx.config.publicUrl}/issuers/${i.slug}/did.json`,
        controller: i.controller_address,
        controllerBalance: balance,
        onChainStatus: onChain.status,
        registeredTx: i.registered_tx,
        keys: issuerKeys(ctx, i).map((k) => ({ id: k.id, status: k.status, createdAt: k.createdAt })),
      },
      stats: stats.rows[0],
    });
  });

  r.post('/credentials', async (req, res) => {
    const records = parseRecords(req.body, req.get('content-type'));
    res.status(201).json(await addRecords(ctx, req.issuer, records, req.user.id, req.is('text/csv') ? 'csv' : 'manual'));
  });

  r.post('/import/digilocker', async (req, res) => {
    const { documents } = z.object({ documents: z.array(z.unknown()).min(1).max(1000) }).parse(req.body);
    res.status(201).json(await addRecords(ctx, req.issuer, documents.map(mapDigiLockerDocument), req.user.id, 'digilocker-mock'));
  });

  r.get('/credentials', async (req, res) => {
    const limit = z.coerce.number().int().min(1).max(1000).default(500).parse(req.query.limit);
    const { rows } = await ctx.pool.query(
      `SELECT c.id, c.student_email, c.claims, c.status, c.status_index, c.signing_kid, c.created_at, c.issued_at,
              c.revoked_at, c.revocation_reason, c.revocation_tx, b.merkle_root, b.tx_hash AS anchor_tx
         FROM credentials c LEFT JOIN batches b ON b.id = c.batch_id
        WHERE c.issuer_id = $1 ORDER BY c.created_at DESC LIMIT $2`,
      [req.issuer.id, limit],
    );
    res.json({ credentials: rows });
  });

  r.post('/credentials/:id/revoke', async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    const reason = z.string().max(500).optional().parse(req.body?.reason);
    res.json(await revokeCredentials(ctx, req.issuer, [id], reason, req.user.id));
  });

  r.post('/anchor', async (req, res) => {
    res.json(await anchorIssuer(ctx, req.issuer));
  });

  r.post('/rotate-key', async (req, res) => {
    const { compromised } = z.object({ compromised: z.boolean().default(false) }).parse(req.body ?? {});
    res.json({ keys: await rotateSigningKey(ctx, req.issuer, { compromised }, req.user.id) });
  });

  return r;
}
