import express from 'express';
import { z } from 'zod';
import { requireRole } from '../auth.js';
import { audit, withTransaction } from '../db.js';
import { decline, getForStudent, listForStudent, respond } from '../verification.js';

const hex32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/);

export function studentRoutes(ctx) {
  const r = express.Router();
  r.use(requireRole('student'));

  r.get('/credentials', async (req, res) => {
    const { rows } = await ctx.pool.query(
      `SELECT w.credential_id AS id, w.sd_jwt, w.received_at, c.status, c.revoked_at, c.merkle_proof,
              b.merkle_root, b.tx_hash AS anchor_tx, b.anchored_at, i.name AS issuer_name, i.did AS issuer_did
         FROM wallet_items w
         JOIN credentials c ON c.id = w.credential_id
         JOIN issuers i ON i.id = c.issuer_id
         LEFT JOIN batches b ON b.id = c.batch_id
        WHERE w.student_user_id = $1 ORDER BY w.received_at DESC`,
      [req.user.id],
    );
    res.json({
      credentials: rows.map((x) => ({
        id: x.id,
        sdJwt: x.sd_jwt,
        receivedAt: x.received_at,
        status: x.status,
        revokedAt: x.revoked_at,
        issuer: { name: x.issuer_name, did: x.issuer_did },
        anchor: x.merkle_root ? { root: x.merkle_root, proof: x.merkle_proof, txHash: x.anchor_tx, anchoredAt: x.anchored_at } : null,
      })),
    });
  });

  r.delete('/credentials/:id', async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    await ctx.pool.query('DELETE FROM wallet_items WHERE credential_id = $1 AND student_user_id = $2', [id, req.user.id]);
    res.json({ ok: true });
  });

  r.get('/requests', async (req, res) => res.json({ requests: await listForStudent(ctx, req.user) }));

  r.get('/requests/:id', async (req, res) => {
    res.json(await getForStudent(ctx, req.user, z.string().uuid().parse(req.params.id)));
  });

  r.post('/requests/:id/respond', async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    const body = z
      .object({
        presentation: z.string().min(10).max(32_768),
        anchorProof: z.object({ root: hex32, proof: z.array(hex32).max(64) }).optional(),
      })
      .parse(req.body);
    res.json(await respond(ctx, req.user, id, body));
  });

  r.post('/requests/:id/decline', async (req, res) => {
    res.json(await decline(ctx, req.user, z.string().uuid().parse(req.params.id)));
  });

  r.get('/consents', async (req, res) => {
    const { rows } = await ctx.pool.query(
      `SELECT at, employer_name, purpose, disclosed_fields, verdict, issuer_did FROM consent_log
        WHERE student_user_id = $1 ORDER BY at DESC LIMIT 500`,
      [req.user.id],
    );
    res.json({ consents: rows });
  });

  // Right to erasure: removes the account, wallet key and wallet contents.
  r.delete('/account', async (req, res) => {
    await withTransaction(ctx.pool, async (db) => {
      await db.query('DELETE FROM wallet_items WHERE student_user_id = $1', [req.user.id]);
      await db.query('DELETE FROM users WHERE id = $1', [req.user.id]);
      await audit(db, null, 'account.erase', { role: 'student' });
    });
    res.clearCookie('bc_session', { path: '/' });
    res.json({ ok: true });
  });

  return r;
}
