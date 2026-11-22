import express from 'express';
import { z } from 'zod';
import { requireRole } from '../auth.js';
import { approveIssuer, setIssuerStatus } from '../issuers.js';

export function adminRoutes(ctx) {
  const r = express.Router();
  r.use(requireRole('admin'));

  r.get('/overview', async (_req, res) => {
    const [chain, users, issuers, creds] = await Promise.all([
      ctx.chain.status().catch((err) => ({ error: err.message })),
      ctx.pool.query('SELECT role, count(*)::int AS n FROM users GROUP BY role'),
      ctx.pool.query(
        `SELECT i.id, i.name, i.slug, i.did, i.status, i.controller_address, i.registered_tx, i.created_at, i.approved_at, u.email,
                (SELECT count(*) FROM credentials c WHERE c.issuer_id = i.id AND c.status <> 'awaiting_student')::int AS issued
           FROM issuers i JOIN users u ON u.id = i.user_id ORDER BY i.created_at DESC`,
      ),
      ctx.pool.query(`SELECT status, count(*)::int AS n FROM credentials GROUP BY status`),
    ]);
    res.json({
      chain,
      users: Object.fromEntries(users.rows.map((x) => [x.role, x.n])),
      credentials: Object.fromEntries(creds.rows.map((x) => [x.status, x.n])),
      issuers: issuers.rows,
    });
  });

  r.post('/issuers/:id/:action', async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    const action = z.enum(['approve', 'suspend', 'reinstate', 'reject']).parse(req.params.action);
    const result = action === 'approve' ? await approveIssuer(ctx, id, req.user.id) : await setIssuerStatus(ctx, id, action, req.user.id);
    res.json(result);
  });

  return r;
}
