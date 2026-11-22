import express from 'express';
import { requireRole } from '../auth.js';
import { createRequest, listForEmployer, requestInputSchema } from '../verification.js';

export function employerRoutes(ctx) {
  const r = express.Router();
  r.use(requireRole('employer'));

  r.post('/requests', async (req, res) => {
    res.status(201).json(await createRequest(ctx, req.user, requestInputSchema.parse(req.body)));
  });

  r.get('/requests', async (req, res) => res.json({ requests: await listForEmployer(ctx, req.user) }));

  return r;
}
