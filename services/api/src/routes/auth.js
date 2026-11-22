import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';
import { decodeJws, jwkThumbprint, toPublicJwk, verifyJws } from '@blockcred/sdk/jws';
import { BlockCredError, nowSeconds } from '@blockcred/sdk/util';
import { authenticate, createUser, endSession, requireRole, startSession } from '../auth.js';
import { deliverPending } from '../credentials.js';
import { audit, withTransaction } from '../db.js';
import { createIssuer } from '../issuers.js';

// `password` is the client-derived auth secret (see packages/sdk/src/keywrap.js), not the raw password.
const secret = z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'password must be sent as a derived auth secret');
const email = z.string().trim().toLowerCase().email().max(200);
const name = z.string().trim().min(2).max(120);
const jwk = z.object({ kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string(), y: z.string() }).strict();
const wrapped = z.object({
  v: z.literal(1),
  kdf: z.literal('PBKDF2-SHA256'),
  iterations: z.number().int().min(100_000).max(5_000_000),
  salt: z.string().max(64),
  iv: z.string().max(64),
  ciphertext: z.string().max(4096),
});

const signupSchema = z.discriminatedUnion('role', [
  z.object({ role: z.literal('student'), email, password: secret, name, holderPublicJwk: jwk, wrappedKey: wrapped, holderProof: z.string().max(4096) }),
  z.object({ role: z.literal('university'), email, password: secret, name }),
  z.object({ role: z.literal('employer'), email, password: secret, name }),
]);

/** The student proves possession of the wallet key they register. */
async function verifyHolderProof(proof, publicJwk, expectedEmail) {
  const { header, payload } = decodeJws(proof);
  if (header.typ !== 'blockcred-holder-proof+jwt' || !header.jwk) throw new BlockCredError('INVALID_PROOF', 'Malformed holder proof');
  if ((await jwkThumbprint(header.jwk)) !== (await jwkThumbprint(publicJwk))) throw new BlockCredError('INVALID_PROOF', 'Proof key mismatch');
  await verifyJws(proof, toPublicJwk(publicJwk)).catch(() => {
    throw new BlockCredError('INVALID_PROOF', 'Holder proof signature invalid');
  });
  if (payload.aud !== 'blockcred-signup' || payload.nonce !== expectedEmail || Math.abs(nowSeconds() - payload.iat) > 300) {
    throw new BlockCredError('INVALID_PROOF', 'Holder proof is stale or for another account');
  }
}

export async function describeUser(ctx, userId) {
  const { rows } = await ctx.pool.query('SELECT id, email, role, display_name FROM users WHERE id = $1', [userId]);
  const u = rows[0];
  const out = { user: { id: u.id, email: u.email, role: u.role, name: u.display_name } };
  if (u.role === 'student') {
    const { rows: k } = await ctx.pool.query('SELECT holder_public_jwk, holder_thumbprint, wrapped_key FROM student_keys WHERE user_id = $1', [u.id]);
    out.student = { publicJwk: k[0].holder_public_jwk, thumbprint: k[0].holder_thumbprint, wrappedKey: k[0].wrapped_key };
  }
  if (u.role === 'university') {
    const { rows: i } = await ctx.pool.query('SELECT id, name, slug, did, status FROM issuers WHERE user_id = $1', [u.id]);
    out.issuer = i[0];
  }
  return out;
}

export function authRoutes(ctx) {
  const r = express.Router();
  const limiter = rateLimit({ windowMs: 15 * 60_000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false });

  r.post('/signup', limiter, async (req, res) => {
    const body = signupSchema.parse(req.body);
    const userId = await withTransaction(ctx.pool, async (db) => {
      const id = await createUser(db, { email: body.email, secret: body.password, role: body.role, displayName: body.name });
      if (body.role === 'student') {
        await verifyHolderProof(body.holderProof, body.holderPublicJwk, body.email);
        await db.query('INSERT INTO student_keys (user_id, holder_public_jwk, holder_thumbprint, wrapped_key) VALUES ($1, $2, $3, $4)', [
          id,
          body.holderPublicJwk,
          await jwkThumbprint(body.holderPublicJwk),
          body.wrappedKey,
        ]);
      }
      if (body.role === 'university') await createIssuer(db, ctx, { userId: id, name: body.name });
      await audit(db, id, 'account.signup', { role: body.role });
      return id;
    });
    if (body.role === 'student') await deliverPending(ctx, [body.email]);
    await startSession(ctx, res, userId);
    res.status(201).json(await describeUser(ctx, userId));
  });

  r.post('/login', limiter, async (req, res) => {
    const body = z.object({ email, password: secret }).parse(req.body);
    const userId = await authenticate(ctx, body.email, body.password);
    await startSession(ctx, res, userId);
    res.json(await describeUser(ctx, userId));
  });

  r.post('/logout', async (req, res) => {
    await endSession(ctx, req, res);
    res.json({ ok: true });
  });

  r.get('/me', requireRole(), async (req, res) => {
    res.json(await describeUser(ctx, req.user.id));
  });

  return r;
}
