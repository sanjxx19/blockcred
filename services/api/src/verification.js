import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { DEGREE_DISCLOSABLE_CLAIMS } from '@blockcred/sdk/credential';
import { BlockCredError, randomToken } from '@blockcred/sdk/util';
import { audit } from './db.js';

export const requestInputSchema = z.object({
  studentEmail: z
    .string()
    .trim()
    .toLowerCase()
    .email()
    .optional()
    .or(z.literal('').transform(() => undefined)),
  fields: z.array(z.enum(DEGREE_DISCLOSABLE_CLAIMS)).min(1).max(DEGREE_DISCLOSABLE_CLAIMS.length),
  purpose: z.string().trim().min(3).max(200),
});

/** Each employer has its own audience, so a presentation made for one employer is useless to another. */
export const audienceFor = (config, employerId) => `${config.publicUrl}/verifiers/${employerId}`;

export async function createRequest(ctx, employer, input) {
  const id = randomUUID();
  const expires = new Date(Date.now() + ctx.config.requestTtlHours * 3600_000);
  let studentUserId = null;
  if (input.studentEmail) {
    const { rows } = await ctx.pool.query(`SELECT id FROM users WHERE email = $1 AND role = 'student'`, [input.studentEmail]);
    studentUserId = rows[0]?.id ?? null;
  }
  await ctx.pool.query(
    `INSERT INTO verification_requests (id, employer_user_id, student_email, student_user_id, nonce, audience, purpose, requested_fields, status, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9)`,
    [id, employer.id, input.studentEmail ?? null, studentUserId, randomToken(24), audienceFor(ctx.config, employer.id), input.purpose, input.fields, expires],
  );
  await audit(ctx.pool, employer.id, 'request.create', { id, targeted: Boolean(input.studentEmail) });
  return { id, code: id, expiresAt: expires, studentHasAccount: input.studentEmail ? Boolean(studentUserId) : null };
}

const STUDENT_VIEW = `
  SELECT r.id, r.nonce, r.audience, r.purpose, r.requested_fields, r.status, r.verdict, r.created_at, r.expires_at,
         r.completed_at, r.student_email, u.display_name AS employer_name
    FROM verification_requests r JOIN users u ON u.id = r.employer_user_id`;

export async function listForStudent(ctx, student) {
  const { rows } = await ctx.pool.query(
    `${STUDENT_VIEW} WHERE r.student_user_id = $1 OR r.student_email = $2 ORDER BY r.created_at DESC LIMIT 200`,
    [student.id, student.email],
  );
  return rows.map((r) => publicRequest(r));
}

/** Students can open a request addressed to them, or an open request by its code. */
export async function getForStudent(ctx, student, id) {
  const { rows } = await ctx.pool.query(`${STUDENT_VIEW} WHERE r.id = $1`, [id]);
  const r = rows[0];
  if (!r || (r.student_email && r.student_email !== student.email)) throw new BlockCredError('NOT_FOUND', 'Request not found');
  return publicRequest(r);
}

function publicRequest(r) {
  const expired = r.status === 'pending' && new Date(r.expires_at) < new Date();
  return {
    id: r.id,
    employer: r.employer_name,
    purpose: r.purpose,
    fields: r.requested_fields,
    status: expired ? 'expired' : r.status,
    verdict: r.verdict,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    completedAt: r.completed_at,
    // Only what the wallet needs to build the key-binding JWT:
    aud: r.audience,
    nonce: r.status === 'pending' && !expired ? r.nonce : undefined,
  };
}

/**
 * Student submits a presentation. The nonce is consumed atomically (replay-proof), the
 * presentation is fully verified (signature, holder binding, on-chain accreditation,
 * schema, revocation, anchor) and must be bound to THIS student's registered key.
 */
export async function respond(ctx, student, id, { presentation, anchorProof }) {
  const { pool, verifier } = ctx;
  const { rows } = await pool.query(
    `UPDATE verification_requests SET status = 'processing', student_user_id = $2
      WHERE id = $1 AND status = 'pending' AND expires_at > now()
        AND (student_email IS NULL OR student_email = $3)
      RETURNING nonce, audience, purpose, requested_fields, employer_user_id,
                (SELECT display_name FROM users WHERE id = employer_user_id) AS employer_name`,
    [id, student.id, student.email],
  );
  if (!rows[0]) throw new BlockCredError('REQUEST_CLOSED', 'This request is unknown, expired or already answered');
  const req = rows[0];

  let result;
  try {
    result = await verifier.verify(presentation, { nonce: req.nonce, audience: req.audience, anchorProof });
    const { rows: kr } = await pool.query('SELECT holder_thumbprint FROM student_keys WHERE user_id = $1', [student.id]);
    if (result.valid && result.holder?.thumbprint !== kr[0]?.holder_thumbprint) {
      result = { valid: false, verdict: 'HOLDER_BINDING_FAILED', error: 'Credential belongs to a different wallet', checks: result.checks };
    }
  } catch (err) {
    await pool.query(`UPDATE verification_requests SET status = 'failed', verdict = 'ERROR', completed_at = now() WHERE id = $1`, [id]);
    throw err;
  }

  const disclosed = Object.keys(result.disclosed ?? {});
  const stored = { ...result, missingFields: req.requested_fields.filter((f) => !disclosed.includes(f)) };
  await pool.query(`UPDATE verification_requests SET status = 'completed', verdict = $2, result = $3, completed_at = now() WHERE id = $1`, [
    id,
    result.verdict,
    stored,
  ]);
  await pool.query(
    `INSERT INTO consent_log (request_id, student_user_id, employer_user_id, employer_name, issuer_did, disclosed_fields, purpose, verdict)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [id, student.id, req.employer_user_id, req.employer_name, result.issuer?.did ?? null, disclosed, req.purpose, result.verdict],
  );
  return { verdict: result.verdict, valid: result.valid, sharedFields: disclosed, missingFields: stored.missingFields };
}

export async function decline(ctx, student, id) {
  const { rowCount } = await ctx.pool.query(
    `UPDATE verification_requests SET status = 'declined', student_user_id = $2, completed_at = now()
      WHERE id = $1 AND status = 'pending' AND (student_email IS NULL OR student_email = $3)`,
    [id, student.id, student.email],
  );
  if (!rowCount) throw new BlockCredError('REQUEST_CLOSED', 'This request is unknown or already answered');
  await ctx.pool.query(
    `INSERT INTO consent_log (request_id, student_user_id, employer_user_id, employer_name, purpose, verdict)
     SELECT r.id, $2, r.employer_user_id, u.display_name, r.purpose, 'DECLINED'
       FROM verification_requests r JOIN users u ON u.id = r.employer_user_id WHERE r.id = $1`,
    [id, student.id],
  );
  return { status: 'declined' };
}

export async function listForEmployer(ctx, employer) {
  const { rows } = await ctx.pool.query(
    `SELECT r.id, r.student_email, r.purpose, r.requested_fields, r.status, r.verdict, r.result, r.claims_purged,
            r.created_at, r.expires_at, r.completed_at, s.display_name AS student_name
       FROM verification_requests r LEFT JOIN users s ON s.id = r.student_user_id
      WHERE r.employer_user_id = $1 ORDER BY r.created_at DESC LIMIT 200`,
    [employer.id],
  );
  return rows.map((r) => ({
    ...r,
    status: r.status === 'pending' && new Date(r.expires_at) < new Date() ? 'expired' : r.status,
  }));
}

/** DPDP purpose limitation: drop disclosed values after the retention window. */
export function startPurgeWorker(ctx) {
  const timer = setInterval(async () => {
    try {
      const { rowCount } = await ctx.pool.query(
        `UPDATE verification_requests SET result = result - 'disclosed', claims_purged = true
          WHERE claims_purged = false AND completed_at IS NOT NULL
            AND completed_at < now() - make_interval(hours => $1)`,
        [ctx.config.resultRetentionHours],
      );
      if (rowCount) ctx.logger.info({ rowCount }, 'purged disclosed claims');
      await ctx.pool.query('DELETE FROM sessions WHERE expires_at < now()');
    } catch (err) {
      ctx.logger.error({ err }, 'purge worker failed');
    }
  }, 5 * 60_000);
  timer.unref();
  return () => clearInterval(timer);
}
