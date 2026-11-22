import { randomInt, randomUUID } from 'node:crypto';
import merkle from '@openzeppelin/merkle-tree';
import { parse as parseCsv } from 'csv-parse/sync';
import { keccak256, toUtf8Bytes } from 'ethers';
import { z } from 'zod';
import { DEGREE_DISCLOSABLE_CLAIMS, buildDegreeClaims } from '@blockcred/sdk/credential';
import { issueSdJwt } from '@blockcred/sdk/sdjwt';
import { BlockCredError, nowSeconds } from '@blockcred/sdk/util';
import { audit, withTransaction } from './db.js';
import { activeSigner, controllerFor } from './issuers.js';

const { StandardMerkleTree } = merkle;
const MAX_RECORDS = 5000;

export const recordSchema = z.object({
  student_email: z.string().trim().toLowerCase().email(),
  student_id: z.string().trim().min(1).max(64),
  name: z.string().trim().min(1).max(200),
  degree: z.string().trim().min(1).max(200),
  major: z.string().trim().max(200).optional().default(''),
  cgpa: z.coerce.number().min(0).max(10),
  graduation_date: z.string().trim().regex(/^\d{4}-\d{2}-\d{2}$/, 'must be YYYY-MM-DD'),
});

export function parseRecords(body, contentType = '') {
  let records;
  if (contentType.includes('text/csv')) {
    records = parseCsv(String(body), { columns: true, skip_empty_lines: true, trim: true, bom: true });
  } else {
    records = z.object({ records: z.array(z.record(z.unknown())) }).parse(body).records;
  }
  if (!records.length) throw new BlockCredError('INVALID_REQUEST', 'No records supplied');
  if (records.length > MAX_RECORDS) throw new BlockCredError('INVALID_REQUEST', `At most ${MAX_RECORDS} records per upload`);
  return records.map((r, i) => {
    const res = recordSchema.safeParse(r);
    if (!res.success) {
      throw new BlockCredError('INVALID_REQUEST', `Row ${i + 1}: ${res.error.issues.map((x) => `${x.path.join('.')} ${x.message}`).join('; ')}`);
    }
    return res.data;
  });
}

/** Maps a (mocked) DigiLocker document to a record. */
export function mapDigiLockerDocument(doc) {
  const d = z
    .object({
      data: z.object({
        email: z.string(),
        rollNo: z.string(),
        studentName: z.string(),
        course: z.string(),
        branch: z.string().optional(),
        cgpa: z.union([z.string(), z.number()]),
        resultDate: z.string(),
      }),
    })
    .parse(doc);
  return recordSchema.parse({
    student_email: d.data.email,
    student_id: d.data.rollNo,
    name: d.data.studentName,
    degree: d.data.course,
    major: d.data.branch ?? '',
    cgpa: d.data.cgpa,
    graduation_date: d.data.resultDate.slice(0, 10),
  });
}

/** Signs one awaiting record into an SD-JWT VC bound to the student's wallet key. */
async function issueOne(db, ctx, issuer, signer, row, student) {
  let statusIndex = null;
  for (let attempt = 0; attempt < 16 && statusIndex === null; attempt++) {
    const candidate = randomInt(0, ctx.config.statusIndexSpace);
    await db.query('SAVEPOINT idx');
    try {
      await db.query('UPDATE credentials SET status_index = $2 WHERE id = $1', [row.id, candidate]);
      await db.query('RELEASE SAVEPOINT idx');
      statusIndex = candidate;
    } catch (err) {
      await db.query('ROLLBACK TO SAVEPOINT idx');
      if (err.code !== '23505') throw err;
    }
  }
  if (statusIndex === null) throw new Error('Status index space exhausted; increase STATUS_INDEX_SPACE');

  const issuedAt = nowSeconds();
  const expiresAt = issuedAt + ctx.config.credentialTtlDays * 86400;
  const claims = buildDegreeClaims({
    issuerDid: issuer.did,
    issuerName: issuer.name,
    credentialId: row.id,
    holderJwk: student.holder_public_jwk,
    statusIndex,
    chainId: ctx.config.chainId,
    revocationRegistry: ctx.config.contracts.RevocationRegistry,
    subject: row.claims,
    issuedAt,
    expiresAt,
  });
  const { sdJwt, jwt } = await issueSdJwt({ claims, disclosable: DEGREE_DISCLOSABLE_CLAIMS, signer, decoys: ctx.config.decoyDigests });
  await db.query(
    `UPDATE credentials SET status = 'issued', student_user_id = $2, signing_kid = $3, leaf = $4,
            issued_at = to_timestamp($5), expires_at = to_timestamp($6)
      WHERE id = $1`,
    [row.id, student.user_id, signer.kid, keccak256(toUtf8Bytes(jwt)), issuedAt, expiresAt],
  );
  await db.query('INSERT INTO wallet_items (credential_id, student_user_id, sd_jwt) VALUES ($1, $2, $3)', [row.id, student.user_id, sdJwt]);
}

/**
 * Issues every awaiting record for the given e-mails whose student account exists
 * and whose institution is active. Called after uploads and after student sign-up.
 */
export async function deliverPending(ctx, emails) {
  if (!emails.length) return 0;
  return withTransaction(ctx.pool, async (db) => {
    const { rows } = await db.query(
      `SELECT c.*, sk.user_id AS s_user_id, sk.holder_public_jwk
         FROM credentials c
         JOIN users u ON u.email = c.student_email AND u.role = 'student'
         JOIN student_keys sk ON sk.user_id = u.id
         JOIN issuers i ON i.id = c.issuer_id AND i.status = 'active'
        WHERE c.status = 'awaiting_student' AND c.student_email = ANY($1::text[])
        ORDER BY c.created_at
        FOR UPDATE OF c SKIP LOCKED`,
      [emails],
    );
    const issuerCache = new Map();
    for (const row of rows) {
      if (!issuerCache.has(row.issuer_id)) {
        const { rows: ir } = await db.query('SELECT * FROM issuers WHERE id = $1', [row.issuer_id]);
        issuerCache.set(row.issuer_id, { issuer: ir[0], signer: await activeSigner(ctx, ir[0]) });
      }
      const { issuer, signer } = issuerCache.get(row.issuer_id);
      await issueOne(db, ctx, issuer, signer, row, { user_id: row.s_user_id, holder_public_jwk: row.holder_public_jwk });
      await audit(db, null, 'credential.issue', { credentialId: row.id, issuerId: row.issuer_id });
    }
    return rows.length;
  });
}

export async function addRecords(ctx, issuer, records, userId, source = 'manual') {
  if (issuer.status !== 'active') throw new BlockCredError('ISSUER_NOT_ACTIVE', 'Your institution must be approved before issuing');
  const ids = [];
  await withTransaction(ctx.pool, async (db) => {
    for (const r of records) {
      const id = randomUUID();
      const { student_email: email, ...claims } = r;
      await db.query(
        `INSERT INTO credentials (id, issuer_id, student_email, claims, status) VALUES ($1, $2, $3, $4, 'awaiting_student')`,
        [id, issuer.id, email, claims],
      );
      ids.push(id);
    }
    await audit(db, userId, 'credentials.add', { issuerId: issuer.id, count: records.length, source });
  });
  const delivered = await deliverPending(ctx, [...new Set(records.map((r) => r.student_email))]);
  return { added: ids.length, deliveredNow: delivered, awaitingSignup: ids.length - delivered };
}

export async function revokeCredentials(ctx, issuer, credentialIds, reason, userId) {
  const { rows } = await ctx.pool.query(
    `SELECT id, status, status_index FROM credentials WHERE issuer_id = $1 AND id = ANY($2::uuid[])`,
    [issuer.id, credentialIds],
  );
  if (rows.length !== new Set(credentialIds).size) throw new BlockCredError('NOT_FOUND', 'Credential not found');
  const awaiting = rows.filter((r) => r.status === 'awaiting_student');
  const issued = rows.filter((r) => r.status === 'issued');
  let txHash = null;
  if (issued.length) {
    txHash = (await controllerFor(ctx, issuer).revokeBatch(issuer.did, issued.map((r) => BigInt(r.status_index)))).hash;
  }
  const changed = [...awaiting, ...issued].map((r) => r.id);
  if (!changed.length) throw new BlockCredError('ALREADY_REVOKED', 'Already revoked');
  await ctx.pool.query(
    `UPDATE credentials SET status = 'revoked', revoked_at = now(), revocation_reason = $2, revocation_tx = $3 WHERE id = ANY($1::uuid[])`,
    [changed, reason ?? null, txHash],
  );
  await audit(ctx.pool, userId, 'credentials.revoke', { ids: changed, reason, tx: txHash });
  return { revoked: changed, txHash };
}

/** Anchors one issuer's un-anchored credentials as a single Merkle root. Idempotent and single-leader. */
export async function anchorIssuer(ctx, issuer) {
  const { pool, chain, config, logger } = ctx;
  const lock = await pool.connect();
  try {
    const { rows: lr } = await lock.query('SELECT pg_try_advisory_lock(hashtext($1)) AS ok', [`anchor:${issuer.id}`]);
    if (!lr[0].ok) return { anchored: 0, skipped: 'anchoring already in progress' };
    try {
      const { rows } = await pool.query(
        `SELECT id, leaf FROM credentials WHERE issuer_id = $1 AND batch_id IS NULL AND leaf IS NOT NULL
          ORDER BY issued_at, id LIMIT $2`,
        [issuer.id, config.anchorMaxBatch],
      );
      if (!rows.length) return { anchored: 0 };
      const tree = StandardMerkleTree.of(rows.map((r) => [r.leaf]), ['bytes32']);
      const root = tree.root;
      await pool.query(
        `INSERT INTO batches (id, issuer_id, merkle_root, leaf_count, status) VALUES ($1, $2, $3, $4, 'pending')
         ON CONFLICT (issuer_id, merkle_root) DO UPDATE SET status = 'pending', error = NULL`,
        [randomUUID(), issuer.id, root, rows.length],
      );
      const { rows: br } = await pool.query('SELECT id FROM batches WHERE issuer_id = $1 AND merkle_root = $2', [issuer.id, root]);
      const batchId = br[0].id;
      let txHash = null;
      try {
        if ((await chain.reader.anchoredAt(issuer.did, root)) === 0) {
          txHash = (await controllerFor(ctx, issuer).anchorBatch(issuer.did, root, rows.length)).hash;
        }
      } catch (err) {
        await pool.query(`UPDATE batches SET status = 'failed', error = $2 WHERE id = $1`, [batchId, String(err.shortMessage ?? err.message).slice(0, 500)]);
        throw err;
      }
      await withTransaction(pool, async (db) => {
        await db.query(`UPDATE batches SET status = 'anchored', tx_hash = COALESCE($2, tx_hash), anchored_at = now() WHERE id = $1`, [batchId, txHash]);
        await db.query(
          `UPDATE credentials c SET batch_id = $1, merkle_proof = v.proof::jsonb
             FROM unnest($2::uuid[], $3::text[]) AS v(id, proof) WHERE c.id = v.id`,
          [batchId, rows.map((r) => r.id), rows.map((_, i) => JSON.stringify(tree.getProof(i)))],
        );
      });
      logger.info({ issuer: issuer.did, root, leaves: rows.length, txHash }, 'batch anchored');
      return { anchored: rows.length, root, txHash };
    } finally {
      await lock.query('SELECT pg_advisory_unlock(hashtext($1))', [`anchor:${issuer.id}`]).catch(() => {});
    }
  } finally {
    lock.release();
  }
}

export function startAnchorWorker(ctx) {
  let running = false;
  const timer = setInterval(async () => {
    if (running) return;
    running = true;
    try {
      const { rows } = await ctx.pool.query(
        `SELECT DISTINCT i.* FROM issuers i JOIN credentials c ON c.issuer_id = i.id
          WHERE i.status = 'active' AND c.batch_id IS NULL AND c.leaf IS NOT NULL`,
      );
      for (const issuer of rows) {
        await anchorIssuer(ctx, issuer).catch((err) => ctx.logger.error({ err, issuer: issuer.did }, 'anchoring failed'));
      }
    } catch (err) {
      ctx.logger.error({ err }, 'anchor worker failed');
    } finally {
      running = false;
    }
  }, ctx.config.anchorIntervalSec * 1000);
  timer.unref();
  return () => clearInterval(timer);
}
