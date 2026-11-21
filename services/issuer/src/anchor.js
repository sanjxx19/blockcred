import { randomUUID } from 'node:crypto';
import merkle from '@openzeppelin/merkle-tree';
import { withTransaction } from './db.js';

const { StandardMerkleTree } = merkle;
const ANCHOR_LOCK = 724_003;

/**
 * Anchors every issued-but-unanchored credential (up to ANCHOR_MAX_BATCH) in a
 * single Merkle root transaction. One replica at a time (advisory lock); safe to
 * retry: if the root is already on-chain (crash after tx), the tx is skipped.
 */
export async function anchorPending({ pool, chain, config, logger }) {
  const lockClient = await pool.connect();
  try {
    const { rows: lockRows } = await lockClient.query('SELECT pg_try_advisory_lock($1) AS locked', [ANCHOR_LOCK]);
    if (!lockRows[0].locked) return { skipped: 'another replica is anchoring' };

    try {
      const { rows } = await pool.query(
        `SELECT id, leaf FROM issuer_credentials
          WHERE batch_id IS NULL AND leaf IS NOT NULL
          ORDER BY issued_at, id
          LIMIT $1`,
        [config.anchorMaxBatch],
      );
      if (!rows.length) return { anchored: 0 };

      const tree = StandardMerkleTree.of(rows.map((r) => [r.leaf]), ['bytes32']);
      const root = tree.root;
      const batchId = randomUUID();
      await pool.query(
        `INSERT INTO issuer_batches (id, merkle_root, leaf_count, status) VALUES ($1, $2, $3, 'pending')
         ON CONFLICT (merkle_root) DO UPDATE SET status = 'pending', error = NULL
         RETURNING id`,
        [batchId, root, rows.length],
      );
      const { rows: batchRows } = await pool.query('SELECT id FROM issuer_batches WHERE merkle_root = $1', [root]);
      const effectiveBatchId = batchRows[0].id;

      let txHash = null;
      try {
        const already = await chain.reader.anchoredAt(config.did, root);
        if (already === 0) {
          const receipt = await chain.anchorBatch(root, rows.length);
          txHash = receipt.hash;
        } else {
          logger.warn({ root }, 'root already anchored on-chain; reconciling database');
        }
      } catch (err) {
        await pool.query(`UPDATE issuer_batches SET status = 'failed', error = $2 WHERE id = $1`, [
          effectiveBatchId,
          String(err.shortMessage ?? err.message).slice(0, 500),
        ]);
        throw err;
      }

      await withTransaction(pool, async (db) => {
        await db.query(
          `UPDATE issuer_batches SET status = 'anchored', tx_hash = COALESCE($2, tx_hash), anchored_at = now() WHERE id = $1`,
          [effectiveBatchId, txHash],
        );
        await db.query(
          `UPDATE issuer_credentials c
              SET batch_id = $1, merkle_proof = v.proof::jsonb
             FROM unnest($2::uuid[], $3::text[]) AS v(id, proof)
            WHERE c.id = v.id`,
          [effectiveBatchId, rows.map((r) => r.id), rows.map((_, i) => JSON.stringify(tree.getProof(i)))],
        );
      });
      logger.info({ root, leaves: rows.length, txHash }, 'batch anchored');
      return { anchored: rows.length, root, txHash, batchId: effectiveBatchId };
    } finally {
      await lockClient.query('SELECT pg_advisory_unlock($1)', [ANCHOR_LOCK]).catch(() => {});
    }
  } finally {
    lockClient.release();
  }
}

export function startAnchorWorker(ctx) {
  let running = false;
  const timer = setInterval(async () => {
    if (running) return;
    running = true;
    try {
      await anchorPending(ctx);
    } catch (err) {
      ctx.logger.error({ err }, 'anchor worker failed');
    } finally {
      running = false;
    }
  }, ctx.config.anchorIntervalSec * 1000);
  timer.unref();
  return () => clearInterval(timer);
}
