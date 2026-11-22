import { randomUUID, webcrypto } from 'node:crypto';
import { Wallet } from 'ethers';
import { buildDidWebDocument, didWebFromUrl } from '@blockcred/sdk/did';
import { signerFromJwk, toPublicJwk } from '@blockcred/sdk/jws';
import { BlockCredError } from '@blockcred/sdk/util';
import { audit } from './db.js';

async function generateSigningKey(id) {
  const { privateKey } = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { kty, crv, x, y, d } = await webcrypto.subtle.exportKey('jwk', privateKey);
  return { id, status: 'active', createdAt: new Date().toISOString(), privateJwk: { kty, crv, x, y, d } };
}

function slugify(name) {
  return (
    name
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40) || 'issuer'
  );
}

/**
 * Called at university sign-up. Creates the institution's did:web identity
 * (did:web:<host>:issuers:<slug>), its first signing key and its on-chain controller
 * account. Nothing is on-chain until the accreditation admin approves it.
 */
export async function createIssuer(db, { box, config }, { userId, name }) {
  const base = slugify(name);
  let slug = base;
  for (let i = 0; i < 5; i++) {
    const { rowCount } = await db.query('SELECT 1 FROM issuers WHERE slug = $1', [slug]);
    if (!rowCount) break;
    slug = `${base}-${Math.random().toString(36).slice(2, 6)}`;
  }
  const did = didWebFromUrl(`${config.publicUrl}/issuers/${slug}`);
  const controller = Wallet.createRandom();
  const id = randomUUID();
  await db.query(
    `INSERT INTO issuers (id, user_id, slug, name, did, status, keys_enc, controller_address, controller_key_enc)
     VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8)`,
    [id, userId, slug, name, did, box.seal([await generateSigningKey('key-1')]), controller.address, box.seal(controller.privateKey)],
  );
  return { id, slug, did };
}

export function issuerKeys({ box }, issuer) {
  return box.open(issuer.keys_enc);
}

export function didDocumentFor(ctx, issuer) {
  const keys = issuerKeys(ctx, issuer);
  return buildDidWebDocument({
    did: issuer.did,
    keys: keys.map((k) => ({ id: k.id, status: k.status, publicJwk: toPublicJwk(k.privateJwk) })),
    services: [{ id: `${issuer.did}#issuer`, type: 'BlockCredIssuer', serviceEndpoint: ctx.config.publicUrl }],
  });
}

export async function activeSigner(ctx, issuer) {
  const active = issuerKeys(ctx, issuer).find((k) => k.status === 'active');
  return signerFromJwk(active.privateJwk, { kid: `${issuer.did}#${active.id}` });
}

export const controllerFor = (ctx, issuer) => ctx.chain.controller(ctx.box.open(issuer.controller_key_enc));

export async function getIssuerByUser(db, userId) {
  const { rows } = await db.query('SELECT * FROM issuers WHERE user_id = $1', [userId]);
  if (!rows[0]) throw new BlockCredError('NOT_FOUND', 'No institution linked to this account');
  return rows[0];
}

/** Admin approval: register DID + controller on-chain and fund the controller for gas. */
export async function approveIssuer(ctx, issuerId, adminId) {
  const { pool, chain, config, logger } = ctx;
  const { rows } = await pool.query('SELECT * FROM issuers WHERE id = $1', [issuerId]);
  const issuer = rows[0];
  if (!issuer) throw new BlockCredError('NOT_FOUND', 'Unknown institution');
  if (!['pending', 'rejected'].includes(issuer.status)) throw new BlockCredError('INVALID_STATE', `Institution is ${issuer.status}`);

  const onChain = await chain.issuerOnChain(issuer.did);
  let txHash = issuer.registered_tx;
  if (onChain.status === 'none') {
    txHash = (await chain.registerIssuer(issuer.did, issuer.controller_address, `${config.publicUrl}/issuers/${issuer.slug}/did.json`)).hash;
  } else if (onChain.status !== 'active') {
    throw new BlockCredError('INVALID_STATE', `Issuer is ${onChain.status} on-chain`);
  }
  if (Number(config.issuerFundingEth) > 0) {
    await chain.fund(issuer.controller_address, config.issuerFundingEth);
  }
  await pool.query(`UPDATE issuers SET status = 'active', registered_tx = $2, approved_at = now() WHERE id = $1`, [issuerId, txHash]);
  await audit(pool, adminId, 'issuer.approve', { issuerId, did: issuer.did, tx: txHash });
  logger.info({ did: issuer.did }, 'issuer approved');
  return { status: 'active', txHash };
}

export async function setIssuerStatus(ctx, issuerId, action, adminId) {
  const { pool, chain } = ctx;
  const { rows } = await pool.query('SELECT * FROM issuers WHERE id = $1', [issuerId]);
  const issuer = rows[0];
  if (!issuer) throw new BlockCredError('NOT_FOUND', 'Unknown institution');
  let next;
  let tx = null;
  if (action === 'suspend' && issuer.status === 'active') {
    tx = (await chain.suspendIssuer(issuer.did)).hash;
    next = 'suspended';
  } else if (action === 'reinstate' && issuer.status === 'suspended') {
    tx = (await chain.reinstateIssuer(issuer.did)).hash;
    next = 'active';
  } else if (action === 'reject' && issuer.status === 'pending') {
    next = 'rejected';
  } else {
    throw new BlockCredError('INVALID_STATE', `Cannot ${action} an institution that is ${issuer.status}`);
  }
  await pool.query('UPDATE issuers SET status = $2 WHERE id = $1', [issuerId, next]);
  await audit(pool, adminId, `issuer.${action}`, { issuerId, tx });
  return { status: next, txHash: tx };
}

/**
 * Key rotation. normal: old key -> retired (still published, old credentials verify).
 * compromised: old key -> revoked (removed from DID document; its credentials stop verifying).
 */
export async function rotateSigningKey(ctx, issuer, { compromised = false }, userId) {
  const keys = issuerKeys(ctx, issuer);
  const next = Math.max(...keys.map((k) => Number(k.id.split('-')[1]) || 0)) + 1;
  for (const k of keys) if (k.status === 'active') k.status = compromised ? 'revoked' : 'retired';
  keys.push(await generateSigningKey(`key-${next}`));
  await ctx.pool.query('UPDATE issuers SET keys_enc = $2 WHERE id = $1', [issuer.id, ctx.box.seal(keys)]);
  ctx.didResolver.invalidate(issuer.did);
  await audit(ctx.pool, userId, 'issuer.rotate_key', { issuerId: issuer.id, compromised, newKey: `key-${next}` });
  return keys.map((k) => ({ id: k.id, status: k.status, createdAt: k.createdAt }));
}
