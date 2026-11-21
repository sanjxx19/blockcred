import { createHash, randomInt, randomUUID } from 'node:crypto';
import { parse as parseCsv } from 'csv-parse/sync';
import { keccak256, toUtf8Bytes } from 'ethers';
import { z } from 'zod';
import { DEGREE_DISCLOSABLE_CLAIMS, buildDegreeClaims } from '@blockcred/sdk/credential';
import { decodeJws, jwkThumbprint, toPublicJwk, verifyJws } from '@blockcred/sdk/jws';
import { issueSdJwt } from '@blockcred/sdk/sdjwt';
import { BlockCredError, nowSeconds, randomToken } from '@blockcred/sdk/util';
import { audit, withTransaction } from './db.js';

export const PROOF_TYP = 'openid4vci-proof+jwt';
const MAX_RECORDS = 5000;

export const subjectSchema = z.object({
  student_id: z.string().trim().min(1).max(64),
  name: z.string().trim().min(1).max(200),
  degree: z.string().trim().min(1).max(200),
  major: z.string().trim().max(200).optional().default(''),
  cgpa: z.coerce.number().min(0).max(10),
  graduation_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'graduation_date must be YYYY-MM-DD'),
});

export const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');

export function parseRecords(body, contentType = '') {
  let records;
  if (contentType.includes('text/csv')) {
    records = parseCsv(String(body), { columns: true, skip_empty_lines: true, trim: true, bom: true });
  } else {
    records = z.object({ records: z.array(z.record(z.unknown())) }).parse(body).records;
  }
  if (!records.length) throw new BlockCredError('INVALID_REQUEST', 'No records supplied');
  if (records.length > MAX_RECORDS) throw new BlockCredError('INVALID_REQUEST', `At most ${MAX_RECORDS} records per request`);
  return records.map((r, i) => {
    const res = subjectSchema.safeParse(r);
    if (!res.success) {
      throw new BlockCredError('INVALID_REQUEST', `Record ${i + 1}: ${res.error.issues.map((x) => `${x.path.join('.')} ${x.message}`).join('; ')}`);
    }
    return res.data;
  });
}

/** Maps a (mocked) DigiLocker "issued document" payload to our subject schema. */
export function mapDigiLockerDocument(doc) {
  const d = z
    .object({
      uri: z.string(),
      doctype: z.string(),
      issuer: z.object({ name: z.string() }).passthrough(),
      data: z.object({
        rollNo: z.string(),
        studentName: z.string(),
        course: z.string(),
        branch: z.string().optional(),
        cgpa: z.union([z.string(), z.number()]),
        resultDate: z.string(),
      }),
    })
    .parse(doc);
  return subjectSchema.parse({
    student_id: d.data.rollNo,
    name: d.data.studentName,
    degree: d.data.course,
    major: d.data.branch ?? '',
    cgpa: d.data.cgpa,
    graduation_date: d.data.resultDate.slice(0, 10),
  });
}

/** Creates one-time credential offers (OpenID4VCI "pre-authorized code"-inspired). */
export async function createOffers({ pool, config }, subjects, { actor, source }) {
  const expiresAt = new Date(Date.now() + config.offerTtlHours * 3600_000);
  const created = [];
  await withTransaction(pool, async (db) => {
    for (const subject of subjects) {
      const id = randomUUID();
      const code = randomToken(24);
      await db.query(
        `INSERT INTO issuer_offers (id, code_hash, subject_ref, claims, source, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [id, sha256Hex(code), subject.student_id, subject, source, expiresAt],
      );
      const walletLink = `${config.walletUrl}/#/wallet?issuer=${encodeURIComponent(config.publicUrl)}&code=${encodeURIComponent(code)}`;
      created.push({ offerId: id, studentId: subject.student_id, name: subject.name, offerCode: code, walletLink, expiresAt });
    }
    await audit(db, actor, 'offers.create', { count: subjects.length, source });
  });
  return created;
}

/** Verifies the holder's proof-of-possession JWT and returns the holder public JWK. */
export async function verifyHolderProof(proof, { issuerDid, code, maxAgeSec = 300 }) {
  const { header, payload } = decodeJws(proof);
  if (header.typ !== PROOF_TYP) throw new BlockCredError('INVALID_PROOF', `proof typ must be ${PROOF_TYP}`);
  if (!header.jwk) throw new BlockCredError('INVALID_PROOF', 'proof header must contain the holder jwk');
  const holderJwk = toPublicJwk(header.jwk);
  try {
    await verifyJws(proof, holderJwk);
  } catch {
    throw new BlockCredError('INVALID_PROOF', 'proof signature invalid');
  }
  const now = nowSeconds();
  if (payload.aud !== issuerDid) throw new BlockCredError('INVALID_PROOF', 'proof aud must be the issuer DID');
  if (payload.nonce !== code) throw new BlockCredError('INVALID_PROOF', 'proof nonce must be the offer code');
  if (typeof payload.iat !== 'number' || Math.abs(now - payload.iat) > maxAgeSec) {
    throw new BlockCredError('INVALID_PROOF', 'proof iat outside the allowed window');
  }
  return holderJwk;
}

/** Redeems an offer: binds the credential to the holder key and signs the SD-JWT VC. */
export async function redeemOffer({ pool, config, keys }, { code, proof }) {
  const holderJwk = await verifyHolderProof(proof, { issuerDid: config.did, code });
  const holderThumbprint = await jwkThumbprint(holderJwk);

  return withTransaction(pool, async (db) => {
    const { rows } = await db.query('SELECT * FROM issuer_offers WHERE code_hash = $1 FOR UPDATE', [sha256Hex(code)]);
    const offer = rows[0];
    if (!offer) throw new BlockCredError('OFFER_NOT_FOUND', 'Unknown offer code');
    if (offer.redeemed_at) throw new BlockCredError('OFFER_REDEEMED', 'Offer has already been redeemed');
    if (offer.expires_at < new Date()) throw new BlockCredError('OFFER_EXPIRED', 'Offer has expired');

    const credentialId = randomUUID();
    const issuedAt = nowSeconds();
    const expiresAt = issuedAt + config.credentialTtlDays * 86400;

    // Random (non-sequential) status index: hides issuance order and volume.
    let statusIndex = null;
    for (let attempt = 0; attempt < 16 && statusIndex === null; attempt++) {
      const candidate = randomInt(0, config.statusIndexSpace);
      const res = await db.query(
        `INSERT INTO issuer_credentials (id, offer_id, subject_ref, status_index, holder_thumbprint, signing_kid, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7))
         ON CONFLICT (status_index) DO NOTHING RETURNING id`,
        [credentialId, offer.id, offer.subject_ref, candidate, holderThumbprint, keys.activeKid, expiresAt],
      );
      if (res.rowCount === 1) statusIndex = candidate;
    }
    if (statusIndex === null) throw new Error('Status index space exhausted; increase STATUS_INDEX_SPACE');

    const claims = buildDegreeClaims({
      issuerDid: config.did,
      issuerName: config.issuerName,
      credentialId,
      holderJwk,
      statusIndex,
      chainId: config.chainId,
      revocationRegistry: config.contracts.RevocationRegistry,
      subject: offer.claims,
      issuedAt,
      expiresAt,
    });
    const { sdJwt, jwt } = await issueSdJwt({
      claims,
      disclosable: DEGREE_DISCLOSABLE_CLAIMS,
      signer: keys.signer,
      decoys: config.decoyDigests,
    });

    await db.query('UPDATE issuer_credentials SET leaf = $2 WHERE id = $1', [credentialId, keccak256(toUtf8Bytes(jwt))]);
    await db.query(
      `UPDATE issuer_offers SET redeemed_at = now(), credential_id = $2, claims = CASE WHEN $3::boolean THEN NULL ELSE claims END WHERE id = $1`,
      [offer.id, credentialId, config.purgeOfferClaims],
    );
    await audit(db, `holder:${holderThumbprint}`, 'credential.issue', { credentialId, offerId: offer.id });

    return { format: 'dc+sd-jwt', credential: sdJwt, credentialId, statusIndex, expiresAt: new Date(expiresAt * 1000).toISOString() };
  });
}
