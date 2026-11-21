// End-to-end verification pipeline:
//   parse -> resolve issuer DID -> verify signature & disclosures -> holder binding
//   -> on-chain accreditation / schema / revocation -> optional Merkle anchor check

import { keyFromDidDocument } from './did.js';
import { decodeJws } from './jws.js';
import { parseSdJwt, verifySdJwt } from './sdjwt.js';
import { BlockCredError } from './util.js';

export const Verdict = Object.freeze({
  VALID: 'VALID',
  INVALID_FORMAT: 'INVALID_FORMAT',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  UNTRUSTED_ISSUER: 'UNTRUSTED_ISSUER',
  UNKNOWN_SCHEMA: 'UNKNOWN_SCHEMA',
  REVOKED: 'REVOKED',
  EXPIRED: 'EXPIRED',
  HOLDER_BINDING_FAILED: 'HOLDER_BINDING_FAILED',
  REPLAY_DETECTED: 'REPLAY_DETECTED',
  WRONG_STATUS_REGISTRY: 'WRONG_STATUS_REGISTRY',
  NOT_ANCHORED: 'NOT_ANCHORED',
  ISSUER_UNREACHABLE: 'ISSUER_UNREACHABLE',
  ERROR: 'ERROR',
});

const CODE_TO_VERDICT = {
  INVALID_FORMAT: Verdict.INVALID_FORMAT,
  UNSUPPORTED_ALG: Verdict.INVALID_FORMAT,
  UNSUPPORTED_KEY: Verdict.INVALID_FORMAT,
  UNSUPPORTED_DID: Verdict.UNTRUSTED_ISSUER,
  INVALID_DID: Verdict.UNTRUSTED_ISSUER,
  INVALID_SIGNATURE: Verdict.INVALID_SIGNATURE,
  KEY_NOT_FOUND: Verdict.INVALID_SIGNATURE,
  KEY_NOT_AUTHORIZED: Verdict.INVALID_SIGNATURE,
  DID_RESOLUTION_FAILED: Verdict.ISSUER_UNREACHABLE,
  UNTRUSTED_ISSUER: Verdict.UNTRUSTED_ISSUER,
  UNKNOWN_SCHEMA: Verdict.UNKNOWN_SCHEMA,
  EXPIRED: Verdict.EXPIRED,
  NOT_YET_VALID: Verdict.EXPIRED,
  HOLDER_BINDING_FAILED: Verdict.HOLDER_BINDING_FAILED,
  HOLDER_BINDING_REQUIRED: Verdict.HOLDER_BINDING_FAILED,
  INVALID_AUDIENCE: Verdict.REPLAY_DETECTED,
  INVALID_NONCE: Verdict.REPLAY_DETECTED,
  STALE_PRESENTATION: Verdict.REPLAY_DETECTED,
  REVOKED: Verdict.REVOKED,
  WRONG_STATUS_REGISTRY: Verdict.WRONG_STATUS_REGISTRY,
  NOT_ANCHORED: Verdict.NOT_ANCHORED,
};

export class BlockCredVerifier {
  /**
   * @param {object} o
   * @param {object} o.chain        BlockCredChain (or anything with the same read methods)
   * @param {object} o.didResolver  DidWebResolver
   * @param {string} [o.audience]   default expected KB-JWT `aud` (your verifier id)
   * @param {object} [o.policy]
   * @param {boolean} [o.policy.requireKeyBinding=true]
   * @param {boolean} [o.policy.requireAnchor=false]
   * @param {string[]} [o.policy.allowedVcts]   restrict credential types
   * @param {number} [o.policy.kbMaxAgeSec=300]
   * @param {number} [o.policy.clockSkewSec=60]
   */
  constructor({ chain, didResolver, audience, policy = {} }) {
    this.chain = chain;
    this.didResolver = didResolver;
    this.audience = audience;
    this.policy = { requireKeyBinding: true, requireAnchor: false, kbMaxAgeSec: 300, clockSkewSec: 60, ...policy };
  }

  /**
   * Never throws for verification failures: returns { valid, verdict, ... }.
   * @param {string} presentation SD-JWT(+KB) compact string
   * @param {object} [o]
   * @param {string} [o.nonce]     expected nonce (required to detect replays)
   * @param {string} [o.audience]  overrides constructor audience
   * @param {{root:string, proof:string[]}} [o.anchorProof]
   */
  async verify(presentation, o = {}) {
    const checks = {};
    try {
      return await this.#verify(presentation, o, checks);
    } catch (err) {
      const code = err instanceof BlockCredError ? err.code : 'ERROR';
      return {
        valid: false,
        verdict: CODE_TO_VERDICT[code] ?? Verdict.ERROR,
        errorCode: code,
        error: err.message,
        checks,
      };
    }
  }

  async #verify(presentation, o, checks) {
    const { jwt } = parseSdJwt(presentation);
    const { header: unverifiedHeader, payload: unverifiedPayload } = decodeJws(jwt);
    const iss = unverifiedPayload.iss;
    if (typeof iss !== 'string') throw new BlockCredError('INVALID_FORMAT', 'Missing iss');

    // 1. Signature, disclosures, expiry and holder binding.
    const result = await verifySdJwt(presentation, {
      resolveIssuerKey: async () => {
        const doc = await this.didResolver.resolve(iss);
        checks.didResolved = true;
        return keyFromDidDocument(doc, unverifiedHeader.kid, 'assertionMethod');
      },
      requireKeyBinding: this.policy.requireKeyBinding,
      expectedAud: o.audience ?? this.audience,
      expectedNonce: o.nonce,
      kbMaxAgeSec: this.policy.kbMaxAgeSec,
      clockSkewSec: this.policy.clockSkewSec,
    });
    checks.signature = true;
    checks.notExpired = true;
    checks.holderBinding = Boolean(result.keyBinding);

    const { payload } = result;
    if (this.policy.allowedVcts && !this.policy.allowedVcts.includes(payload.vct)) {
      throw new BlockCredError('UNKNOWN_SCHEMA', `Credential type ${payload.vct} not accepted by this verifier`);
    }

    // 2. Status pointer must reference *our* trusted registry on *our* chain.
    const status = payload.status?.blockcred;
    if (!status || typeof status.idx !== 'number' || !Number.isSafeInteger(status.idx) || status.idx < 0) {
      throw new BlockCredError('INVALID_FORMAT', 'Missing or malformed status.blockcred');
    }
    if (
      Number(status.chain_id) !== this.chain.chainId ||
      String(status.registry).toLowerCase() !== this.chain.addresses.RevocationRegistry.toLowerCase()
    ) {
      throw new BlockCredError('WRONG_STATUS_REGISTRY', 'Credential status points to an untrusted chain or registry');
    }

    // 3. On-chain trust checks (in parallel).
    const [accredited, schemaOk, revoked] = await Promise.all([
      this.chain.isAccredited(iss),
      this.chain.isSchemaRegistered(payload.vct),
      this.chain.isRevoked(iss, status.idx),
    ]);
    checks.issuerAccredited = accredited;
    checks.schemaRegistered = schemaOk;
    checks.notRevoked = !revoked;
    if (!accredited) throw new BlockCredError('UNTRUSTED_ISSUER', 'Issuer is not accredited on-chain');
    if (!schemaOk) throw new BlockCredError('UNKNOWN_SCHEMA', 'Credential schema is not registered on-chain');
    if (revoked) throw new BlockCredError('REVOKED', 'Credential has been revoked');

    // 4. Optional batch anchor (tamper-evidence / proof of issuance time).
    let anchoredAt = null;
    if (o.anchorProof?.root && Array.isArray(o.anchorProof.proof)) {
      const { credentialLeafValue, standardLeafHash, verifyMerkleProof } = await import('./merkle.js');
      const leaf = standardLeafHash(credentialLeafValue(result.issuerJwt));
      const included = verifyMerkleProof(o.anchorProof.root, leaf, o.anchorProof.proof);
      const ts = included ? await this.chain.anchoredAt(iss, o.anchorProof.root) : 0;
      checks.anchored = included && ts > 0;
      if (checks.anchored) anchoredAt = new Date(ts * 1000).toISOString();
    } else {
      checks.anchored = false;
    }
    if (this.policy.requireAnchor && !checks.anchored) {
      throw new BlockCredError('NOT_ANCHORED', 'Credential is not anchored in an on-chain batch');
    }

    return {
      valid: true,
      verdict: Verdict.VALID,
      issuer: { did: iss, name: payload.issuer_name ?? null },
      credential: {
        id: payload.jti ?? null,
        type: payload.vct,
        issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
        expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
        statusIndex: status.idx,
        anchoredAt,
      },
      disclosed: result.disclosed,
      holder: result.keyBinding ? { thumbprint: result.keyBinding.holderThumbprint } : null,
      checks,
    };
  }
}
