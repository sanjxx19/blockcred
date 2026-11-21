import { buildDidWebDocument } from '@blockcred/sdk/did';
import { signerFromJwk, toPublicJwk } from '@blockcred/sdk/jws';

/**
 * Loads issuer signing keys.
 *  - active:  signs new credentials
 *  - retired: still published in the DID document so older credentials keep verifying
 *  - revoked: removed from the DID document (use after a key compromise)
 *
 * Production: replace signerFromJwk with an HSM / cloud KMS signer that implements
 * the same { alg, kid, sign(bytes) } interface (see packages/sdk/src/jws.js).
 */
export async function loadIssuerKeys(config) {
  const active = config.keys.find((k) => k.status === 'active');
  const signer = await signerFromJwk(active.privateJwk, { kid: `${config.did}#${active.id}` });
  const didDocument = buildDidWebDocument({
    did: config.did,
    keys: config.keys.map((k) => ({ id: k.id, status: k.status, publicJwk: toPublicJwk(k.privateJwk) })),
    services: [{ id: `${config.did}#issuer`, type: 'BlockCredIssuer', serviceEndpoint: config.publicUrl }],
  });
  return { signer, activeKid: signer.kid, didDocument };
}
