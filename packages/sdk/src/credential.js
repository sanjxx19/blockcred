// Credential profile shared by issuer, wallet and verifier.

export const DEGREE_VCT = 'urn:blockcred:vct:degree:v1';

/** Claims a holder may choose to disclose or withhold. */
export const DEGREE_DISCLOSABLE_CLAIMS = ['student_id', 'name', 'degree', 'major', 'cgpa', 'graduation_date'];

export const CLAIM_LABELS = {
  student_id: 'Student ID',
  name: 'Full name',
  degree: 'Degree',
  major: 'Major',
  cgpa: 'CGPA',
  graduation_date: 'Graduation date',
};

/**
 * Builds the claim set for a degree credential (SD-JWT VC profile).
 * `status.blockcred` points at the on-chain revocation bitstring.
 */
export function buildDegreeClaims({
  issuerDid,
  issuerName,
  credentialId,
  holderJwk,
  statusIndex,
  chainId,
  revocationRegistry,
  subject,
  issuedAt,
  expiresAt,
}) {
  return {
    iss: issuerDid,
    iat: issuedAt,
    nbf: issuedAt,
    exp: expiresAt,
    vct: DEGREE_VCT,
    jti: `urn:uuid:${credentialId}`,
    issuer_name: issuerName,
    cnf: { jwk: holderJwk },
    status: { blockcred: { chain_id: chainId, registry: revocationRegistry, idx: statusIndex } },
    student_id: subject.student_id,
    name: subject.name,
    degree: subject.degree,
    major: subject.major || undefined,
    cgpa: subject.cgpa,
    graduation_date: subject.graduation_date,
  };
}
