# DPDP Act 2023 compliance design

This maps BlockCred's design to the main obligations of India's **Digital Personal Data Protection Act, 2023** (DPDP) and the DPDP Rules. It describes the design and is not legal advice.

## Roles

| DPDP role | BlockCred actor |
|---|---|
| Data Principal | Student (holder) |
| Data Fiduciary | University (issuer) for issuance; Employer (verifier) for verification |
| Data Processor | Hosting / RPC providers acting for a fiduciary |

The public blockchain holds **no personal data**. It contains only:
- hashes of issuer DIDs;
- an opaque, randomly chosen revocation bit;
- Merkle roots of hashed credentials.

None of these identifies a student on its own.

## Consent (s.6)

- **Issuance:** accepting an offer in the wallet is an explicit, affirmative act. The student must hold the code and sign a proof of possession.
- **Sharing:**
  - Every presentation passes through a consent screen showing the verifier's identity, the stated **purpose** and the requested fields. The student can untick any field.
  - Every response (or decline) is recorded in `consent_log`: timestamp, student, employer, issuer DID, **field names only**, purpose, outcome. The student sees it as *Sharing history*.
- **Withdrawal:** consent is per presentation, so there is no standing permission to withdraw. Each new verification needs a new consent.

## Purpose limitation and data minimisation (s.4–s.8)

- Verifiers declare a purpose and request specific fields. The UI encourages asking only for what is needed.
- SD-JWT selective disclosure means the verifier cryptographically **cannot** see undisclosed fields (e.g. CGPA).
- Employer retention: disclosed values are deleted from `verification_requests.result` after `RESULT_RETENTION_HOURS` (default 30 days) by a background job. The verdict and the field-name log remain for accountability.
- Issuer side: the university keeps its own record (its system of record) plus a leaf hash. The signed credential lives in the student's wallet.
- Passwords are never transmitted. Student wallet keys are encrypted client-side.

## Accuracy (s.8(3))

Credentials come from the issuer's system of record and are signed. Corrections work by revoking the old credential on-chain and issuing a new offer.

## Security safeguards (s.8(5))

See [THREAT_MODEL.md](THREAT_MODEL.md): signature verification, holder binding, replay protection, rate limiting, hashed secrets, least-privilege roles and audit logs (`audit_log`).

## Rights of the Data Principal (s.11–s.14)

| Right | How it is served |
|---|---|
| Access / summary | The student dashboard shows every credential and the full sharing history |
| Correction | Revoke + re-issue (admin flow) |
| Erasure | Student: **Delete my account and wallet** removes the account, wallet key and wallet; consent-log rows are de-identified. Employer: automatic purge. University: see the tension below |
| Grievance redressal | Each fiduciary must publish a grievance contact; `audit_log` and `consent_log` provide the evidence trail |
| Nominee | Out of scope for the software (policy) |

## Open policy questions

1. **Erasure vs. record retention.** Universities have statutory duties to keep academic records, which conflicts with the right to erasure. BlockCred keeps the issuer's *own* records outside the credential system. The credential system stores only hashes and the subject reference needed for revocation. A real deployment needs a documented retention schedule.
2. **Immutable on-chain data.** A revocation bit and a Merkle root cannot be erased. We argue they are not personal data, because they cannot be linked to a person without the off-chain credential. This interpretation should be confirmed by counsel.
3. **Cross-border transfer.** Public-chain nodes are global. Since no personal data goes on-chain, transfer restrictions should not be triggered. Verifier and issuer databases should be hosted in permitted jurisdictions.
4. **Children's data (s.9).** Applies to under-18 learners (e.g. school certificates). Verifiable parental consent would be needed before issuance.
