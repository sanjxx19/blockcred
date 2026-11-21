-- BlockCred issuer schema.
-- Data minimisation: the issued SD-JWT itself is NEVER stored; only its hash (Merkle leaf).
-- Offer claims are purged on redemption when PURGE_OFFER_CLAIMS=true.

CREATE TABLE IF NOT EXISTS issuer_offers (
  id            uuid PRIMARY KEY,
  code_hash     text NOT NULL UNIQUE,           -- sha256(offer code); the code itself is never stored
  subject_ref   text NOT NULL,                  -- institution's internal student id (for admin lookup)
  claims        jsonb,                          -- NULL once purged
  source        text NOT NULL DEFAULT 'admin',  -- admin | csv | digilocker-mock
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  redeemed_at   timestamptz,
  credential_id uuid
);
CREATE INDEX IF NOT EXISTS issuer_offers_subject_idx ON issuer_offers (subject_ref);

CREATE TABLE IF NOT EXISTS issuer_batches (
  id          uuid PRIMARY KEY,
  merkle_root text NOT NULL UNIQUE,
  leaf_count  integer NOT NULL,
  tx_hash     text,
  status      text NOT NULL CHECK (status IN ('pending', 'anchored', 'failed')),
  error       text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  anchored_at timestamptz
);

CREATE TABLE IF NOT EXISTS issuer_credentials (
  id                 uuid PRIMARY KEY,
  offer_id           uuid NOT NULL REFERENCES issuer_offers (id),
  subject_ref        text NOT NULL,
  status_index       bigint NOT NULL UNIQUE,
  holder_thumbprint  text NOT NULL,
  signing_kid        text NOT NULL,
  leaf               text,                      -- keccak256(issuer-signed JWT)
  issued_at          timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  batch_id           uuid REFERENCES issuer_batches (id),
  merkle_proof       jsonb,
  revoked_at         timestamptz,
  revocation_reason  text,
  revocation_tx      text
);
CREATE INDEX IF NOT EXISTS issuer_credentials_unanchored_idx ON issuer_credentials (issued_at) WHERE batch_id IS NULL AND leaf IS NOT NULL;
CREATE INDEX IF NOT EXISTS issuer_credentials_subject_idx ON issuer_credentials (subject_ref);

CREATE TABLE IF NOT EXISTS issuer_audit_log (
  id      bigserial PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  actor   text NOT NULL,
  action  text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);
