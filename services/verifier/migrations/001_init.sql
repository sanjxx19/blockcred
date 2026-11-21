-- BlockCred verifier schema.
-- Purpose limitation: disclosed claim values are kept only for RESULT_RETENTION_SEC
-- (so the relying-party UI can display them), then purged. The consent log keeps
-- only field NAMES, never values.

CREATE TABLE IF NOT EXISTS verifier_requests (
  id               uuid PRIMARY KEY,
  nonce            text NOT NULL UNIQUE,
  poll_token_hash  text NOT NULL,
  audience         text NOT NULL,
  purpose          text NOT NULL,
  requested_fields text[] NOT NULL DEFAULT '{}',
  status           text NOT NULL CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
  verdict          text,
  result           jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  completed_at     timestamptz,
  claims_purged    boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS verifier_requests_purge_idx ON verifier_requests (completed_at) WHERE claims_purged = false;

CREATE TABLE IF NOT EXISTS verifier_consent_log (
  id                bigserial PRIMARY KEY,
  at                timestamptz NOT NULL DEFAULT now(),
  request_id        uuid REFERENCES verifier_requests (id),
  holder_thumbprint text,
  issuer_did        text,
  disclosed_fields  text[] NOT NULL DEFAULT '{}',
  purpose           text NOT NULL,
  verdict           text NOT NULL
);
