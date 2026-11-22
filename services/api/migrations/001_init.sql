-- BlockCred platform schema (v2: accounts + roles).

CREATE TABLE IF NOT EXISTS users (
  id            uuid PRIMARY KEY,
  email         text NOT NULL UNIQUE,              -- stored lower-case
  password_hash text NOT NULL,                     -- scrypt(auth secret); the raw password never reaches the server
  role          text NOT NULL CHECK (role IN ('admin', 'university', 'employer', 'student')),
  display_name  text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  disabled      boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);

-- Student wallet key: public part in clear, private part encrypted client-side.
CREATE TABLE IF NOT EXISTS student_keys (
  user_id           uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  holder_public_jwk jsonb NOT NULL,
  holder_thumbprint text NOT NULL UNIQUE,
  wrapped_key       jsonb NOT NULL
);

-- One issuer (did:web + keys + on-chain controller) per university account.
CREATE TABLE IF NOT EXISTS issuers (
  id                 uuid PRIMARY KEY,
  user_id            uuid NOT NULL UNIQUE REFERENCES users (id) ON DELETE CASCADE,
  slug               text NOT NULL UNIQUE,
  name               text NOT NULL,
  did                text NOT NULL UNIQUE,
  status             text NOT NULL CHECK (status IN ('pending', 'active', 'suspended', 'rejected')),
  keys_enc           text NOT NULL,                -- AES-256-GCM sealed JSON array of signing keys
  controller_address text NOT NULL,
  controller_key_enc text NOT NULL,                -- AES-256-GCM sealed Ethereum private key
  registered_tx      text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  approved_at        timestamptz
);

CREATE TABLE IF NOT EXISTS batches (
  id          uuid PRIMARY KEY,
  issuer_id   uuid NOT NULL REFERENCES issuers (id),
  merkle_root text NOT NULL,
  leaf_count  integer NOT NULL,
  tx_hash     text,
  status      text NOT NULL CHECK (status IN ('pending', 'anchored', 'failed')),
  error       text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  anchored_at timestamptz,
  UNIQUE (issuer_id, merkle_root)
);

-- University records. A record is signed into a credential once the student has an account.
CREATE TABLE IF NOT EXISTS credentials (
  id                uuid PRIMARY KEY,
  issuer_id         uuid NOT NULL REFERENCES issuers (id),
  student_email     text NOT NULL,
  student_user_id   uuid REFERENCES users (id) ON DELETE SET NULL,
  claims            jsonb NOT NULL,                -- the institution's own record (system of record)
  status            text NOT NULL CHECK (status IN ('awaiting_student', 'issued', 'revoked')),
  status_index      bigint,
  signing_kid       text,
  leaf              text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  issued_at         timestamptz,
  expires_at        timestamptz,
  batch_id          uuid REFERENCES batches (id),
  merkle_proof      jsonb,
  revoked_at        timestamptz,
  revocation_reason text,
  revocation_tx     text,
  UNIQUE (issuer_id, status_index)
);
CREATE INDEX IF NOT EXISTS credentials_email_idx ON credentials (student_email) WHERE status = 'awaiting_student';
CREATE INDEX IF NOT EXISTS credentials_unanchored_idx ON credentials (issuer_id, issued_at) WHERE batch_id IS NULL AND leaf IS NOT NULL;

-- The student's cloud wallet: signed SD-JWT VCs delivered to their account.
CREATE TABLE IF NOT EXISTS wallet_items (
  credential_id   uuid PRIMARY KEY REFERENCES credentials (id),
  student_user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  sd_jwt          text NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS wallet_items_student_idx ON wallet_items (student_user_id);

CREATE TABLE IF NOT EXISTS verification_requests (
  id               uuid PRIMARY KEY,
  employer_user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  student_email    text,                            -- NULL = open request answered via code
  student_user_id  uuid REFERENCES users (id) ON DELETE SET NULL,
  nonce            text NOT NULL UNIQUE,
  audience         text NOT NULL,
  purpose          text NOT NULL,
  requested_fields text[] NOT NULL,
  status           text NOT NULL CHECK (status IN ('pending', 'processing', 'completed', 'declined', 'failed')),
  verdict          text,
  result           jsonb,
  claims_purged    boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  completed_at     timestamptz
);
CREATE INDEX IF NOT EXISTS vr_student_email_idx ON verification_requests (student_email);
CREATE INDEX IF NOT EXISTS vr_employer_idx ON verification_requests (employer_user_id, created_at DESC);

-- DPDP consent log: field NAMES only, never values.
CREATE TABLE IF NOT EXISTS consent_log (
  id               bigserial PRIMARY KEY,
  at               timestamptz NOT NULL DEFAULT now(),
  request_id       uuid REFERENCES verification_requests (id) ON DELETE SET NULL,
  student_user_id  uuid REFERENCES users (id) ON DELETE SET NULL,
  employer_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
  employer_name    text,
  issuer_did       text,
  disclosed_fields text[] NOT NULL DEFAULT '{}',
  purpose          text NOT NULL,
  verdict          text NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id      bigserial PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  user_id uuid,
  action  text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);
