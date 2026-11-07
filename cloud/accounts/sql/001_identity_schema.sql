-- F7-A1-P02: DDL REVIEW CANDIDATE ONLY. DO NOT APPLY TO PRODUCTION.
-- VPS PostgreSQL transaction database; Supabase is optional ENCRYPTED BACKUP,
-- not an auth read-replica. No exposed API or public roles.
-- Requires PostgreSQL 15+ and pgcrypto for gen_random_uuid on older releases.
BEGIN;
CREATE SCHEMA IF NOT EXISTS spdecode_accounts;
REVOKE ALL ON SCHEMA spdecode_accounts FROM PUBLIC;

CREATE TABLE IF NOT EXISTS spdecode_accounts.accounts (
  account_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_canonical text,
  email_verified_at timestamptz,
  username text,
  display_name text NOT NULL,
  password_hash text,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  privacy_version text,
  terms_version text,
  CONSTRAINT email_canonical_shape CHECK (
    email_canonical IS NULL OR
    (length(email_canonical) <= 254 AND email_canonical = lower(email_canonical)
     AND email_canonical LIKE '%@%.%')
  ),
  CONSTRAINT username_shape CHECK (
    username IS NULL OR username ~ '^[a-z][a-z0-9_]{2,23}$'
  ),
  CONSTRAINT display_name_bounds CHECK (length(display_name) BETWEEN 1 AND 160),
  CONSTRAINT password_hash_version CHECK (
    password_hash IS NULL OR password_hash ~
    '^scrypt[$]32768[$]8[$]2[$][0-9a-f]{48}[$][0-9a-f]{128}$'
  ),
  CONSTRAINT password_requires_verified_email CHECK (
    password_hash IS NULL OR (email_canonical IS NOT NULL AND email_verified_at IS NOT NULL)
  ),
  CONSTRAINT account_status CHECK (status IN ('active','suspended','deletion_requested','deleted'))
);
CREATE UNIQUE INDEX IF NOT EXISTS account_email_unique
 ON spdecode_accounts.accounts (email_canonical)
 WHERE email_canonical IS NOT NULL AND status <> 'deleted';
CREATE UNIQUE INDEX IF NOT EXISTS account_username_unique
 ON spdecode_accounts.accounts (username)
 WHERE username IS NOT NULL AND status <> 'deleted';

CREATE TABLE IF NOT EXISTS spdecode_accounts.identities (
  identity_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES spdecode_accounts.accounts(account_id) ON DELETE RESTRICT,
  provider text NOT NULL CHECK (provider IN ('google','password')),
  provider_subject text NOT NULL,
  linked_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider,provider_subject),
  UNIQUE (account_id,provider)
);
-- Never silently link Google accounts to password identities solely by email.

CREATE TABLE IF NOT EXISTS spdecode_accounts.registration_challenges (
  challenge_id text PRIMARY KEY CHECK (challenge_id ~ '^[0-9a-f]{32}$'),
  email_canonical text NOT NULL,
  requested_username text NOT NULL
    CHECK (requested_username ~ '^[a-z][a-z0-9_]{2,23}$'),
  requested_display_name text NOT NULL,
  code_hmac_sha256 text NOT NULL CHECK (code_hmac_sha256 ~ '^[0-9a-f]{64}$'),
  attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  continuation_sha256 text CHECK (
    continuation_sha256 IS NULL OR continuation_sha256 ~ '^[0-9a-f]{64}$'
  ),
  continuation_expires_at timestamptz,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT continuation_only_after_verification CHECK (
    continuation_sha256 IS NULL OR verified_at IS NOT NULL
  ),
  CONSTRAINT continuation_pair CHECK (
    (continuation_sha256 IS NULL AND continuation_expires_at IS NULL) OR
    (continuation_sha256 IS NOT NULL AND continuation_expires_at IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS registration_expiry_idx
 ON spdecode_accounts.registration_challenges (expires_at);
CREATE INDEX IF NOT EXISTS registration_email_idx
 ON spdecode_accounts.registration_challenges (email_canonical);

CREATE TABLE IF NOT EXISTS spdecode_accounts.account_sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES spdecode_accounts.accounts(account_id) ON DELETE CASCADE,
  session_digest text NOT NULL UNIQUE CHECK (session_digest ~ '^[0-9a-f]{64}$'),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  last_seen_at timestamptz
);
CREATE INDEX IF NOT EXISTS account_sessions_owner_idx
 ON spdecode_accounts.account_sessions (account_id,expires_at);

CREATE TABLE IF NOT EXISTS spdecode_accounts.security_events (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id uuid REFERENCES spdecode_accounts.accounts(account_id) ON DELETE SET NULL,
  event_type text NOT NULL CHECK (event_type IN (
     'email_verified','password_set','password_changed','password_reset_requested',
     'password_reset_completed','login_success','login_failed','new_device',
     'identity_linked','session_revoked','account_suspended','email_changed',
     'account_deletion_requested')),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  notification_state text NOT NULL DEFAULT 'pending'
   CHECK (notification_state IN ('pending','queued','sent','failed','suppressed')),
  correlation_id uuid NOT NULL DEFAULT gen_random_uuid()
);
CREATE INDEX IF NOT EXISTS security_event_owner_idx
 ON spdecode_accounts.security_events(account_id,occurred_at DESC);

REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_accounts FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA spdecode_accounts FROM PUBLIC;
COMMIT;

-- EXECUTION GATE: application role grants, audit, backup, test database and
-- rolling migration must be reviewed before this SQL is applied to a VPS.
-- No credit/billing tables are added in F7-A1; that belongs to F7-A3.
