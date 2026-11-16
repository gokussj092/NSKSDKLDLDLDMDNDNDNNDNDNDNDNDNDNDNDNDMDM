-- Support anti-spam suspensions (one row per suspension; a suspension only
-- blocks creating threads and sending messages, never the rest of the account).
-- The active suspension is the row with lifted_at IS NULL and
-- suspended_until in the future; expired rows stay for audit/prior counts.
CREATE TABLE IF NOT EXISTS spdecode_shop.support_suspensions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 reason text NOT NULL,
 suspended_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 lifted_at timestamptz,
 lifted_by text
);
CREATE INDEX IF NOT EXISTS support_suspensions_account
 ON spdecode_shop.support_suspensions(account_id, suspended_until);
