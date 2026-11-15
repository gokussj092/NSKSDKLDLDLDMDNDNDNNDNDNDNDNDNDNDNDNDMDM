-- Owner-defined staff roles. No custom role may grant owner-only secrets
-- or staff management, even when an administrator modifies its permissions.
CREATE TABLE IF NOT EXISTS spdecode_shop.staff_custom_roles (
 code varchar(16) PRIMARY KEY
  CHECK(code ~ '^x_[a-z][a-z0-9_]{1,12}$'),
 name varchar(72) NOT NULL CHECK(length(btrim(name)) BETWEEN 3 AND 72),
 permissions text[] NOT NULL DEFAULT '{}'::text[]
  CHECK(permissions <@ ARRAY[
   'users.read','support.read','support.write','support.assign','billing.read'
  ]::text[]),
 enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE spdecode_shop.staff_accounts
 DROP CONSTRAINT IF EXISTS staff_accounts_role_check;
ALTER TABLE spdecode_shop.staff_accounts
 ADD CONSTRAINT staff_accounts_role_check CHECK(
 role IN ('admin','support','moderator','billing')
 OR role ~ '^x_[a-z][a-z0-9_]{1,12}$');
CREATE INDEX IF NOT EXISTS staff_custom_roles_enabled
 ON spdecode_shop.staff_custom_roles(enabled,updated_at DESC);
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
