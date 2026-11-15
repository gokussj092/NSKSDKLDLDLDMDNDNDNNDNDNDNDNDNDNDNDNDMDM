-- Role-scoped staff identities; independent of the immutable VPS owner credentials.
CREATE TABLE IF NOT EXISTS spdecode_shop.staff_accounts (
 id uuid PRIMARY KEY,
 username varchar(48) NOT NULL UNIQUE CHECK(username ~ '^[a-z][a-z0-9._-]{2,47}$'),
 display_name varchar(80) NOT NULL CHECK(length(btrim(display_name)) BETWEEN 2 AND 80),
 role varchar(16) NOT NULL CHECK(role IN ('admin','support','moderator','billing')),
 password_hash text NOT NULL CHECK(length(password_hash) BETWEEN 64 AND 256),
 enabled boolean NOT NULL DEFAULT true,
 must_change_password boolean NOT NULL DEFAULT true,
 session_version integer NOT NULL DEFAULT 1 CHECK(session_version>0),
 last_login_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS staff_by_role ON spdecode_shop.staff_accounts(role,enabled);
CREATE TABLE IF NOT EXISTS spdecode_shop.staff_audit (
 id uuid PRIMARY KEY,
 actor_id text NOT NULL,
 actor_role varchar(16) NOT NULL,
 action varchar(48) NOT NULL,
 target_id text NOT NULL,
 details jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS staff_audit_recent ON spdecode_shop.staff_audit(created_at DESC);
ALTER TABLE spdecode_shop.support_threads
 ADD COLUMN IF NOT EXISTS assigned_staff_id uuid REFERENCES spdecode_shop.staff_accounts(id) ON DELETE SET NULL,
 ADD COLUMN IF NOT EXISTS priority varchar(12) NOT NULL DEFAULT 'normal'
 CHECK(priority IN ('low','normal','high')),
 ADD COLUMN IF NOT EXISTS updated_by text;
CREATE INDEX IF NOT EXISTS support_assigned_recent ON spdecode_shop.support_threads(assigned_staff_id,last_message_at DESC);
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
