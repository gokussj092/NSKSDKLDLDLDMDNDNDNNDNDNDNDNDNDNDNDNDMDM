-- Administrative events never enter the public SP-DECODE notice feed.
CREATE TABLE IF NOT EXISTS spdecode_shop.admin_notices (
 id uuid NOT NULL,
 recipient_id text NOT NULL CHECK(recipient_id='owner' OR recipient_id ~ '^[0-9a-f-]{36}$'),
 kind text NOT NULL CHECK(kind IN ('support_message','support_escalation')),
 thread_id uuid REFERENCES spdecode_shop.support_threads(id) ON DELETE CASCADE,
 created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours',
 read_at timestamptz,
 PRIMARY KEY(recipient_id,id)
);
CREATE TABLE IF NOT EXISTS spdecode_shop.admin_push_devices (
 token_digest char(64) PRIMARY KEY,
 recipient_id text NOT NULL CHECK(recipient_id='owner' OR recipient_id ~ '^[0-9a-f-]{36}$'),
 token_ciphertext text NOT NULL CHECK(length(token_ciphertext) BETWEEN 60 AND 2048),
 seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS admin_notice_recipient ON spdecode_shop.admin_notices(recipient_id,created_at DESC);
CREATE INDEX IF NOT EXISTS admin_push_recipient ON spdecode_shop.admin_push_devices(recipient_id,seen_at DESC);
-- Only display metadata changes; encrypted message bodies remain intact.
UPDATE spdecode_shop.support_messages SET agent_name='Ghost Developer' WHERE agent_role='owner';
REVOKE ALL ON spdecode_shop.admin_notices,spdecode_shop.admin_push_devices FROM PUBLIC;
