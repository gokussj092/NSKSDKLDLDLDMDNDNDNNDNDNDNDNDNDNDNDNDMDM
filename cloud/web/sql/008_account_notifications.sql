-- Private account notifications: messages and FCM registrations are never public.
-- Device tokens are AES-GCM encrypted by the application before insertion.
CREATE TABLE IF NOT EXISTS spdecode_shop.account_push_devices (
 token_digest char(64) PRIMARY KEY,
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 token_ciphertext text NOT NULL CHECK (length(token_ciphertext) BETWEEN 60 AND 2048),
 created_at timestamptz NOT NULL DEFAULT now(),
 seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS account_push_owner
 ON spdecode_shop.account_push_devices(account_id,seen_at DESC);

CREATE TABLE IF NOT EXISTS spdecode_shop.account_notices (
 id uuid PRIMARY KEY,
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 event_key varchar(160) NOT NULL,
 kind varchar(16) NOT NULL CHECK(kind IN ('support','purchase','security','service')),
 resource_id text,
 title varchar(96) NOT NULL,
 body varchar(240) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 read_at timestamptz,
 UNIQUE(account_id,event_key)
);
CREATE INDEX IF NOT EXISTS account_notice_unread
 ON spdecode_shop.account_notices(account_id,created_at DESC);
-- Retain an auditable history of commercial transactions, but never store
-- bank details, Google tokens, message plaintext or Firebase registration IDs.
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
