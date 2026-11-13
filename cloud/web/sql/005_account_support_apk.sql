-- Account-bound support inbox. Messages are encrypted before persistence.
CREATE TABLE IF NOT EXISTS spdecode_shop.support_threads (
 id uuid PRIMARY KEY,
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 subject varchar(100) NOT NULL,
 category varchar(20) NOT NULL CHECK(category IN ('technical','apk','payments','account','other')),
 status varchar(16) NOT NULL DEFAULT 'open' CHECK(status IN ('open','answered','closed')),
 last_message_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS support_account_recent
 ON spdecode_shop.support_threads(account_id,last_message_at DESC);
CREATE TABLE IF NOT EXISTS spdecode_shop.support_messages (
 id uuid PRIMARY KEY,
 thread_id uuid NOT NULL REFERENCES spdecode_shop.support_threads(id) ON DELETE CASCADE,
 sender_kind varchar(8) NOT NULL CHECK(sender_kind IN ('user','admin')),
 ciphertext text NOT NULL CHECK(length(ciphertext) BETWEEN 24 AND 16384),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS support_messages_thread
 ON spdecode_shop.support_messages(thread_id,created_at ASC,id ASC);
CREATE TABLE IF NOT EXISTS spdecode_shop.support_limits (
 account_id text PRIMARY KEY REFERENCES shop_user(id) ON DELETE CASCADE,
 window_start timestamptz NOT NULL DEFAULT now(),
 messages integer NOT NULL DEFAULT 0 CHECK(messages>=0)
);
-- APK QA authorization is never derived from local Android preferences.
CREATE TABLE IF NOT EXISTS spdecode_shop.apk_qa_jobs (
 job_id uuid PRIMARY KEY,
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 device_key_hash char(64) NOT NULL,
 payment_live boolean NOT NULL,
 state varchar(12) NOT NULL DEFAULT 'held' CHECK(state IN ('held','completed','released')),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS apk_qa_owner ON spdecode_shop.apk_qa_jobs(account_id,created_at DESC);
-- Device-bound cryptographic step-up for highly sensitive operations.
CREATE TABLE IF NOT EXISTS spdecode_shop.account_device_keys (
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 key_id uuid NOT NULL,
 public_key text NOT NULL CHECK(length(public_key) BETWEEN 140 AND 2048),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(account_id,key_id), UNIQUE(key_id)
);
CREATE TABLE IF NOT EXISTS spdecode_shop.account_challenges (
 id uuid PRIMARY KEY,
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 key_id uuid REFERENCES spdecode_shop.account_device_keys(key_id),
 purpose varchar(20) NOT NULL CHECK(purpose IN ('delete-account')),
 challenge_digest char(64) NOT NULL,
 expires_at timestamptz NOT NULL,
 used_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS account_challenges_user ON spdecode_shop.account_challenges(account_id,created_at DESC);
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
