-- Gift codes: entitlement authority remains exclusively in PostgreSQL.
-- Never store raw redemption codes or expose their digests to account clients.
CREATE TABLE IF NOT EXISTS spdecode_shop.gift_codes (
 id uuid PRIMARY KEY,
 code_digest char(64) NOT NULL UNIQUE,
 title varchar(80) NOT NULL,
 kind varchar(24) NOT NULL CHECK(kind IN ('credits','ads-free','offline-3')),
 credits integer,
 duration_days integer,
 max_uses integer NOT NULL CHECK(max_uses BETWEEN 1 AND 10000),
 used integer NOT NULL DEFAULT 0 CHECK(used>=0),
 enabled boolean NOT NULL DEFAULT true,
 expires_at timestamptz,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(used<=max_uses),
 CHECK((kind='credits' AND credits BETWEEN 1 AND 1000 AND duration_days IS NULL)
 OR (kind IN ('ads-free','offline-3') AND credits IS NULL
     AND duration_days BETWEEN 1 AND 3650))
);
CREATE INDEX IF NOT EXISTS gift_code_created ON spdecode_shop.gift_codes(created_at DESC);
CREATE TABLE IF NOT EXISTS spdecode_shop.gift_redemptions (
 id uuid PRIMARY KEY,
 gift_id uuid NOT NULL REFERENCES spdecode_shop.gift_codes(id),
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 order_id uuid NOT NULL UNIQUE REFERENCES spdecode_shop.orders(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(gift_id,account_id)
);
CREATE INDEX IF NOT EXISTS gift_redemptions_recent ON spdecode_shop.gift_redemptions(created_at DESC);
-- One bounded counter per authenticated account, no unbounded attack log.
CREATE TABLE IF NOT EXISTS spdecode_shop.gift_attempt_limits (
 account_id text PRIMARY KEY REFERENCES shop_user(id) ON DELETE CASCADE,
 window_start timestamptz NOT NULL DEFAULT now(),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0)
);
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
