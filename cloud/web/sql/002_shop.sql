-- Applied only by the reviewed commerce migration command. Better Auth creates
-- its pinned shop_user/session/identity/verification/rate-limit models first.
CREATE SCHEMA IF NOT EXISTS spdecode_shop;
REVOKE ALL ON SCHEMA spdecode_shop FROM PUBLIC;
CREATE TABLE IF NOT EXISTS spdecode_shop.profiles (
 account_id text PRIMARY KEY REFERENCES shop_user(id) ON DELETE CASCADE,
 username text NOT NULL UNIQUE CHECK(username ~ '^[a-z][a-z0-9_]{2,23}$'),
 handle_changed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE spdecode_shop.profiles ADD COLUMN IF NOT EXISTS bio text NOT NULL DEFAULT '';
ALTER TABLE spdecode_shop.profiles ADD COLUMN IF NOT EXISTS avatar_data text;
CREATE TABLE IF NOT EXISTS spdecode_shop.reserved_handles (
 username text PRIMARY KEY, account_id text NOT NULL, reserved_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS spdecode_shop.products (
 id text PRIMARY KEY CHECK(id IN ('offline-3','api-ip')), settings jsonb NOT NULL,
 version integer NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO spdecode_shop.products(id,settings) VALUES
 ('offline-3','{"id":"offline-3","enabled":false,"prices":{"USD":499},"maxDevices":3,"quota":null,"days":null}'),
 ('api-ip','{"id":"api-ip","enabled":false,"prices":{},"maxDevices":null,"quota":1000,"days":30}')
 ON CONFLICT DO NOTHING;
-- Approved retail examples in USD, new only; never overwrite administrator edits.
-- 30 days per commercial month; API and Offline sales remain independently gated.
UPDATE spdecode_shop.products SET
 settings=jsonb_set(settings,'{termPrices}',
 '{"1m":{"USD":299},"2m":{"USD":549},"3m":{"USD":749},"6m":{"USD":1299},"12m":{"USD":2199}}'::jsonb,true),
 version=version+1,updated_at=now()
 WHERE id='offline-3' AND NOT (settings ? 'termPrices');
UPDATE spdecode_shop.products SET
 settings=jsonb_set(settings,'{termPrices}',
 '{"1m":{"USD":599},"2m":{"USD":1099},"3m":{"USD":1549},"6m":{"USD":2799},"12m":{"USD":4999}}'::jsonb,true),
 version=version+1,updated_at=now()
 WHERE id='api-ip' AND NOT (settings ? 'termPrices');
-- Add the optional analysis-credit product without modifying existing prices.
ALTER TABLE spdecode_shop.products DROP CONSTRAINT IF EXISTS products_id_check;
ALTER TABLE spdecode_shop.products ADD CONSTRAINT products_id_check
 CHECK(id IN ('offline-3','api-ip','analysis-credits'));
INSERT INTO spdecode_shop.products(id,settings) VALUES
 ('analysis-credits','{"id":"analysis-credits","enabled":false,"prices":{},"bundles":{"1c":{"USD":399},"5c":{"USD":1795},"10c":{"USD":3290},"25c":{"USD":7475},"50c":{"USD":13450},"100c":{"USD":23900}}}')
 ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS spdecode_shop.settings (
 id text PRIMARY KEY, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO spdecode_shop.settings(id,value) VALUES ('tax-rules','[]') ON CONFLICT DO NOTHING;
INSERT INTO spdecode_shop.settings(id,value) VALUES
 ('cleanup-policy','{"enabled":false,"retentionHours":168,"requested":false,"lastRunAt":null,"lastResult":null}')
 ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS spdecode_shop.orders (
 id uuid PRIMARY KEY, account_id text NOT NULL, product_id text NOT NULL,
 product_snapshot jsonb NOT NULL, quote jsonb NOT NULL, provider text NOT NULL,
 provider_id text, checkout_url text, checkout_lock_until timestamptz, idempotency_key uuid NOT NULL,
 request_digest text NOT NULL, allowed_ip text, status text NOT NULL DEFAULT 'created'
 CHECK(status IN ('created','pending','paid','refunded','disputed','failed')),
 paid_at timestamptz, refunded_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(account_id,idempotency_key), UNIQUE(provider,provider_id)
);
CREATE INDEX IF NOT EXISTS shop_orders_owner ON spdecode_shop.orders(account_id,created_at DESC);
CREATE TABLE IF NOT EXISTS spdecode_shop.events (
 provider text NOT NULL, event_id text NOT NULL, order_id uuid NOT NULL REFERENCES spdecode_shop.orders(id),
 type text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(provider,event_id)
);
CREATE TABLE IF NOT EXISTS spdecode_shop.entitlements (
 id uuid PRIMARY KEY, order_id uuid NOT NULL UNIQUE REFERENCES spdecode_shop.orders(id),
 account_id text NOT NULL, product_id text NOT NULL,
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
 token_digest text UNIQUE, token_prefix text, allowed_ip text,
 quota integer, days integer, expires_at timestamptz, claimed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shop_entitlements_owner ON spdecode_shop.entitlements(account_id);
-- Additive for installations that ran the staged schema before mode binding.
ALTER TABLE spdecode_shop.orders ADD COLUMN IF NOT EXISTS payment_live boolean NOT NULL DEFAULT false;
ALTER TABLE spdecode_shop.entitlements ADD COLUMN IF NOT EXISTS payment_live boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS spdecode_shop.usage (
 entitlement_id uuid REFERENCES spdecode_shop.entitlements(id), period date NOT NULL,
 accepted integer NOT NULL DEFAULT 0 CHECK(accepted>=0), PRIMARY KEY(entitlement_id,period)
);
CREATE TABLE IF NOT EXISTS spdecode_shop.audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, actor_id text NOT NULL,
 action text NOT NULL, resource_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS spdecode_shop.usage_reservations (
 id uuid PRIMARY KEY, entitlement_id uuid NOT NULL REFERENCES spdecode_shop.entitlements(id),
 period date NOT NULL, state text NOT NULL CHECK(state IN ('held','completed','released')),
 created_at timestamptz NOT NULL DEFAULT now()
);
-- Immutable credit movements: grants/reversals come only from verified payment
-- events. Debits are recorded only after successful eligible analyses.
CREATE TABLE IF NOT EXISTS spdecode_shop.credit_ledger (
 id uuid PRIMARY KEY,account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 order_id uuid REFERENCES spdecode_shop.orders(id),job_id uuid,
 movement_kind text NOT NULL CHECK(movement_kind IN ('grant','refund','spend')),
 delta integer NOT NULL CHECK(delta<>0 AND abs(delta)<=1000),
 payment_live boolean NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(order_id,movement_kind),UNIQUE(job_id,movement_kind)
);
CREATE INDEX IF NOT EXISTS credit_ledger_account ON spdecode_shop.credit_ledger(account_id,payment_live,created_at DESC);
CREATE TABLE IF NOT EXISTS spdecode_shop.credit_reservations (
 id uuid PRIMARY KEY,account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 job_id uuid NOT NULL UNIQUE,payment_live boolean NOT NULL,
 state text NOT NULL CHECK(state IN ('held','completed','released')),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS credit_reserved_account ON spdecode_shop.credit_reservations(account_id,payment_live,state);
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
