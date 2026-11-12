-- Additive migration for existing SP-DECODE commerce databases.
-- Run on the VPS only after the server code for ads-free is deployed.
-- No product is enabled by this migration.
BEGIN;
ALTER TABLE spdecode_shop.products DROP CONSTRAINT IF EXISTS products_id_check;
ALTER TABLE spdecode_shop.products ADD CONSTRAINT products_id_check
  CHECK(id IN ('offline-3','api-ip','analysis-credits','ads-free'));
INSERT INTO spdecode_shop.products(id,settings) VALUES
 ('ads-free','{"id":"ads-free","enabled":false,"prices":{"USD":100},"days":30,"termPrices":{}}')
 ON CONFLICT DO NOTHING;
COMMIT;
