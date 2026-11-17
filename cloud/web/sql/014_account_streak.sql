-- Decryption streak (racha de descifrado, 2026-11-16): one row per account,
-- keyed by account_id so the state survives reinstalling the app or changing
-- phones. Day = UTC calendar day; week = Monday to Sunday (UTC).
-- week_days[1..7] is Mon..Sun of week_start (the Monday of the current UTC
-- week). A day counts only when the account performs a successful file/text
-- decode while logged in (see lib/commerce/account-streak.mjs).
-- Chest: completing all 7 days of the current week grants exactly 1 analysis
-- credit. Idempotency is enforced twice: chest_open/chest_week on this row
-- (one chest per week) AND the credit_ledger UNIQUE(job_id, movement_kind)
-- on a deterministic job UUID derived from account + week (see the module),
-- so a retried grant can never double-spend.
CREATE TABLE IF NOT EXISTS spdecode_shop.account_streaks (
 account_id text PRIMARY KEY REFERENCES shop_user(id) ON DELETE CASCADE,
 current_streak integer NOT NULL DEFAULT 0 CHECK(current_streak>=0),
 last_active_date date,
 week_start date,
 week_days boolean[7] NOT NULL DEFAULT '{f,f,f,f,f,f,f}',
 chest_open boolean NOT NULL DEFAULT false,
 chest_week date,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(cardinality(week_days)=7),
 CHECK(chest_week IS NULL OR chest_open)
);
CREATE INDEX IF NOT EXISTS account_streaks_week
 ON spdecode_shop.account_streaks(week_start) WHERE chest_open;

-- Analysis result summary (op 30 history): the bot may report how many
-- servers/networks the delivered catalog contains. Optional, never charged.
ALTER TABLE spdecode_shop.app_analysis_jobs
 ADD COLUMN IF NOT EXISTS result_servers integer
   CHECK(result_servers IS NULL OR result_servers>=0),
 ADD COLUMN IF NOT EXISTS result_networks integer
   CHECK(result_networks IS NULL OR result_networks>=0);
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
