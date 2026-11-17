-- Server-owned local calendar and rolling seven-day reward blocks.
-- Existing totals, legacy weekly flags and credit ledger entries are preserved.
ALTER TABLE spdecode_shop.account_streaks
 ADD COLUMN IF NOT EXISTS time_zone text,
 ADD COLUMN IF NOT EXISTS last_counted_at timestamptz,
 ADD COLUMN IF NOT EXISTS reward_progress smallint CHECK(reward_progress BETWEEN 0 AND 7),
 ADD COLUMN IF NOT EXISTS reward_cycle_start date,
 ADD COLUMN IF NOT EXISTS reward_claim_id uuid,
 ADD COLUMN IF NOT EXISTS reward_claim_date date;
UPDATE spdecode_shop.account_streaks SET last_counted_at=updated_at
 WHERE last_counted_at IS NULL AND last_active_date IS NOT NULL;
