-- Closed Play test detection (2026-11-17): first-seen install origin +
-- version per account, and one row per day with a successful decode.
-- The app reports installerPackage/versionName/versionCode with the decode
-- payload (see lib/commerce/play-testers.mjs); first-seen wins, never
-- overwritten. Active days reuse the streak's day (account time zone):
-- recordDecodeDay already decides which local day a decode counts for, and
-- withDecodeStreak passes that day here, so no new counter is invented.
-- Qualification is computed in the panel, never here: a tester "califica"
-- if installed from Play and used the app at least once inside the 14-day
-- window that starts on its first active day. Rewards stay MANUAL — this
-- schema grants nothing, stores no code and delivers nothing.
CREATE TABLE IF NOT EXISTS spdecode_shop.play_tester_first_seen (
 account_id text PRIMARY KEY REFERENCES shop_user(id) ON DELETE CASCADE,
 install_source text NOT NULL CHECK(install_source IN ('play','other','unknown')),
 installer_package text,
 version_name text,
 version_code integer CHECK(version_code IS NULL OR version_code>=0),
 device_key_hash text,
 first_seen_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS spdecode_shop.play_tester_days (
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 day date NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(account_id, day)
);
CREATE INDEX IF NOT EXISTS play_tester_days_day
 ON spdecode_shop.play_tester_days(day);
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
