-- Support read receipts (one row per actor per thread) + agent avatar snapshots.
-- Read state is per actor: the user reads as their account id, staff as their own id
-- (the owner id is a 64-hex digest, hence reader_id is text, not uuid).
CREATE TABLE IF NOT EXISTS spdecode_shop.support_thread_reads (
 thread_id uuid NOT NULL REFERENCES spdecode_shop.support_threads(id) ON DELETE CASCADE,
 reader_kind varchar(12) NOT NULL CHECK(reader_kind IN ('user','staff')),
 reader_id text NOT NULL CHECK(length(reader_id) BETWEEN 1 AND 128),
 read_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(thread_id,reader_kind,reader_id)
);
CREATE INDEX IF NOT EXISTS support_reads_by_reader
 ON spdecode_shop.support_thread_reads(reader_kind,reader_id,read_at DESC);
-- Agent avatar snapshot per admin message, same pattern as agent_name/agent_role
-- (historical messages keep the avatar the agent had when replying).
ALTER TABLE spdecode_shop.support_messages
 ADD COLUMN IF NOT EXISTS agent_avatar text;
-- Staff avatar (data-URI JPEG, same validation as profiles.avatar_data).
ALTER TABLE spdecode_shop.staff_accounts
 ADD COLUMN IF NOT EXISTS avatar text;
