-- Support sender identity snapshots. Keep historical messages intact.
-- Per-agent roles can be introduced later without changing the wire contract.
ALTER TABLE spdecode_shop.support_messages
 ADD COLUMN IF NOT EXISTS agent_id varchar(128),
 ADD COLUMN IF NOT EXISTS agent_name varchar(80),
 ADD COLUMN IF NOT EXISTS agent_role varchar(24);
CREATE INDEX IF NOT EXISTS support_agent_history
 ON spdecode_shop.support_messages(agent_id,created_at DESC)
 WHERE sender_kind='admin';
