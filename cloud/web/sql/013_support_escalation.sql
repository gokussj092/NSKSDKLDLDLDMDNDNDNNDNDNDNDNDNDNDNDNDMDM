-- Support escalation to the owner (Ghost Developer): when the assigned agent cannot solve
-- a user's problem, the thread is marked escalated, raised to high priority,
-- and listed for the owner. Escalation is one-way: there is no un-escalate;
-- the owner resolves the thread normally (reply/close).
ALTER TABLE spdecode_shop.support_threads
 ADD COLUMN IF NOT EXISTS escalated_at timestamptz,
 ADD COLUMN IF NOT EXISTS escalated_by text;
CREATE INDEX IF NOT EXISTS support_escalated_recent
 ON spdecode_shop.support_threads(escalated_at DESC) WHERE escalated_at IS NOT NULL;
