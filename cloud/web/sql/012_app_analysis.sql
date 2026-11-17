-- App-analysis jobs (SP-DECODE Arnes, fase 1). Durable progress in Postgres:
-- the QA worker state.json (12 h) is not enough for a human analysis.
-- No support-thread mirror: progress lives only in the analysis section.
CREATE TABLE IF NOT EXISTS spdecode_shop.app_analysis_jobs (
 job_id uuid PRIMARY KEY,
 account_id text NOT NULL REFERENCES shop_user(id) ON DELETE CASCADE,
 device_key_hash char(64) NOT NULL,
 upload_token_hash char(64) NOT NULL,
 filename varchar(120) NOT NULL,
 package_name text,
 app_name text,
 input_sha256 char(64) NOT NULL,
 input_bytes bigint NOT NULL CHECK(input_bytes>0),
 received_bytes bigint NOT NULL DEFAULT 0 CHECK(received_bytes>=0),
 chunk_bytes integer NOT NULL DEFAULT 2097152 CHECK(chunk_bytes>0),
 status varchar(24) NOT NULL DEFAULT 'UPLOADING' CHECK(status IN (
   'UPLOADING','UPLOADED','QUEUED_FOR_ANALYSIS','ANALYZING','AWAITING_HUMAN',
   'COMPLETED','COMPLETED_PARTIAL','FAILED','REJECTED','EXPIRED')),
 phase_code varchar(40),
 progress_percent smallint CHECK(progress_percent IS NULL OR (progress_percent>=0 AND progress_percent<=100)),
 credit_state varchar(12) NOT NULL DEFAULT 'held' CHECK(credit_state IN ('held','completed','released')),
 result_sha256 char(64),
 result_bytes bigint CHECK(result_bytes IS NULL OR result_bytes>0),
 needs_token boolean NOT NULL DEFAULT false,
 is_new_catalog_candidate boolean NOT NULL DEFAULT false,
 error_code varchar(40),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL DEFAULT (now()+interval '30 days')
);
CREATE INDEX IF NOT EXISTS app_analysis_owner
 ON spdecode_shop.app_analysis_jobs(account_id,created_at DESC);
CREATE INDEX IF NOT EXISTS app_analysis_queue
 ON spdecode_shop.app_analysis_jobs(status,created_at ASC)
 WHERE status IN ('QUEUED_FOR_ANALYSIS','ANALYZING');
CREATE INDEX IF NOT EXISTS app_analysis_active
 ON spdecode_shop.app_analysis_jobs(status) WHERE status='ANALYZING';

-- Append-only internal event log (cap 64 per job, like the QA worker).
-- The client renders ONE status card from the latest event; it never renders
-- this table as a list or timeline.
CREATE TABLE IF NOT EXISTS spdecode_shop.app_analysis_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 job_id uuid NOT NULL REFERENCES spdecode_shop.app_analysis_jobs(job_id) ON DELETE CASCADE,
 sequence integer NOT NULL CHECK(sequence>=1),
 code varchar(40) NOT NULL,
 status varchar(8) NOT NULL CHECK(status IN ('RUNNING','DONE','FAILED','PARTIAL')),
 detail_key varchar(80),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(job_id,sequence)
);
CREATE INDEX IF NOT EXISTS app_analysis_events_job
 ON spdecode_shop.app_analysis_events(job_id,sequence ASC);

-- Catalog candidates: a new method is delivered to the user AND saved at the
-- same time. Promotion to the public catalog is MANUAL (Ghost Developer), never automatic.
-- icon_ref is internal only: it never appears in a job view or a download.
CREATE TABLE IF NOT EXISTS spdecode_shop.app_analysis_catalog_candidates (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 job_id uuid NOT NULL REFERENCES spdecode_shop.app_analysis_jobs(job_id) ON DELETE CASCADE,
 provider_id text NOT NULL,
 icon_ref text,
 catalog_ref text,
 texts_ref text,
 dossier_ref text,
 status varchar(16) NOT NULL DEFAULT 'pending'
   CHECK(status IN ('pending','approved','rejected','published')),
 reviewed_by text,
 reviewed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_analysis_candidates_status
 ON spdecode_shop.app_analysis_catalog_candidates(status,created_at DESC);
CREATE INDEX IF NOT EXISTS app_analysis_candidates_job
 ON spdecode_shop.app_analysis_catalog_candidates(job_id);

-- Outbound webhook deliveries to Yamada (no polling). One row per attempt
-- batch; 'skipped' when no webhook URL is configured (never fails the job).
CREATE TABLE IF NOT EXISTS spdecode_shop.app_analysis_webhook_deliveries (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 job_id uuid NOT NULL REFERENCES spdecode_shop.app_analysis_jobs(job_id) ON DELETE CASCADE,
 event varchar(40) NOT NULL,
 status varchar(16) NOT NULL CHECK(status IN ('delivered','failed','pending','skipped')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 last_error text,
 next_retry_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_analysis_webhook_pending
 ON spdecode_shop.app_analysis_webhook_deliveries(status,next_retry_at)
 WHERE status IN ('pending','failed');

-- Credit reservations must expire: an abandoned upload used to hold 1 credit
-- forever. The sweeper releases 'held' reservations past expires_at, but only
-- when the job is not actively being analysed.
ALTER TABLE spdecode_shop.credit_reservations
 ADD COLUMN IF NOT EXISTS expires_at timestamptz;
CREATE INDEX IF NOT EXISTS credit_reservations_expiry
 ON spdecode_shop.credit_reservations(state,expires_at)
 WHERE state='held';
REVOKE ALL ON ALL TABLES IN SCHEMA spdecode_shop FROM PUBLIC;
