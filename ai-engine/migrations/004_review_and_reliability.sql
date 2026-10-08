-- Preserve scanner records/severity; decisions are separate, versioned evidence.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_status TEXT NOT NULL DEFAULT 'unverified';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_owner TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_evidence TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_details JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS review_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_findings_review_status ON findings(review_status);
CREATE TABLE IF NOT EXISTS finding_reviews (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    evidence TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(finding_id, version)
);
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS ai_task_id TEXT;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS ai_task_status TEXT;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS ai_task_updated_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_key ON alerts(event_key);
-- Existing alerts remain unchanged; future keyed deliveries are idempotent.
