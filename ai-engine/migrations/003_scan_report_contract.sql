ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS required_reports JSONB;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS pipeline_commit TEXT;
CREATE TABLE IF NOT EXISTS scan_reports (
    scan_run_id INT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    finding_count INT NOT NULL,
    coverage TEXT NOT NULL DEFAULT 'analyzed',
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_run_id, tool)
);
