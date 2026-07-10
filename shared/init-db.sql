-- SecureGuard tables
-- postgres already connected to 'secureguard' db (set by POSTGRES_DB env)
-- DO NOT use \connect or CREATE DATABASE here

CREATE TABLE IF NOT EXISTS scan_runs (
    id              SERIAL PRIMARY KEY,
    repo_url        TEXT NOT NULL,
    commit_sha      TEXT NOT NULL,
    branch          TEXT NOT NULL,
    triggered_by    TEXT DEFAULT 'push',
    status          TEXT DEFAULT 'pending',
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    total_findings  INT DEFAULT 0,
    critical_count  INT DEFAULT 0,
    high_count      INT DEFAULT 0,
    medium_count    INT DEFAULT 0,
    low_count       INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id              SERIAL PRIMARY KEY,
    scan_run_id     INT REFERENCES scan_runs(id) ON DELETE CASCADE,
    scanner         TEXT NOT NULL,
    rule_id         TEXT,
    cve_id          TEXT,
    cwe_id          TEXT,
    severity        TEXT,
    cvss_score      NUMERIC(4,1),
    title           TEXT NOT NULL,
    description     TEXT,
    file_path       TEXT,
    line_start      INT,
    line_end        INT,
    vulnerable_code TEXT,
    fix_status      TEXT DEFAULT 'open',
    ai_fix_code     TEXT,
    pr_url          TEXT,
    pr_confidence   NUMERIC(4,3),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_feed (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    severity        TEXT,
    cvss_score      NUMERIC(4,1),
    cvss_vector     TEXT,
    cwe_ids         TEXT[],
    affected_pkgs   JSONB,
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,
    sources         TEXT[],
    is_kev          BOOLEAN DEFAULT FALSE,
    fetched_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id              SERIAL PRIMARY KEY,
    alert_type      TEXT NOT NULL,
    severity        TEXT,
    title           TEXT NOT NULL,
    body            TEXT,
    related_cve     TEXT,
    related_scan_id INT,
    notified        BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_cve      ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_severity      ON cve_feed(severity);
CREATE INDEX IF NOT EXISTS idx_cve_kev           ON cve_feed(is_kev);
CREATE INDEX IF NOT EXISTS idx_alerts_notified   ON alerts(notified);

-- Gitea needs its own database
-- Grant sgadmin full access to it
CREATE DATABASE gitea OWNER sgadmin;
