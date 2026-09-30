-- Preserve artifact metadata from new reports; historical rows stay unknown.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS package TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS installed_version TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fixed_version TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS image TEXT;
