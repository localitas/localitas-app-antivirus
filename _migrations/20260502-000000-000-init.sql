CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    verdict TEXT NOT NULL,
    threat_name TEXT NOT NULL DEFAULT '',
    storage_path TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    scanned_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_results_user ON scan_results(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_scanned ON scan_results(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_verdict ON scan_results(verdict);
