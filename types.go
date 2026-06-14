package antivirus

import "time"

type ScanResult struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Filename    string    `json:"filename"`
	FileSize    int64     `json:"file_size"`
	Verdict     string    `json:"verdict"`
	ThreatName  string    `json:"threat_name,omitempty"`
	StoragePath string    `json:"storage_path,omitempty"`
	Duration    int64     `json:"duration_ms"`
	ScannedAt   time.Time `json:"scanned_at"`
}

type ClamdStatus struct {
	Running      bool   `json:"running"`
	Version      string `json:"version,omitempty"`
	DatabaseAge  string `json:"database_age,omitempty"`
	SocketPath   string `json:"socket_path"`
	Installed    bool   `json:"installed"`
	TotalScans   int    `json:"total_scans"`
	ThreatsFound int    `json:"threats_found"`
	CleanFiles   int    `json:"clean_files"`
}
