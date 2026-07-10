package antivirus

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

func HandleCron(w http.ResponseWriter, r *http.Request) {
	dataDir := os.Getenv("LOCALITAS_DATA_DIR")
	if dataDir == "" {
		homeDir, _ := os.UserHomeDir()
		dataDir = filepath.Join(homeDir, ".localitas")
	}

	spec := map[string]interface{}{
		"jobs": []map[string]interface{}{
			{
				"id":                 "cron:antivirus:scan-folder",
				"path":               "/api/scan-folder",
				"method":             "POST",
				"schedule":           "0 2 * * *",
				"description":        "Scans all files in localitas data directory for threats",
				"execution_strategy": "all_nodes",
				"timeout":            "3600s",
				"body": map[string]interface{}{
					"path": dataDir,
				},
				"retry": map[string]interface{}{
					"max_attempts": 1,
				},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(spec)
}
