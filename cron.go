package antivirus

import (
	"encoding/json"
	"net/http"
)

func HandleCron(w http.ResponseWriter, r *http.Request) {
	spec := map[string]interface{}{
		"jobs": []map[string]interface{}{
			{
				"id":          "cron:antivirus:managed-scan",
				"path":        "/api/scan-managed-all",
				"method":      "POST",
				"schedule":    "0 2 * * *",
				"description": "Scans all files in managed filesystem for threats",
				"timeout":     "600s",
				"retry": map[string]interface{}{
					"max_attempts": 1,
				},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(spec)
}
