package antivirus

import (
	"net/http"
	"os"
	"path/filepath"

	client "github.com/localitas/localitas-go"
)

// HandleCron serves the nightly scan of the Localitas data directory, minus
// what churns or holds no user files.
func HandleCron(w http.ResponseWriter, r *http.Request) {
	dataDir := os.Getenv("LOCALITAS_DATA_DIR")
	if dataDir == "" {
		homeDir, _ := os.UserHomeDir()
		dataDir = filepath.Join(homeDir, ".localitas")
	}

	client.CronSpec{Jobs: []client.CronJob{{
		ID:                "cron:antivirus:scan-folder",
		Path:              "/api/scan-folder",
		Method:            "POST",
		Schedule:          "0 2 * * *",
		Description:       "Scans all files in localitas data directory for threats",
		ExecutionStrategy: "all_nodes",
		Timeout:           "3600s",
		Body: client.JSONBody(ScanFolderRequest{
			Path:    dataDir,
			Exclude: []string{"raft", "bleve-indices", "logs", "*.sqlitedb", "*.sqlitedb-wal", "*.sqlitedb-shm", "*.log"},
		}),
		Retry: &client.CronRetry{MaxAttempts: 1},
	}}}.ServeHTTP(w, r)
}
