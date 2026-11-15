package antivirus

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	client "github.com/localitas/localitas-go"
)

func strictDecode(t *testing.T, data []byte, into any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

// The nightly job is a typed cron.json job whose body is exactly the
// request the scan-folder handler reads: the data directory, minus what
// must not be scanned.
func TestHandleCron_TheNightlyScanJob(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("LOCALITAS_DATA_DIR", dataDir)

	rec := httptest.NewRecorder()
	HandleCron(rec, httptest.NewRequest("GET", "/cron.json", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("cron.json: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	var spec client.CronSpec
	strictDecode(t, rec.Body.Bytes(), &spec)
	if len(spec.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(spec.Jobs))
	}
	job := spec.Jobs[0]
	if job.ID != "cron:antivirus:scan-folder" || job.Path != "/api/scan-folder" || job.Method != "POST" ||
		job.Schedule != "0 2 * * *" || job.ExecutionStrategy != "all_nodes" || job.Timeout != "3600s" {
		t.Fatalf("job %+v", job)
	}
	if job.Retry == nil || job.Retry.MaxAttempts != 1 {
		t.Fatalf("a nightly scan is not retried: retry %+v", job.Retry)
	}

	var req ScanFolderRequest
	strictDecode(t, job.Body, &req)
	if req.Path != dataDir {
		t.Fatalf("job scans %q, want the data directory %q", req.Path, dataDir)
	}
	for _, skip := range []string{"raft", "bleve-indices", "logs", "*.sqlitedb", "*.sqlitedb-wal", "*.sqlitedb-shm", "*.log"} {
		if !contains(req.Exclude, skip) {
			t.Errorf("job does not exclude %q: %v", skip, req.Exclude)
		}
	}
}

// Without LOCALITAS_DATA_DIR the job scans ~/.localitas.
func TestHandleCron_DefaultsToTheHomeDataDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LOCALITAS_DATA_DIR", "")
	t.Setenv("HOME", home)

	rec := httptest.NewRecorder()
	HandleCron(rec, httptest.NewRequest("GET", "/cron.json", nil))
	var spec client.CronSpec
	strictDecode(t, rec.Body.Bytes(), &spec)
	var req ScanFolderRequest
	strictDecode(t, spec.Jobs[0].Body, &req)
	if want := filepath.Join(home, ".localitas"); req.Path != want {
		t.Fatalf("job scans %q, want %q", req.Path, want)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
