package antivirus

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleCron(t *testing.T) {
	req := httptest.NewRequest("GET", "/cron.json", nil)
	w := httptest.NewRecorder()
	HandleCron(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var spec struct {
		Jobs []struct {
			ID                string      `json:"id"`
			Path              string      `json:"path"`
			Method            string      `json:"method"`
			Schedule          string      `json:"schedule"`
			ExecutionStrategy string      `json:"execution_strategy"`
			Body              interface{} `json:"body"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(spec.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(spec.Jobs))
	}

	job := spec.Jobs[0]
	if job.ID != "cron:antivirus:scan-folder" {
		t.Errorf("expected id cron:antivirus:scan-folder, got %s", job.ID)
	}
	if job.Path != "/api/scan-folder" {
		t.Errorf("expected path /api/scan-folder, got %s", job.Path)
	}
	if job.Schedule != "0 2 * * *" {
		t.Errorf("expected schedule 0 2 * * *, got %s", job.Schedule)
	}
	if job.ExecutionStrategy != "all_nodes" {
		t.Errorf("expected execution_strategy all_nodes, got %s", job.ExecutionStrategy)
	}
	if job.Body == nil {
		t.Error("expected body with path field")
	}
}

func TestHandleCron_ContentType(t *testing.T) {
	req := httptest.NewRequest("GET", "/cron.json", nil)
	w := httptest.NewRecorder()
	HandleCron(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
}
