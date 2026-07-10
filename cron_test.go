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
			ID       string      `json:"id"`
			Path     string      `json:"path"`
			Method   string      `json:"method"`
			Schedule string      `json:"schedule"`
			Body     interface{} `json:"body"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(spec.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(spec.Jobs))
	}

	job := spec.Jobs[0]
	if job.ID != "cron:antivirus:local-scan" {
		t.Errorf("expected id cron:antivirus:local-scan, got %s", job.ID)
	}
	if job.Path != "/api/scan-local" {
		t.Errorf("expected path /api/scan-local, got %s", job.Path)
	}
	if job.Schedule != "0 2 * * *" {
		t.Errorf("expected schedule 0 2 * * *, got %s", job.Schedule)
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

func TestHandleCron_DailySchedule(t *testing.T) {
	req := httptest.NewRequest("GET", "/cron.json", nil)
	w := httptest.NewRecorder()
	HandleCron(w, req)

	var spec struct {
		Jobs []struct {
			Schedule string `json:"schedule"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if spec.Jobs[0].Schedule != "0 2 * * *" {
		t.Errorf("expected daily schedule 0 2 * * *, got %s", spec.Jobs[0].Schedule)
	}
}

func TestHandleCron_LongTimeout(t *testing.T) {
	req := httptest.NewRequest("GET", "/cron.json", nil)
	w := httptest.NewRecorder()
	HandleCron(w, req)

	var spec struct {
		Jobs []struct {
			Timeout string `json:"timeout"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if spec.Jobs[0].Timeout != "3600s" {
		t.Errorf("expected timeout 3600s, got %s", spec.Jobs[0].Timeout)
	}
}
