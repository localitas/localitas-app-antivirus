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
			ID       string `json:"id"`
			Path     string `json:"path"`
			Method   string `json:"method"`
			Schedule string `json:"schedule"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(w.Body).Decode(&spec); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(spec.Jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(spec.Jobs))
	}

	if spec.Jobs[0].ID != "cron:antivirus:managed-scan" {
		t.Errorf("expected id cron:antivirus:managed-scan, got %s", spec.Jobs[0].ID)
	}
	if spec.Jobs[0].Schedule != "0 2 * * *" {
		t.Errorf("expected schedule 0 2 * * *, got %s", spec.Jobs[0].Schedule)
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

	if spec.Jobs[0].Timeout != "600s" {
		t.Errorf("expected timeout 600s, got %s", spec.Jobs[0].Timeout)
	}
}
