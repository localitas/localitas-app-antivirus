package antivirus

import (
	"encoding/json"
	"net/http"
)

type APIEndpoint struct {
	Method      string     `json:"method"`
	Path        string     `json:"path"`
	Summary     string     `json:"summary"`
	QueryParams []APIParam `json:"query_params,omitempty"`
	RequestBody *APIBody   `json:"request_body,omitempty"`
	Response    *APIBody   `json:"response,omitempty"`
}

type APIParam struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type APIBody struct {
	ContentType string `json:"content_type"`
	Example     string `json:"example"`
}

type APIDoc struct {
	AppName     string        `json:"app_name"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	Keywords    []string      `json:"keywords,omitempty"`
	Endpoints   []APIEndpoint `json:"endpoints"`
}

var AntivirusAPIDoc = APIDoc{
	AppName:     "Antivirus",
	Version:     "1.0.0",
	Description: "ClamAV-powered file scanner. Scans uploaded files, and core's nightly job scans the Localitas data directory.",
	Keywords:    []string{"antivirus", "scan", "malware", "virus", "threat", "security", "clamav", "infected"},
	Endpoints: []APIEndpoint{
		{Method: "POST", Path: "/api/scan-file", Summary: "Upload and scan a file (needs write scope)", RequestBody: &APIBody{ContentType: "multipart/form-data", Example: `file: <binary>`}, Response: &APIBody{ContentType: "application/json", Example: `{"id":"abc","user_id":"u1","filename":"doc.pdf","file_size":2048,"verdict":"clean","duration_ms":120,"scanned_at":"2026-05-02T10:00:00Z"}`}},
		{Method: "POST", Path: "/api/scan-folder", Summary: "Scan a host directory (core's nightly job only)", RequestBody: &APIBody{ContentType: "application/json", Example: `{"path":"/Users/me/.localitas","exclude":["raft","*.log"]}`}, Response: &APIBody{ContentType: "application/json", Example: `{"scanned":15,"results":[{"id":"abc","filename":"report.pdf","verdict":"clean"}]}`}},
		{Method: "GET", Path: "/api/history", Summary: "Get scan history", QueryParams: []APIParam{{Name: "limit", Type: "integer", Required: false, Description: "Max results (default 50)"}, {Name: "offset", Type: "integer", Required: false, Description: "Pagination offset"}}, Response: &APIBody{ContentType: "application/json", Example: `[{"id":"abc","filename":"doc.pdf","verdict":"clean","scanned_at":"2026-05-02T10:00:00Z"}]`}},
		{Method: "GET", Path: "/api/status", Summary: "Get ClamAV status and scan statistics", Response: &APIBody{ContentType: "application/json", Example: `{"running":true,"version":"ClamAV 1.4.0","total_scans":42,"threats_found":1,"clean_files":41}`}},
	},
}

func HandleSwagger(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AntivirusAPIDoc)
}
