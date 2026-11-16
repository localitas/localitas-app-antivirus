package antivirus

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The API doc names exactly the routes the app serves: every documented
// endpoint is routed, and every /api route is documented.
func TestAPIDoc_MatchesTheRoutes(t *testing.T) {
	_, mux := newTestApp(t)

	documented := map[string]bool{}
	for _, e := range AntivirusAPIDoc.Endpoints {
		documented[e.Method+" "+e.Path] = true
		_, pattern := mux.Handler(httptest.NewRequest(e.Method, e.Path, nil))
		if pattern != e.Method+" "+e.Path {
			t.Errorf("documented %s %s is not routed (matched %q)", e.Method, e.Path, pattern)
		}
	}

	for _, route := range []string{"POST /api/scan-file", "POST /api/scan-folder", "GET /api/history", "GET /api/status"} {
		method, path, _ := strings.Cut(route, " ")
		if _, pattern := mux.Handler(httptest.NewRequest(method, path, nil)); pattern != route {
			t.Fatalf("%s is not routed (matched %q)", route, pattern)
		}
		if !documented[route] {
			t.Errorf("%s is routed but not documented", route)
		}
	}

	if _, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, "/api/scan", nil)); pattern != "" {
		t.Errorf("/api/scan is routed after all (%q)", pattern)
	}
}
