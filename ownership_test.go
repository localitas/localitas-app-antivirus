package antivirus

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	client "github.com/localitas/localitas-go"
	_ "github.com/mattn/go-sqlite3"
)

const testAPIToken = "lt_test_cluster_token"

func TestMain(m *testing.M) {
	os.Setenv("LOCALITAS_API_TOKEN", testAPIToken)
	client.SetIdentityKeyFromAPIToken(testAPIToken)
	os.Exit(m.Run())
}

// identity signs claims as core does for a request it forwards to the app.
func identity(userID, permission string) string {
	raw, _ := json.Marshal(client.TokenInfo{UserID: userID, Email: userID + "@test.local", Permission: permission})
	payload := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte("localitas-internal-token-v1:" + testAPIToken))
	mac := hmac.New(sha256.New, []byte(base64.StdEncoding.EncodeToString(sum[:])))
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func newTestApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "antivirus.sqlitedb"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	migrations, _ := filepath.Glob("_migrations/*.sql")
	for _, m := range migrations {
		sqlText, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(sqlText)); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	app := New(client.New("http://127.0.0.1:1"), "/", filepath.Join(t.TempDir(), "no-clamd.sock"))
	app.Store = NewStore(db)
	mux := http.NewServeMux()
	app.RegisterRoutes(mux)
	return app, mux
}

func call(mux *http.ServeMux, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(`{"path":"/"}`))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestScans_BelongToTheirUser(t *testing.T) {
	app, mux := newTestApp(t)
	ctx := context.Background()
	if _, err := app.Store.RecordScan(ctx, "alice", "alice-tax.pdf", 10, "clean", "", "/tmp/a", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Store.RecordScan(ctx, SystemOwner, "nightly.bin", 10, "infected", "Eicar", "/data/x", 1); err != nil {
		t.Fatal(err)
	}

	bob := call(mux, "GET", "/api/history", identity("bob", "write"))
	if bob.Code != http.StatusOK || strings.Contains(bob.Body.String(), "alice-tax.pdf") || strings.Contains(bob.Body.String(), "nightly.bin") {
		t.Fatalf("bob's history: %d %s", bob.Code, bob.Body)
	}
	alice := call(mux, "GET", "/api/history", identity("alice", "write"))
	if !strings.Contains(alice.Body.String(), "alice-tax.pdf") || strings.Contains(alice.Body.String(), "nightly.bin") {
		t.Fatalf("alice's history: %d %s", alice.Code, alice.Body)
	}
	admin := call(mux, "GET", "/api/history", identity("root", "admin"))
	if !strings.Contains(admin.Body.String(), "nightly.bin") || strings.Contains(admin.Body.String(), "alice-tax.pdf") {
		t.Fatalf("an admin sees the nightly scans and only their own uploads: %s", admin.Body)
	}

	var status ClamdStatus
	json.NewDecoder(call(mux, "GET", "/api/status", identity("bob", "write")).Body).Decode(&status)
	if status.TotalScans != 0 || status.ThreatsFound != 0 {
		t.Fatalf("bob's stats count other users' scans: %+v", status)
	}
	json.NewDecoder(call(mux, "GET", "/api/status", identity("root", "admin")).Body).Decode(&status)
	if status.TotalScans != 1 || status.ThreatsFound != 1 {
		t.Fatalf("admin stats: %+v, want the nightly scan", status)
	}
}

func TestScans_RequireAVerifiedUser(t *testing.T) {
	_, mux := newTestApp(t)
	forged := base64.StdEncoding.EncodeToString([]byte(`{"user_id":"alice","permission":"admin"}`))
	for _, token := range []string{"", forged, identity("", "admin")} {
		for _, route := range []struct{ method, path string }{{"GET", "/api/history"}, {"GET", "/api/status"}, {"POST", "/api/scan-file"}} {
			if rec := call(mux, route.method, route.path, token); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with %q: %d, want 401", route.method, route.path, token, rec.Code)
			}
		}
	}
	if rec := call(mux, "POST", "/api/scan-file", identity("reader", "read")); rec.Code != http.StatusForbidden {
		t.Errorf("a read-only user uploads a scan: %d, want 403", rec.Code)
	}
}

// Walking a host directory is core's nightly job: a user, even an admin,
// cannot point it at any path on the machine.
func TestScanFolder_OnlyCore(t *testing.T) {
	_, mux := newTestApp(t)
	for _, token := range []string{"", identity("root", "admin"), "lt_someone_else"} {
		if rec := call(mux, "POST", "/api/scan-folder", token); rec.Code != http.StatusForbidden {
			t.Errorf("scan-folder with %q: %d, want 403", token, rec.Code)
		}
	}
	empty := t.TempDir()
	req := httptest.NewRequest("POST", "/api/scan-folder", strings.NewReader(`{"path":"`+empty+`"}`))
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"scanned":0`) {
		t.Fatalf("core's scan-folder: %d %s", rec.Code, rec.Body)
	}
}
