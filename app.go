package antivirus

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/localitas/localitas-go"
)

var logger = slog.Default().With("component", "antivirus")

//go:embed templates/*.html
var TemplatesFS embed.FS

//go:embed docs/help.md
var helpMarkdown []byte

const DatabaseName = "antivirus"

type App struct {
	Store      *Store
	Scanner    *Scanner
	BasePath   string
	CoreURL    string
	AuthToken  string
	client     *client.Client
	socketPath string
}

func New(c *client.Client, basePath string, socketPath string) *App {
	if basePath == "" {
		basePath = "/"
	}
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}
	return &App{
		BasePath:   basePath,
		client:     c,
		socketPath: socketPath,
		Scanner:    NewScanner(socketPath),
	}
}

func (a *App) Install(ctx context.Context) (string, error) {
	if err := a.ensureClamAV(); err != nil {
		logger.Warn("ClamAV setup issue", "error", err)
		logger.Warn("scanning will be unavailable until ClamAV is installed and clamd is running")
	}

	for attempt := 1; ; attempt++ {
		db, err := a.client.CreateSystemDatabase(ctx, DatabaseName)
		if err != nil {
			logger.Warn("install attempt failed", "attempt", attempt, "error", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if err := applyEmbeddedMigrations(ctx, a.client, db.ID); err != nil {
			logger.Warn("install migrations attempt failed", "attempt", attempt, "error", err)
			time.Sleep(2 * time.Second)
			continue
		}
		return db.ID, nil
	}
}

func (a *App) InitStore(coreURL, dbID, token string) error {
	store, err := OpenStore(coreURL, dbID, token)
	if err != nil {
		return err
	}
	a.Store = store
	return nil
}

func (a *App) ensureClamAV() error {
	if IsClamdRunning(a.socketPath) {
		logger.Info("clamd is running", "socket", a.socketPath)
		return nil
	}

	if !IsClamAVInstalled() {
		if err := InstallClamAV(); err != nil {
			return fmt.Errorf("clamd not reachable at %s and auto-install failed: %w", a.socketPath, err)
		}
	}

	if err := EnsureClamdConf(a.socketPath); err != nil {
		return err
	}

	EnsureFreshclam()

	if err := StartClamd(); err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		time.Sleep(time.Second)
		if IsClamdRunning(a.socketPath) {
			logger.Info("clamd is ready")
			return nil
		}
	}
	return fmt.Errorf("clamd did not start within 30 seconds")
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(TemplatesFS, "templates/index.html")
	if err != nil {
		logger.Error("index template error", "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"BasePath": a.BasePath,
	})
}

func (a *App) RegisterRoutes(mux *http.ServeMux) {
	h := &handler{app: a}
	mux.HandleFunc("GET /{$}", a.handleIndex)
	mux.HandleFunc("POST /api/scan", h.handleScan)
	mux.HandleFunc("GET /api/history", h.handleHistory)
	mux.HandleFunc("GET /api/status", h.handleStatus)
	mux.HandleFunc("POST /api/scan-managed", h.handleScanManaged)
	mux.HandleFunc("POST /api/scan-managed-all", h.handleScanManagedAll)
	mux.HandleFunc("GET /swagger.json", HandleSwagger)
	mux.HandleFunc("GET /help.md", handleHelpMarkdown)
}

func handleHelpMarkdown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/markdown")
	w.Write(helpMarkdown)
}
