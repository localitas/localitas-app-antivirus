package antivirus

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/localitas/localitas-go"
	"github.com/localitas/localitas-go/httputil"
)

type handler struct {
	app *App
}

func (h *handler) handleScan(w http.ResponseWriter, r *http.Request) {
	userID := client.UserIDFromRequest(r)

	r.ParseMultipartForm(100 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	tmpFile, err := os.CreateTemp("", "antivirus-scan-*"+filepath.Ext(header.Filename))
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "create temp file: %v", err)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	written, err := io.Copy(tmpFile, file)
	if err != nil {
		tmpFile.Close()
		writeErr(w, r, http.StatusInternalServerError, "write temp file: %v", err)
		return
	}
	tmpFile.Close()

	start := time.Now()
	scanFile, err := os.Open(tmpPath)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "open for scan: %v", err)
		return
	}

	clean, threatName, scanErr := h.app.Scanner.ScanStream(scanFile)
	scanFile.Close()
	duration := time.Since(start).Milliseconds()

	if scanErr != nil {
		writeErr(w, r, http.StatusInternalServerError, "scan failed: %v", scanErr)
		return
	}

	verdict := "clean"
	if !clean {
		verdict = "infected"
	}

	result, err := h.app.Store.RecordScan(r.Context(), userID, header.Filename, written, verdict, threatName, tmpPath, duration)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "record scan: %v", err)
		return
	}

	writeJSON(w, r, http.StatusOK, result)
}

func (h *handler) handleScanFolder(w http.ResponseWriter, r *http.Request) {
	userID := client.UserIDFromRequest(r)

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Path == "" {
		writeErr(w, r, http.StatusBadRequest, "path is required")
		return
	}

	info, err := os.Stat(req.Path)
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "path not accessible: %v", err)
		return
	}

	if info.IsDir() {
		results := h.scanDirectory(r, userID, req.Path)
		writeJSON(w, r, http.StatusOK, map[string]interface{}{
			"scanned": len(results),
			"results": results,
		})
		return
	}

	result := h.scanSingleFile(r, userID, req.Path, info.Size())
	if result == nil {
		writeErr(w, r, http.StatusInternalServerError, "scan failed")
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	userID := client.UserIDFromRequest(r)
	limit := intParam(r, "limit", 50)
	offset := intParam(r, "offset", 0)

	results, err := h.app.Store.ListHistory(r.Context(), userID, limit, offset)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "%v", err)
		return
	}
	if results == nil {
		results = make([]*ScanResult, 0)
	}
	writeJSON(w, r, http.StatusOK, results)
}

func (h *handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	userID := client.UserIDFromRequest(r)
	status := ClamdStatus{
		SocketPath: h.app.socketPath,
		Installed:  IsClamAVInstalled(),
	}

	if pong, err := h.app.Scanner.Ping(); err == nil {
		status.Running = true
		_ = pong
	}

	if ver, err := h.app.Scanner.Version(); err == nil {
		status.Version = ver
	}

	total, threats, clean := h.app.Store.GetStats(r.Context(), userID)
	status.TotalScans = total
	status.ThreatsFound = threats
	status.CleanFiles = clean

	writeJSON(w, r, http.StatusOK, status)
}

func (h *handler) scanSingleFile(r *http.Request, userID, filePath string, fileSize int64) *ScanResult {
	start := time.Now()
	clean, threatName, err := h.app.Scanner.ScanPath(filePath)
	duration := time.Since(start).Milliseconds()
	if err != nil {
		logger.Error("scan failed", "path", filePath, "error", err)
		return nil
	}

	verdict := "clean"
	if !clean {
		verdict = "infected"
	}

	result, err := h.app.Store.RecordScan(r.Context(), userID, filepath.Base(filePath), fileSize, verdict, threatName, filePath, duration)
	if err != nil {
		logger.Error("record scan failed", "path", filePath, "error", err)
		return nil
	}
	return result
}

func (h *handler) scanDirectory(r *http.Request, userID, dirPath string) []*ScanResult {
	var results []*ScanResult
	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if result := h.scanSingleFile(r, userID, path, info.Size()); result != nil {
			results = append(results, result)
		}
		return nil
	})
	if results == nil {
		results = make([]*ScanResult, 0)
	}
	return results
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v interface{}) {
	httputil.WriteResponse(w, r, status, v)
}

func writeErr(w http.ResponseWriter, r *http.Request, status int, format string, args ...interface{}) {
	httputil.WriteError(w, r, status, format, args...)
}

func intParam(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
