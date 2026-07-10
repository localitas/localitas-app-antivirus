package antivirus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	storagePath := ""

	if clean {
		storagePath, err = h.moveToManaged(r, userID, tmpPath, header.Filename)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "move to managed: %v", err)
			return
		}
	} else {
		verdict = "infected"
	}

	result, err := h.app.Store.RecordScan(r.Context(), userID, header.Filename, written, verdict, threatName, storagePath, duration)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "record scan: %v", err)
		return
	}

	writeJSON(w, r, http.StatusOK, result)
}

func (h *handler) moveToManaged(r *http.Request, userID, tmpPath, filename string) (string, error) {
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return "", err
	}

	storagePath := fmt.Sprintf("downloads/%s/%s", userID, filename)
	dirURL := fmt.Sprintf("%s/apps/filesystem/webdav/managed/downloads/%s/", h.app.CoreURL, userID)

	httpClient := &http.Client{Timeout: 60 * time.Second}

	mkReq, _ := http.NewRequestWithContext(r.Context(), "MKCOL", dirURL, nil)
	if h.app.AuthToken != "" {
		mkReq.Header.Set("Authorization", "Bearer "+h.app.AuthToken)
	}
	mkResp, _ := httpClient.Do(mkReq)
	if mkResp != nil {
		mkResp.Body.Close()
	}

	webdavURL := fmt.Sprintf("%s/apps/filesystem/webdav/managed/%s", h.app.CoreURL, url.PathEscape(storagePath))
	putReq, err := http.NewRequestWithContext(r.Context(), "PUT", webdavURL, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if h.app.AuthToken != "" {
		putReq.Header.Set("Authorization", "Bearer "+h.app.AuthToken)
	}
	putReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpClient.Do(putReq)
	if err != nil {
		return "", fmt.Errorf("webdav put: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("webdav put %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	return storagePath, nil
}

func (h *handler) handleScanManaged(w http.ResponseWriter, r *http.Request) {
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

	webdavURL := fmt.Sprintf("%s/apps/filesystem/webdav/managed/%s", h.app.CoreURL, url.PathEscape(req.Path))
	getReq, err := http.NewRequestWithContext(r.Context(), "GET", webdavURL, nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "build request: %v", err)
		return
	}
	if h.app.AuthToken != "" {
		getReq.Header.Set("Authorization", "Bearer "+h.app.AuthToken)
	}

	httpClient := &http.Client{Timeout: 60 * time.Second}
	resp, err := httpClient.Do(getReq)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "fetch file: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		writeErr(w, r, http.StatusNotFound, "file not found: %s", req.Path)
		return
	}

	start := time.Now()
	clean, threatName, scanErr := h.app.Scanner.ScanStream(resp.Body)
	duration := time.Since(start).Milliseconds()

	if scanErr != nil {
		writeErr(w, r, http.StatusInternalServerError, "scan failed: %v", scanErr)
		return
	}

	verdict := "clean"
	if !clean {
		verdict = "infected"
	}

	filename := filepath.Base(req.Path)
	result, err := h.app.Store.RecordScan(r.Context(), userID, filename, resp.ContentLength, verdict, threatName, req.Path, duration)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "record: %v", err)
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

func (h *handler) handleScanManagedAll(w http.ResponseWriter, r *http.Request) {
	userID := client.UserIDFromRequest(r)

	listURL := fmt.Sprintf("%s/apps/filesystem/api/files?path_prefix=managed/&limit=10000", h.app.CoreURL)
	listReq, err := http.NewRequestWithContext(r.Context(), "GET", listURL, nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "build request: %v", err)
		return
	}
	if h.app.AuthToken != "" {
		listReq.Header.Set("Authorization", "Bearer "+h.app.AuthToken)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	listResp, err := httpClient.Do(listReq)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "list files: %v", err)
		return
	}
	defer listResp.Body.Close()

	var files []struct {
		Path string `json:"path"`
		Size int64  `json:"size"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&files); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "parse file list: %v", err)
		return
	}

	var results []*ScanResult
	for _, f := range files {
		webdavURL := fmt.Sprintf("%s/apps/filesystem/webdav/%s", h.app.CoreURL, f.Path)
		getReq, err := http.NewRequestWithContext(r.Context(), "GET", webdavURL, nil)
		if err != nil {
			continue
		}
		if h.app.AuthToken != "" {
			getReq.Header.Set("Authorization", "Bearer "+h.app.AuthToken)
		}

		resp, err := httpClient.Do(getReq)
		if err != nil {
			continue
		}

		start := time.Now()
		clean, threatName, scanErr := h.app.Scanner.ScanStream(resp.Body)
		resp.Body.Close()
		duration := time.Since(start).Milliseconds()

		if scanErr != nil {
			continue
		}

		verdict := "clean"
		if !clean {
			verdict = "infected"
		}

		filename := filepath.Base(f.Path)
		result, err := h.app.Store.RecordScan(r.Context(), userID, filename, f.Size, verdict, threatName, f.Path, duration)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	if results == nil {
		results = make([]*ScanResult, 0)
	}

	writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"scanned": len(results),
		"results": results,
	})
}

func (h *handler) handleScanLocal(w http.ResponseWriter, r *http.Request) {
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
