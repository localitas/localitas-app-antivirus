package antivirus

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func OpenStore(coreURL, dbID, token string) (*Store, error) {
	dsn := fmt.Sprintf("%s?database_id=%s&token=%s", coreURL, dbID, token)
	db, err := sql.Open("localitas", dsn)
	if err != nil {
		return nil, err
	}
	return NewStore(db), nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) RecordScan(ctx context.Context, userID, filename string, fileSize int64, verdict, threatName, storagePath string, durationMs int64) (*ScanResult, error) {
	id := newID()
	now := time.Now().UTC().Unix()
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO scan_results (id, user_id, filename, file_size, verdict, threat_name, storage_path, duration_ms, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		id, userID, filename, fileSize, verdict, threatName, storagePath, durationMs, now)
	if err != nil {
		return nil, err
	}
	return &ScanResult{
		ID: id, UserID: userID, Filename: filename, FileSize: fileSize,
		Verdict: verdict, ThreatName: threatName, StoragePath: storagePath,
		Duration: durationMs, ScannedAt: time.Unix(now, 0),
	}, nil
}

func (s *Store) ListHistory(ctx context.Context, userID string, limit, offset int) ([]*ScanResult, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, user_id, filename, file_size, verdict, threat_name, storage_path, duration_ms, scanned_at FROM scan_results WHERE user_id = ? ORDER BY scanned_at DESC LIMIT ? OFFSET ?",
		userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ScanResult
	for rows.Next() {
		var r ScanResult
		var scannedAt int64
		if err := rows.Scan(&r.ID, &r.UserID, &r.Filename, &r.FileSize, &r.Verdict, &r.ThreatName, &r.StoragePath, &r.Duration, &scannedAt); err != nil {
			return nil, err
		}
		r.ScannedAt = time.Unix(scannedAt, 0)
		out = append(out, &r)
	}
	return out, nil
}

func (s *Store) GetStats(ctx context.Context, userID string) (total, threats, clean int) {
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_results WHERE user_id = ?", userID).Scan(&total)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_results WHERE user_id = ? AND verdict = 'infected'", userID).Scan(&threats)
	clean = total - threats
	return
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
