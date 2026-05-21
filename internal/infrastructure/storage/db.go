// Package storage — db.go provides SQLite-backed persistent storage for BBPTS
// scans, targets, and discovered vulnerabilities.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database and provides CRUD methods.
type DB struct {
	conn *sql.DB
}

// Open creates or opens a BBPTS database at the given path.
func Open(dbPath string) (*DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// Configure for concurrent access: 10 max open connections, 5 idle, 5s busy timeout
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA cache_size=-64000;`); err != nil {
		return nil, fmt.Errorf("failed to configure sqlite pragmas: %w", err)
	}

	instance := &DB{conn: db}
	if err := instance.migrate(context.Background()); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return instance, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate creates the schema and records the migration version.
func (db *DB) migrate(ctx context.Context) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);`,
		`
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scope TEXT NOT NULL,
		start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		end_time TIMESTAMP,
		status TEXT
	);

	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		is_new BOOLEAN,
		FOREIGN KEY(scan_id) REFERENCES scans(id)
	);

	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		target TEXT NOT NULL,
		source TEXT NOT NULL,
		type TEXT NOT NULL,
		properties TEXT, -- JSON
		FOREIGN KEY(scan_id) REFERENCES scans(id)
	);

	CREATE TABLE IF NOT EXISTS insights (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		priority TEXT,
		score INTEGER,
		tags TEXT, -- JSON
		FOREIGN KEY(scan_id) REFERENCES scans(id)
	);

	CREATE INDEX IF NOT EXISTS idx_scans_scope ON scans(scope);
	CREATE INDEX IF NOT EXISTS idx_events_target ON events(target);
	CREATE INDEX IF NOT EXISTS idx_events_scan_target ON events(scan_id, target);
	CREATE INDEX IF NOT EXISTS idx_targets_host ON targets(host);
	CREATE INDEX IF NOT EXISTS idx_targets_scan_host ON targets(scan_id, host);
	`,
	}
	for version, migration := range migrations {
		if _, err := db.conn.ExecContext(ctx, migration); err != nil {
			return err
		}
		if _, err := db.conn.ExecContext(ctx, `INSERT OR IGNORE INTO schema_version (version) VALUES (?)`, version+1); err != nil {
			return err
		}
	}
	return nil
}

// StartScan creates a new scan record and returns its ID.
func (db *DB) StartScan(ctx context.Context, scope string) (int64, error) {
	res, err := db.conn.ExecContext(ctx, "INSERT INTO scans (scope, status) VALUES (?, ?)", scope, "running")
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScan updates a scan record as completed.
func (db *DB) FinishScan(ctx context.Context, scanID int64) error {
	_, err := db.conn.ExecContext(ctx, "UPDATE scans SET end_time = CURRENT_TIMESTAMP, status = ? WHERE id = ?", "completed", scanID)
	return err
}

// SaveTargets bulk inserts target records.
func (db *DB) SaveTargets(ctx context.Context, scanID int64, targets []string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, "INSERT INTO targets (scan_id, host) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, t := range targets {
		if _, err := stmt.ExecContext(ctx, scanID, t); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// EventRecord maps to the database event structure.
type EventRecord struct {
	Target     string
	Source     string
	Type       string
	Properties map[string]string
}

// SaveEvents bulk inserts event records.
func (db *DB) SaveEvents(ctx context.Context, scanID int64, events []EventRecord) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, "INSERT INTO events (scan_id, target, source, type, properties) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ev := range events {
		propsJSON, _ := json.Marshal(ev.Properties)
		if _, err := stmt.ExecContext(ctx, scanID, ev.Target, ev.Source, ev.Type, string(propsJSON)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ScanRecord represents a scan in the database.
type ScanRecord struct {
	ID        int64      `json:"id"`
	Scope     string     `json:"scope"`
	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Status    string     `json:"status"`
}

// GetScans returns all scans from the database.
func (db *DB) GetScans(ctx context.Context) ([]ScanRecord, error) {
	rows, err := db.conn.QueryContext(ctx, "SELECT id, scope, start_time, end_time, status FROM scans ORDER BY start_time DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanRecord
	for rows.Next() {
		var s ScanRecord
		if err := rows.Scan(&s.ID, &s.Scope, &s.StartTime, &s.EndTime, &s.Status); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, nil
}

// GetTargets returns all targets for a given scan.
func (db *DB) GetTargets(ctx context.Context, scanID int64) ([]string, error) {
	rows, err := db.conn.QueryContext(ctx, "SELECT host FROM targets WHERE scan_id = ?", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// GetEvents returns all events for a given scan.
func (db *DB) GetEvents(ctx context.Context, scanID int64) ([]EventRecord, error) {
	rows, err := db.conn.QueryContext(ctx, "SELECT target, source, type, properties FROM events WHERE scan_id = ?", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []EventRecord
	for rows.Next() {
		var ev EventRecord
		var propsJSON string
		if err := rows.Scan(&ev.Target, &ev.Source, &ev.Type, &propsJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(propsJSON), &ev.Properties); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, nil
}

// GetLastScanID returns the ID of the most recent completed scan for a scope.
func (db *DB) GetLastScanID(ctx context.Context, scope string) (int64, error) {
	var id int64
	err := db.conn.QueryRowContext(ctx, "SELECT id FROM scans WHERE scope = ? AND status = 'completed' ORDER BY start_time DESC LIMIT 1", scope).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// ScanDiff represents the difference between two scans.
type ScanDiff struct {
	NewTargets []string
	NewEvents  []EventRecord
}

// GetScanDiff compares two scans and returns the differences.
func (db *DB) GetScanDiff(ctx context.Context, scope string, currentScanID int64) (*ScanDiff, error) {
	lastID, err := db.GetLastScanID(ctx, scope)
	if err != nil {
		return nil, err
	}
	if lastID == 0 {
		return nil, nil // No previous scan to diff against
	}

	diff := &ScanDiff{}

	// Find new targets
	rows, err := db.conn.QueryContext(ctx, `
		SELECT t1.host
		FROM targets t1
		LEFT JOIN targets t2 ON t2.host = t1.host AND t2.scan_id = ?
		WHERE t1.scan_id = ? AND t2.host IS NULL`,
		lastID, currentScanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err == nil {
				diff.NewTargets = append(diff.NewTargets, h)
			}
		}
	}

	// Find new events
	newEvents, err := db.GetNewFindings(ctx, scope, currentScanID)
	if err == nil {
		diff.NewEvents = newEvents
	}

	return diff, nil
}

// GetNewFindings returns events from a scan that were not present in the previous scan.
func (db *DB) GetNewFindings(ctx context.Context, scope string, scanID int64) ([]EventRecord, error) {
	lastID, err := db.GetLastScanID(ctx, scope)
	if err != nil || lastID == 0 {
		return nil, nil
	}

	query := `
		SELECT e1.target, e1.source, e1.type, e1.properties
		FROM events e1
		LEFT JOIN events e2 ON e2.target = e1.target AND e2.scan_id = ?
		WHERE e1.scan_id = ? AND e2.target IS NULL
	`
	rows, err := db.conn.QueryContext(ctx, query, lastID, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []EventRecord
	for rows.Next() {
		var ev EventRecord
		var propsJSON string
		if err := rows.Scan(&ev.Target, &ev.Source, &ev.Type, &propsJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(propsJSON), &ev.Properties); err != nil {
			return nil, err
		}
		findings = append(findings, ev)
	}

	return findings, nil
}

// Stats represents aggregate system statistics for the dashboard.
type Stats struct {
	TotalScans    int `json:"total_scans"`
	TotalTargets  int `json:"total_targets"`
	TotalEvents   int `json:"total_events"`
	CriticalVulns int `json:"critical_vulns"`
}

// GetStats computes aggregate statistics from the database.
func (db *DB) GetStats(ctx context.Context) (Stats, error) {
	var stats Stats

	err := db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM scans").Scan(&stats.TotalScans)
	if err != nil {
		return stats, err
	}

	err = db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM targets").Scan(&stats.TotalTargets)
	if err != nil {
		return stats, err
	}

	err = db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&stats.TotalEvents)
	if err != nil {
		return stats, err
	}

	err = db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM insights WHERE priority = 'critical'").Scan(&stats.CriticalVulns)
	if err != nil {
		// insights table might be empty, ignore error and set to 0
		stats.CriticalVulns = 0
	}

	return stats, nil
}
