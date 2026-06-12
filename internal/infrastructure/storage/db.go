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

// Open creates or opens a BBPTS database at the given path.
func Open(dbPath string) (*Storage, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// Configure for concurrent access: 1 max open connection to avoid SQLite database locks, 1 idle, 5s busy timeout
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA cache_size=-64000;`); err != nil {
		return nil, fmt.Errorf("failed to configure sqlite pragmas: %w", err)
	}

	instance := &Storage{db: db, dbType: "sqlite3"}
	if err := instance.migrate(context.Background()); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return instance, nil
}

// migrate creates the schema and records the migration version.
func (db *Storage) migrate(ctx context.Context) error {
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
		`
	CREATE TABLE IF NOT EXISTS teams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS owners (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS asset_ownership (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id TEXT NOT NULL,
		owner_id INTEGER,
		team_id INTEGER,
		start_time TIMESTAMP NOT NULL,
		end_time TIMESTAMP,
		FOREIGN KEY(owner_id) REFERENCES owners(id),
		FOREIGN KEY(team_id) REFERENCES teams(id)
	);

	CREATE TABLE IF NOT EXISTS sla_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		duration_days INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS finding_assignments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		finding_id INTEGER NOT NULL,
		team_id INTEGER,
		owner_id INTEGER,
		status TEXT NOT NULL,
		assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		due_at TIMESTAMP NOT NULL,
		resolved_at TIMESTAMP,
		FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE,
		FOREIGN KEY(team_id) REFERENCES teams(id),
		FOREIGN KEY(owner_id) REFERENCES owners(id)
	);

	CREATE TABLE IF NOT EXISTS escalation_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		policy_id INTEGER NOT NULL,
		delay_days INTEGER NOT NULL,
		action_type TEXT NOT NULL,
		properties TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(policy_id) REFERENCES sla_policies(id) ON DELETE CASCADE
	);
	`,
		`
	CREATE TABLE IF NOT EXISTS finding_status_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		finding_id INTEGER NOT NULL,
		old_status TEXT NOT NULL,
		new_status TEXT NOT NULL,
		changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		comment TEXT,
		changed_by TEXT,
		FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
	);
	`,
		`
	CREATE TABLE IF NOT EXISTS setup_tokens (
		token TEXT PRIMARY KEY,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`,
		`
	CREATE TABLE IF NOT EXISTS evidence (
		id TEXT PRIMARY KEY,
		asset_id TEXT NOT NULL,
		source TEXT NOT NULL,
		confidence REAL DEFAULT 1.0,
		collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		raw_data BLOB,
		hash TEXT NOT NULL
	);
	`,
	}
	for version, migration := range migrations {
		if _, err := db.db.ExecContext(ctx, migration); err != nil {
			return err
		}
		if _, err := db.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_version (version) VALUES (?)`, version+1); err != nil {
			return err
		}
	}
	_, _ = db.db.ExecContext(ctx, "ALTER TABLE asset_ownership ADD COLUMN change_reason TEXT")
	return nil
}

// StartScan creates a new scan record and returns its ID.
func (db *Storage) StartScan(ctx context.Context, scope string) (int64, error) {
	res, err := db.db.ExecContext(ctx, "INSERT INTO scans (scope, status) VALUES (?, ?)", scope, "running")
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScan updates a scan record as completed.
func (db *Storage) FinishScan(ctx context.Context, scanID int64) error {
	_, err := db.db.ExecContext(ctx, "UPDATE scans SET end_time = CURRENT_TIMESTAMP, status = ? WHERE id = ?", "completed", scanID)
	return err
}

// SaveTargets bulk inserts target records.
func (db *Storage) SaveTargets(ctx context.Context, scanID int64, targets []string) error {
	tx, err := db.db.Begin()
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
func (db *Storage) SaveEvents(ctx context.Context, scanID int64, events []EventRecord) error {
	tx, err := db.db.Begin()
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

// GetScans returns scans from the database with pagination.
func (db *Storage) GetScans(ctx context.Context, limit, offset int) ([]ScanRecord, error) {
	query := "SELECT id, scope, start_time, end_time, status FROM scans ORDER BY start_time DESC, id DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else {
		query += " LIMIT 100"
	}
	rows, err := db.db.QueryContext(ctx, query)
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

// GetTargets returns targets for a given scan with pagination.
func (db *Storage) GetTargets(ctx context.Context, scanID int64, limit, offset int) ([]string, error) {
	query := "SELECT host FROM targets WHERE scan_id = ? ORDER BY id"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, scanID)
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

// GetEvents returns events for a given scan with pagination.
func (db *Storage) GetEvents(ctx context.Context, scanID int64, limit, offset int) ([]EventRecord, error) {
	query := "SELECT target, source, type, properties FROM events WHERE scan_id = ?"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, scanID)
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
func (db *Storage) GetLastScanID(ctx context.Context, scope string) (int64, error) {
	var id int64
	err := db.db.QueryRowContext(ctx, "SELECT id FROM scans WHERE scope = ? AND status = 'completed' ORDER BY start_time DESC, id DESC LIMIT 1", scope).Scan(&id)
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

// GetScanDiff compares the current scan against the most recent previous completed scan
// in the same scope.
func (db *Storage) GetScanDiff(ctx context.Context, scope string, currentScanID int64) (*ScanDiff, error) {
	var previousID int64
	err := db.db.QueryRowContext(ctx,
		"SELECT id FROM scans WHERE scope = ? AND status = 'completed' AND id < ? ORDER BY start_time DESC, id DESC LIMIT 1",
		scope, currentScanID).Scan(&previousID)
	if err == sql.ErrNoRows {
		return nil, nil // No previous scan to diff against
	}
	if err != nil {
		return nil, err
	}

	diff := &ScanDiff{}

	// Find new targets
	rows, err := db.db.QueryContext(ctx, `
		SELECT t1.host
		FROM targets t1
		LEFT JOIN targets t2 ON t2.host = t1.host AND t2.scan_id = ?
		WHERE t1.scan_id = ? AND t2.host IS NULL`,
		previousID, currentScanID)
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
func (db *Storage) GetNewFindings(ctx context.Context, scope string, scanID int64) ([]EventRecord, error) {
	var previousID int64
	err := db.db.QueryRowContext(ctx,
		"SELECT id FROM scans WHERE scope = ? AND status = 'completed' AND id < ? ORDER BY start_time DESC, id DESC LIMIT 1",
		scope, scanID).Scan(&previousID)
	if err == sql.ErrNoRows || previousID == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	query := `
		SELECT e1.target, e1.source, e1.type, e1.properties
		FROM events e1
		LEFT JOIN events e2 ON e2.target = e1.target AND e2.scan_id = ?
		WHERE e1.scan_id = ? AND e2.target IS NULL
	`
	rows, err := db.db.QueryContext(ctx, query, previousID, scanID)
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
func (db *Storage) GetStats(ctx context.Context) (Stats, error) {
	var stats Stats

	err := db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scans").Scan(&stats.TotalScans)
	if err != nil {
		return stats, err
	}

	err = db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM targets").Scan(&stats.TotalTargets)
	if err != nil {
		return stats, err
	}

	err = db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&stats.TotalEvents)
	if err != nil {
		return stats, err
	}

	err = db.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM insights WHERE priority = 'critical'").Scan(&stats.CriticalVulns)
	if err != nil {
		// insights table might be empty, ignore error and set to 0
		stats.CriticalVulns = 0
	}

	return stats, nil
}

// InsightRecord represents an insight record in the database.
type InsightRecord struct {
	Host     string   `json:"host"`
	Priority string   `json:"priority"`
	Score    int      `json:"score"`
	Tags     []string `json:"tags"`
}

// SaveInsights bulk inserts insight records.
func (db *Storage) SaveInsights(ctx context.Context, scanID int64, insights []InsightRecord) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, "INSERT INTO insights (scan_id, host, priority, score, tags) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, in := range insights {
		tagsJSON, _ := json.Marshal(in.Tags)
		if _, err := stmt.ExecContext(ctx, scanID, in.Host, in.Priority, in.Score, string(tagsJSON)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// RiskHistoryRecord represents a host's risk score at a scan time.
type RiskHistoryRecord struct {
	Host     string    `json:"host"`
	Score    int       `json:"score"`
	Priority string    `json:"priority"`
	ScanTime time.Time `json:"scan_time"`
}

// GetRiskHistory returns risk history for a specific host.
func (db *Storage) GetRiskHistory(ctx context.Context, host string, limit, offset int) ([]RiskHistoryRecord, error) {
	query := `
		SELECT i.host, i.score, i.priority, s.start_time
		FROM insights i
		JOIN scans s ON i.scan_id = s.id
		WHERE i.host = ? AND s.status = 'completed'
		ORDER BY s.start_time ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else {
		query += " LIMIT 1000"
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []RiskHistoryRecord
	for rows.Next() {
		var r RiskHistoryRecord
		if err := rows.Scan(&r.Host, &r.Score, &r.Priority, &r.ScanTime); err != nil {
			return nil, err
		}
		r.ScanTime = r.ScanTime.UTC()
		history = append(history, r)
	}
	return history, nil
}

// GetRiskTrend returns the average and maximum risk scores for all scans in a scope.
func (db *Storage) GetRiskTrend(ctx context.Context, scope string, limit, offset int) ([]map[string]interface{}, error) {
	query := `
		SELECT s.id, s.start_time, AVG(i.score) as avg_score, MAX(i.score) as max_score, COUNT(i.id) as host_count
		FROM scans s
		JOIN insights i ON i.scan_id = s.id
		WHERE s.scope = ? AND s.status = 'completed'
		GROUP BY s.id, s.start_time
		ORDER BY s.start_time ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else {
		query += " LIMIT 1000"
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trend []map[string]interface{}
	for rows.Next() {
		var id int64
		var t time.Time
		var avg float64
		var max int
		var count int
		if err := rows.Scan(&id, &t, &avg, &max, &count); err != nil {
			return nil, err
		}
		trend = append(trend, map[string]interface{}{
			"scan_id":    id,
			"scan_time":  t.UTC(),
			"avg_score":  avg,
			"max_score":  max,
			"host_count": count,
		})
	}
	return trend, nil
}

// TechHistoryRecord represents technology tag counts for a scan.
type TechHistoryRecord struct {
	ScanTime time.Time      `json:"scan_time"`
	Techs    map[string]int `json:"techs"`
}

// GetTechTrend returns technology tag occurrence counts over time for a scope.
func (db *Storage) GetTechTrend(ctx context.Context, scope string, limit, offset int) ([]TechHistoryRecord, error) {
	query := `
		SELECT s.start_time, i.tags
		FROM scans s
		JOIN insights i ON i.scan_id = s.id
		WHERE s.scope = ? AND s.status = 'completed'
		ORDER BY s.start_time ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else {
		query += " LIMIT 1000"
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := make(map[time.Time][]string)
	var timeSequence []time.Time

	for rows.Next() {
		var t time.Time
		var tagsJSON string
		if err := rows.Scan(&t, &tagsJSON); err != nil {
			return nil, err
		}
		t = t.UTC()
		var tags []string
		if tagsJSON != "" && tagsJSON != "null" {
			_ = json.Unmarshal([]byte(tagsJSON), &tags)
		}
		if _, ok := groups[t]; !ok {
			timeSequence = append(timeSequence, t)
		}
		groups[t] = append(groups[t], tags...)
	}

	var trend []TechHistoryRecord
	for _, t := range timeSequence {
		techCounts := make(map[string]int)
		for _, tag := range groups[t] {
			techCounts[tag]++
		}
		trend = append(trend, TechHistoryRecord{
			ScanTime: t,
			Techs:    techCounts,
		})
	}
	return trend, nil
}

// OwnershipHistoryRecord represents ownership history of an asset.
type OwnershipHistoryRecord struct {
	AssetID      string     `json:"asset_id"`
	OwnerName    string     `json:"owner_name"`
	OwnerEmail   string     `json:"owner_email"`
	TeamName     string     `json:"team_name"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	ChangeReason string     `json:"change_reason,omitempty"`
}

// GetOwnershipHistory returns ownership changes over time for an asset.
func (db *Storage) GetOwnershipHistory(ctx context.Context, assetID string, limit, offset int) ([]OwnershipHistoryRecord, error) {
	query := `
		SELECT ao.asset_id, COALESCE(o.name, ''), COALESCE(o.email, ''), COALESCE(t.name, ''), ao.start_time, ao.end_time, COALESCE(ao.change_reason, '')
		FROM asset_ownership ao
		LEFT JOIN owners o ON ao.owner_id = o.id
		LEFT JOIN teams t ON ao.team_id = t.id
		WHERE ao.asset_id = ?
		ORDER BY ao.start_time ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else {
		query += " LIMIT 1000"
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []OwnershipHistoryRecord
	for rows.Next() {
		var h OwnershipHistoryRecord
		if err := rows.Scan(&h.AssetID, &h.OwnerName, &h.OwnerEmail, &h.TeamName, &h.StartTime, &h.EndTime, &h.ChangeReason); err != nil {
			return nil, err
		}
		h.StartTime = h.StartTime.UTC()
		if h.EndTime != nil {
			utcEnd := h.EndTime.UTC()
			h.EndTime = &utcEnd
		}
		history = append(history, h)
	}
	return history, nil
}

// GetAssetHistory returns scan presence history for a specific asset.
func (db *Storage) GetAssetHistory(ctx context.Context, host string, limit, offset int) ([]map[string]interface{}, error) {
	query := `
		SELECT s.id, s.start_time, s.status
		FROM scans s
		JOIN targets t ON t.scan_id = s.id
		WHERE t.host = ?
		ORDER BY s.start_time ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else {
		query += " LIMIT 1000"
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []map[string]interface{}
	for rows.Next() {
		var id int64
		var t time.Time
		var status string
		if err := rows.Scan(&id, &t, &status); err != nil {
			return nil, err
		}
		history = append(history, map[string]interface{}{
			"scan_id":   id,
			"scan_time": t.UTC(),
			"status":    status,
		})
	}
	return history, nil
}

// GetFindingHistory returns historical scan observations of a specific finding.
func (db *Storage) GetFindingHistory(ctx context.Context, target string, limit, offset int) ([]map[string]interface{}, error) {
	query := `
		SELECT s.id, s.start_time, e.source, e.type
		FROM scans s
		JOIN events e ON e.scan_id = s.id
		WHERE e.target = ?
		ORDER BY s.start_time ASC
	`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else {
		query += " LIMIT 1000"
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	}
	rows, err := db.db.QueryContext(ctx, query, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []map[string]interface{}
	for rows.Next() {
		var id int64
		var t time.Time
		var source, eventType string
		if err := rows.Scan(&id, &t, &source, &eventType); err != nil {
			return nil, err
		}
		history = append(history, map[string]interface{}{
			"scan_id":    id,
			"scan_time":  t.UTC(),
			"source":     source,
			"event_type": eventType,
		})
	}
	return history, nil
}
