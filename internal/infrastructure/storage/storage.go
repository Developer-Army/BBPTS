package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	_ "github.com/mattn/go-sqlite3" // Import SQLite driver
)

// Storage manages the SQLite/Postgres database connection and queries.
type Storage struct {
	db     *sql.DB
	dbType string
}

// NewStorage initializes a new database connection.
func NewStorage(dbType, dbSource string) (*Storage, error) {
	if dbType == "" {
		dbType = "sqlite3"
	}
	if dbType == "postgres" {
		return nil, fmt.Errorf("postgres storage is not enabled in the default build")
	}

	db, err := sql.Open(dbType, dbSource)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if dbType == "sqlite" || dbType == "sqlite3" {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	if dbType == "sqlite" || dbType == "sqlite3" {
		if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;`); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to configure sqlite pragmas: %w", err)
		}
	}

	s := &Storage{db: db, dbType: dbType}
	if err := s.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

func (s *Storage) initSchema() error {
	autoInc := "AUTOINCREMENT"
	if s.dbType == "postgres" {
		autoInc = ""
	}

	schema := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY %s,
		target TEXT NOT NULL,
		source TEXT NOT NULL,
		event_type TEXT NOT NULL,
		properties TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_events_target ON events(target);
	CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
	CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY %s,
		title TEXT NOT NULL,
		description TEXT,
		severity TEXT,
		target TEXT NOT NULL,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS asset_nodes (
		id TEXT PRIMARY KEY,
		node_type TEXT NOT NULL,
		value TEXT NOT NULL,
		properties TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS asset_edges (
		source_id TEXT NOT NULL,
		target_id TEXT NOT NULL,
		relation TEXT NOT NULL,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (source_id, target_id, relation),
		FOREIGN KEY (source_id) REFERENCES asset_nodes(id) ON DELETE CASCADE,
		FOREIGN KEY (target_id) REFERENCES asset_nodes(id) ON DELETE CASCADE
	);
	`, autoInc, autoInc)

	if s.dbType == "postgres" {
		schema = strings.ReplaceAll(schema, "INTEGER PRIMARY KEY", "SERIAL PRIMARY KEY")
		schema = strings.ReplaceAll(schema, "DATETIME", "TIMESTAMP")
	}

	_, err := s.db.Exec(schema)
	return err
}

// SaveEvent stores a recon event in the database.
func (s *Storage) SaveEvent(ev recon.Event) error {
	// Hot/Cold Data Separation for massive response bodies
	if body, ok := ev.Properties["response_body"]; ok && len(body) > 1024 {
		hash := sha256.Sum256([]byte(body))
		blobID := fmt.Sprintf("%x", hash[:16])

		blobDir := filepath.Join("results", "blobs")
		_ = os.MkdirAll(blobDir, 0700)
		blobPath := filepath.Join(blobDir, blobID)

		if err := os.WriteFile(blobPath, []byte(body), 0644); err == nil {
			ev.Properties["response_body_blob"] = "file://" + blobPath
			delete(ev.Properties, "response_body")
		}
	}

	propsJSON, err := json.Marshal(ev.Properties)
	if err != nil {
		return err
	}

	query := "INSERT INTO events (target, source, event_type, properties, created_at) VALUES (?, ?, ?, ?, ?)"
	if s.dbType == "postgres" {
		query = "INSERT INTO events (target, source, event_type, properties, created_at) VALUES ($1, $2, $3, $4, $5)"
	}

	_, err = s.db.Exec(query, ev.Target, ev.Source, ev.Type, string(propsJSON), time.Now().UTC())
	return err
}

// GetEventsByTarget retrieves all events for a specific target.
func (s *Storage) GetEventsByTarget(target string) ([]recon.Event, error) {
	query := "SELECT target, source, event_type, properties FROM events WHERE target = ?"
	if s.dbType == "postgres" {
		query = "SELECT target, source, event_type, properties FROM events WHERE target = $1"
	}

	rows, err := s.db.Query(query, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []recon.Event
	for rows.Next() {
		var ev recon.Event
		var propsStr string
		if err := rows.Scan(&ev.Target, &ev.Source, &ev.Type, &propsStr); err != nil {
			return nil, err
		}
		if propsStr != "" {
			if err := json.Unmarshal([]byte(propsStr), &ev.Properties); err != nil {
				return nil, err
			}
		}
		events = append(events, ev)
	}
	return events, nil
}

// Close gracefully closes the database connection.
func (s *Storage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
