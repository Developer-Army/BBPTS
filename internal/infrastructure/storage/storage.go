package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/assets"
	"github.com/Developer-Army/BBPTS/internal/domain/findings"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	_ "modernc.org/sqlite" // Import Go-native SQLite driver
)

// Storage manages the SQLite/Postgres database connection and queries.
type Storage struct {
	db     *sql.DB
	dbType string
}

// DB is an alias of Storage to unify database classes.
type DB = Storage

// NewStorage initializes a new database connection.
func NewStorage(dbType, dbSource string) (*Storage, error) {
	if dbType == "" || dbType == "sqlite3" {
		dbType = "sqlite"
	}
	if dbType == "postgres" {
		return nil, fmt.Errorf("postgres storage is not enabled in the default build")
	}

	db, err := sql.Open(dbType, dbSource)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if dbType == "sqlite" {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	if err := db.Ping(); err != nil {
		if errClose := db.Close(); errClose != nil {
			slog.Warn("failed to close database on initialization error", "error", errClose)
		}
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	if dbType == "sqlite" {
		if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;`); err != nil {
			if errClose := db.Close(); errClose != nil {
				slog.Warn("failed to close database on initialization error", "error", errClose)
			}
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
		asset_id TEXT DEFAULT '',
		risk_score INTEGER DEFAULT 0,
		confidence INTEGER DEFAULT 0,
		evidence_ids TEXT DEFAULT '[]',
		workflow_state TEXT DEFAULT 'Discovered',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS asset_nodes (
		id TEXT PRIMARY KEY,
		node_type TEXT NOT NULL,
		value TEXT NOT NULL,
		properties TEXT,
		scope_id TEXT DEFAULT '',
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		source TEXT DEFAULT '',
		confidence REAL DEFAULT 1.0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS asset_edges (
		source_id TEXT NOT NULL,
		target_id TEXT NOT NULL,
		relation TEXT NOT NULL,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		confidence REAL DEFAULT 1.0,
		observed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		evidence_id TEXT DEFAULT '',
		PRIMARY KEY (source_id, target_id, relation),
		FOREIGN KEY (source_id) REFERENCES asset_nodes(id) ON DELETE CASCADE,
		FOREIGN KEY (target_id) REFERENCES asset_nodes(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS teams (
		id INTEGER PRIMARY KEY %s,
		name TEXT NOT NULL UNIQUE,
		manager_id INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(manager_id) REFERENCES owners(id)
	);

	CREATE TABLE IF NOT EXISTS owners (
		id INTEGER PRIMARY KEY %s,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		manager_id INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(manager_id) REFERENCES owners(id)
	);

	CREATE TABLE IF NOT EXISTS asset_ownership (
		id INTEGER PRIMARY KEY %s,
		asset_id TEXT NOT NULL,
		owner_id INTEGER,
		team_id INTEGER,
		start_time TIMESTAMP NOT NULL,
		end_time TIMESTAMP,
		FOREIGN KEY(owner_id) REFERENCES owners(id),
		FOREIGN KEY(team_id) REFERENCES teams(id)
	);

	CREATE TABLE IF NOT EXISTS sla_policies (
		id INTEGER PRIMARY KEY %s,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		duration_days INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS finding_assignments (
		id INTEGER PRIMARY KEY %s,
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
		id INTEGER PRIMARY KEY %s,
		policy_id INTEGER NOT NULL,
		delay_days INTEGER NOT NULL,
		action_type TEXT NOT NULL,
		properties TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(policy_id) REFERENCES sla_policies(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS dashboard_users (
		id INTEGER PRIMARY KEY %s,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS user_sessions (
		token TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		role TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY %s,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		username TEXT NOT NULL,
		role TEXT NOT NULL,
		action TEXT NOT NULL,
		resource TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		status TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS finding_status_history (
		id INTEGER PRIMARY KEY %s,
		finding_id INTEGER NOT NULL,
		old_status TEXT NOT NULL,
		new_status TEXT NOT NULL,
		changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		comment TEXT,
		changed_by TEXT,
		FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS setup_tokens (
		token TEXT PRIMARY KEY,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS evidence (
		id TEXT PRIMARY KEY,
		asset_id TEXT NOT NULL,
		source TEXT NOT NULL,
		confidence REAL DEFAULT 1.0,
		collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		raw_data BLOB,
		hash TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS assets (
		id TEXT PRIMARY KEY,
		asset_type TEXT NOT NULL,
		name TEXT NOT NULL,
		criticality TEXT DEFAULT 'medium',
		environment TEXT DEFAULT 'production',
		owner_id INTEGER,
		confidence REAL DEFAULT 1.0,
		first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		status TEXT DEFAULT 'active'
	);
	`, autoInc, autoInc, autoInc, autoInc, autoInc, autoInc, autoInc, autoInc, autoInc, autoInc, autoInc)

	if s.dbType == "postgres" {
		schema = strings.ReplaceAll(schema, "INTEGER PRIMARY KEY", "SERIAL PRIMARY KEY")
		schema = strings.ReplaceAll(schema, "DATETIME", "TIMESTAMP")
	}

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Dynamic column migrations for Phase 3
	_, _ = s.db.Exec("ALTER TABLE asset_ownership ADD COLUMN change_reason TEXT")
	_, _ = s.db.Exec("ALTER TABLE sla_policies ADD COLUMN asset_class TEXT")
	_, _ = s.db.Exec("ALTER TABLE sla_policies ADD COLUMN business_unit TEXT")
	_, _ = s.db.Exec("ALTER TABLE sla_policies ADD COLUMN environment TEXT")
	_, _ = s.db.Exec("ALTER TABLE sla_policies ADD COLUMN program TEXT")

	// Dynamic migrations for rich asset graph metadata
	_, _ = s.db.Exec("ALTER TABLE asset_nodes ADD COLUMN scope_id TEXT DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE asset_nodes ADD COLUMN first_seen DATETIME DEFAULT CURRENT_TIMESTAMP")
	_, _ = s.db.Exec("ALTER TABLE asset_nodes ADD COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP")
	_, _ = s.db.Exec("ALTER TABLE asset_nodes ADD COLUMN source TEXT DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE asset_nodes ADD COLUMN confidence REAL DEFAULT 1.0")
	_, _ = s.db.Exec("ALTER TABLE asset_edges ADD COLUMN confidence REAL DEFAULT 1.0")
	_, _ = s.db.Exec("ALTER TABLE asset_edges ADD COLUMN observed_at DATETIME DEFAULT CURRENT_TIMESTAMP")
	_, _ = s.db.Exec("ALTER TABLE asset_edges ADD COLUMN evidence_id TEXT DEFAULT ''")

	// Dynamic migrations for findings domain mapping
	_, _ = s.db.Exec("ALTER TABLE findings ADD COLUMN asset_id TEXT DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE findings ADD COLUMN risk_score INTEGER DEFAULT 0")
	_, _ = s.db.Exec("ALTER TABLE findings ADD COLUMN confidence INTEGER DEFAULT 0")
	_, _ = s.db.Exec("ALTER TABLE findings ADD COLUMN evidence_ids TEXT DEFAULT '[]'")
	_, _ = s.db.Exec("ALTER TABLE findings ADD COLUMN workflow_state TEXT DEFAULT 'Discovered'")

	// Add manager_id columns to owners and teams
	_, _ = s.db.Exec("ALTER TABLE owners ADD COLUMN manager_id INTEGER")
	_, _ = s.db.Exec("ALTER TABLE teams ADD COLUMN manager_id INTEGER")

	return nil
}

// SaveEvidence stores findings evidence.
func (s *Storage) SaveEvidence(id, assetID, source string, confidence float64, rawData []byte, hash string) error {
	query := `
		INSERT INTO evidence (id, asset_id, source, confidence, collected_at, raw_data, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			confidence = excluded.confidence,
			raw_data = excluded.raw_data
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO evidence (id, asset_id, source, confidence, collected_at, raw_data, hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT(id) DO UPDATE SET
				confidence = EXCLUDED.confidence,
				raw_data = EXCLUDED.raw_data
		`
	}
	_, err := s.db.Exec(query, id, assetID, source, confidence, time.Now().UTC(), rawData, hash)
	return err
}

// GetEvidenceByAssetID retrieves evidence for an asset.
func (s *Storage) GetEvidenceByAssetID(assetID string) ([]map[string]interface{}, error) {
	query := "SELECT id, asset_id, source, confidence, collected_at, raw_data, hash FROM evidence WHERE asset_id = ?"
	if s.dbType == "postgres" {
		query = "SELECT id, asset_id, source, confidence, collected_at, raw_data, hash FROM evidence WHERE asset_id = $1"
	}
	rows, err := s.db.Query(query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id, assID, source, hash string
		var confidence float64
		var collectedAt time.Time
		var rawData []byte
		if err := rows.Scan(&id, &assID, &source, &confidence, &collectedAt, &rawData, &hash); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{
			"id":           id,
			"asset_id":     assID,
			"source":       source,
			"confidence":   confidence,
			"collected_at": collectedAt,
			"raw_data":     rawData,
			"hash":         hash,
		})
	}
	return result, nil
}

// SaveEvent stores a recon event in the database.
func (s *Storage) SaveEvent(ev recon.Event) error {
	// Hot/Cold Data Separation for massive response bodies
	if body, ok := ev.Properties["response_body"]; ok && len(body) > 1024 {
		hash := sha256.Sum256([]byte(body))
		blobID := fmt.Sprintf("%x", hash[:16])

		blobDir := filepath.Join("results", "blobs")
		if errMkdir := os.MkdirAll(blobDir, 0700); errMkdir != nil {
			slog.Warn("failed to create blob directory", "dir", blobDir, "error", errMkdir)
		}
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

// GetDB returns the raw sql.DB connection.
func (s *Storage) GetDB() *sql.DB {
	return s.db
}

// SaveFindingModel stores or updates the domain Finding model.
func (s *Storage) SaveFindingModel(f findings.Finding) (int64, error) {
	evidenceJSON, err := json.Marshal(f.EvidenceIDs)
	if err != nil {
		return 0, err
	}
	if f.ID > 0 {
		query := `
			UPDATE findings SET
				asset_id = ?,
				risk_score = ?,
				confidence = ?,
				evidence_ids = ?,
				workflow_state = ?
			WHERE id = ?
		`
		if s.dbType == "postgres" {
			query = `
				UPDATE findings SET
					asset_id = $1,
					risk_score = $2,
					confidence = $3,
					evidence_ids = $4,
					workflow_state = $5
				WHERE id = $6
			`
		}
		_, err = s.db.Exec(query, f.AssetID, f.RiskScore, f.Confidence, string(evidenceJSON), f.WorkflowState, f.ID)
		return f.ID, err
	}

	query := `
		INSERT INTO findings (title, description, severity, target, metadata, asset_id, risk_score, confidence, evidence_ids, workflow_state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO findings (title, description, severity, target, metadata, asset_id, risk_score, confidence, evidence_ids, workflow_state)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id
		`
		var id int64
		err = s.db.QueryRow(query, "", "", "", "", "", f.AssetID, f.RiskScore, f.Confidence, string(evidenceJSON), f.WorkflowState).Scan(&id)
		return id, err
	}

	res, err := s.db.Exec(query, "", "", "", "", "", f.AssetID, f.RiskScore, f.Confidence, string(evidenceJSON), f.WorkflowState)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetFindingModel retrieves the domain Finding model by ID.
func (s *Storage) GetFindingModel(id int64) (*findings.Finding, error) {
	query := `
		SELECT id, asset_id, risk_score, confidence, evidence_ids, workflow_state
		FROM findings
		WHERE id = ?
	`
	if s.dbType == "postgres" {
		query = `
			SELECT id, asset_id, risk_score, confidence, evidence_ids, workflow_state
			FROM findings
			WHERE id = $1
		`
	}
	var f findings.Finding
	var evidenceJSON string
	err := s.db.QueryRow(query, id).Scan(&f.ID, &f.AssetID, &f.RiskScore, &f.Confidence, &evidenceJSON, &f.WorkflowState)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if evidenceJSON != "" {
		_ = json.Unmarshal([]byte(evidenceJSON), &f.EvidenceIDs)
	}
	return &f, nil
}

// GetEvidenceModel retrieves the domain Evidence model by ID.
func (s *Storage) GetEvidenceModel(id string) (*findings.Evidence, error) {
	query := `
		SELECT id, asset_id, source, confidence, collected_at, raw_data, hash
		FROM evidence
		WHERE id = ?
	`
	if s.dbType == "postgres" {
		query = `
			SELECT id, asset_id, source, confidence, collected_at, raw_data, hash
			FROM evidence
			WHERE id = $1
		`
	}
	var ev findings.Evidence
	err := s.db.QueryRow(query, id).Scan(&ev.ID, &ev.AssetID, &ev.Source, &ev.Confidence, &ev.CollectedAt, &ev.RawData, &ev.Hash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ev, nil
}

// SaveAsset inserts or updates an asset in the database.
func (s *Storage) SaveAsset(a assets.Asset) error {
	query := `
		INSERT INTO assets (id, asset_type, name, criticality, environment, owner_id, confidence, first_seen, last_seen, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			asset_type = excluded.asset_type,
			name = excluded.name,
			criticality = excluded.criticality,
			environment = excluded.environment,
			owner_id = excluded.owner_id,
			confidence = excluded.confidence,
			last_seen = excluded.last_seen,
			status = excluded.status
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO assets (id, asset_type, name, criticality, environment, owner_id, confidence, first_seen, last_seen, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT(id) DO UPDATE SET
				asset_type = EXCLUDED.asset_type,
				name = EXCLUDED.name,
				criticality = EXCLUDED.criticality,
				environment = EXCLUDED.environment,
				owner_id = EXCLUDED.owner_id,
				confidence = EXCLUDED.confidence,
				last_seen = EXCLUDED.last_seen,
				status = EXCLUDED.status
		`
	}
	_, err := s.db.Exec(query, a.ID, a.Type, a.Name, a.Criticality, a.Environment, a.OwnerID, a.Confidence, a.FirstSeen, a.LastSeen, a.Status)
	return err
}

// GetAsset retrieves an asset by its ID.
func (s *Storage) GetAsset(id string) (*assets.Asset, error) {
	query := `
		SELECT id, asset_type, name, criticality, environment, owner_id, confidence, first_seen, last_seen, status
		FROM assets
		WHERE id = ?
	`
	if s.dbType == "postgres" {
		query = `
			SELECT id, asset_type, name, criticality, environment, owner_id, confidence, first_seen, last_seen, status
			FROM assets
			WHERE id = $1
		`
	}
	var a assets.Asset
	err := s.db.QueryRow(query, id).Scan(&a.ID, &a.Type, &a.Name, &a.Criticality, &a.Environment, &a.OwnerID, &a.Confidence, &a.FirstSeen, &a.LastSeen, &a.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetAllAssets retrieves all assets.
func (s *Storage) GetAllAssets() ([]assets.Asset, error) {
	query := `
		SELECT id, asset_type, name, criticality, environment, owner_id, confidence, first_seen, last_seen, status
		FROM assets
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []assets.Asset
	for rows.Next() {
		var a assets.Asset
		err := rows.Scan(&a.ID, &a.Type, &a.Name, &a.Criticality, &a.Environment, &a.OwnerID, &a.Confidence, &a.FirstSeen, &a.LastSeen, &a.Status)
		if err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, nil
}

