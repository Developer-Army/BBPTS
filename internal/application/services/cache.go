package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteTimeFmt = "2006-01-02 15:04:05"

type CacheEntry struct {
	Key       string    `json:"key"`
	ToolName  string    `json:"tool_name"`
	Target    string    `json:"target"`
	Events    []Event   `json:"events"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	HitCount  int       `json:"hit_count"`
}

type CacheConfig struct {
	// Enabled turns caching on/off.
	Enabled bool
	// DBPath is the SQLite database file path.
	DBPath string
	// DefaultTTL is the default time-to-live for cache entries.
	DefaultTTL time.Duration
	// MaxEntries is the maximum number of cached entries (LRU eviction).
	MaxEntries int
	// ToolTTLOverrides allows per-tool TTL configuration.
	ToolTTLOverrides map[string]time.Duration
}

func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:    true,
		DBPath:     "results/tmp/bbpts_cache.db",
		DefaultTTL: 4 * time.Hour,
		MaxEntries: 10000,
		ToolTTLOverrides: map[string]time.Duration{

			"crtsh":       24 * time.Hour,
			"whois":       24 * time.Hour,
			"shodan":      12 * time.Hour,
			"subfinder":   8 * time.Hour,
			"assetfinder": 8 * time.Hour,
			"chaos":       8 * time.Hour,

			"httpx":  2 * time.Hour,
			"naabu":  2 * time.Hour,
			"nuclei": 1 * time.Hour,
		},
	}
}

type ResultCache struct {
	db     *sql.DB
	config CacheConfig
	mu     sync.RWMutex
}

func NewResultCache(config CacheConfig) (*ResultCache, error) {
	if !config.Enabled {
		return nil, nil
	}

	dir := filepath.Dir(config.DBPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	db, err := sql.Open("sqlite", config.DBPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	rc := &ResultCache{
		db:     db,
		config: config,
	}

	if err := rc.initialize(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize cache schema: %w", err)
	}

	go rc.cleanupLoop()

	return rc, nil
}

func (rc *ResultCache) initialize() error {
	schema := `
		CREATE TABLE IF NOT EXISTS result_cache (
			cache_key   TEXT PRIMARY KEY,
			tool_name   TEXT NOT NULL,
			target      TEXT NOT NULL,
			events_json TEXT NOT NULL,
			created_at  TEXT NOT NULL,
			expires_at  TEXT NOT NULL,
			hit_count   INTEGER DEFAULT 0,
			last_hit_at TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_cache_tool ON result_cache(tool_name);
		CREATE INDEX IF NOT EXISTS idx_cache_expires ON result_cache(expires_at);
		CREATE INDEX IF NOT EXISTS idx_cache_target ON result_cache(target);
	`
	_, err := rc.db.Exec(schema)
	return err
}

func CacheKey(toolName string, targets []string, threads int) string {
	sorted := make([]string, len(targets))
	copy(sorted, targets)

	key := fmt.Sprintf("%s|%s|%d", strings.ToLower(toolName), strings.Join(sorted, ","), threads)
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash[:16])
}

func (rc *ResultCache) Get(toolName string, targets []string, threads int) (*CacheEntry, bool) {
	if rc == nil {
		return nil, false
	}

	key := CacheKey(toolName, targets, threads)

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	row := rc.db.QueryRow(`
		SELECT cache_key, tool_name, target, events_json, created_at, expires_at, hit_count
		FROM result_cache
		WHERE cache_key = ? AND expires_at > datetime('now')
	`, key)

	var entry CacheEntry
	var eventsJSON, createdStr, expiresStr string
	err := row.Scan(&entry.Key, &entry.ToolName, &entry.Target, &eventsJSON, &createdStr, &expiresStr, &entry.HitCount)
	if err != nil {
		return nil, false
	}

	if err := json.Unmarshal([]byte(eventsJSON), &entry.Events); err != nil {
		slog.Warn("Failed to unmarshal cached events", "key", key, "error", err)
		return nil, false
	}

	var errParse error
	entry.CreatedAt, errParse = time.Parse(sqliteTimeFmt, createdStr)
	if errParse != nil {
		slog.Warn("Failed to parse CreatedAt from cache database", "string", createdStr, "error", errParse)
	}
	entry.ExpiresAt, errParse = time.Parse(sqliteTimeFmt, expiresStr)
	if errParse != nil {
		slog.Warn("Failed to parse ExpiresAt from cache database", "string", expiresStr, "error", errParse)
	}

	go func() {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		if _, errExec := rc.db.Exec(`
			UPDATE result_cache 
			SET hit_count = hit_count + 1, last_hit_at = datetime('now')
			WHERE cache_key = ?
		`, key); errExec != nil {
			slog.Warn("Failed to update cache hit count", "key", key, "error", errExec)
		}
	}()

	slog.Debug("Cache hit", "tool", toolName, "key", key, "hits", entry.HitCount+1)
	return &entry, true
}

func (rc *ResultCache) Put(toolName string, targets []string, threads int, events []Event) error {
	if rc == nil {
		return nil
	}

	key := CacheKey(toolName, targets, threads)
	ttl := rc.ttlForTool(toolName)

	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal events for cache: %w", err)
	}

	now := time.Now().UTC()
	expires := now.Add(ttl)

	rc.mu.Lock()
	defer rc.mu.Unlock()

	_, err = rc.db.Exec(`
		INSERT OR REPLACE INTO result_cache 
		(cache_key, tool_name, target, events_json, created_at, expires_at, hit_count, last_hit_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, NULL)
	`, key, toolName, strings.Join(targets, ","), string(eventsJSON),
		now.Format(sqliteTimeFmt), expires.Format(sqliteTimeFmt))

	if err != nil {
		return fmt.Errorf("failed to insert cache entry: %w", err)
	}

	slog.Debug("Cache put", "tool", toolName, "key", key, "ttl", ttl)
	return nil
}

func (rc *ResultCache) Invalidate(toolName string, targets []string, threads int) error {
	if rc == nil {
		return nil
	}

	key := CacheKey(toolName, targets, threads)
	rc.mu.Lock()
	defer rc.mu.Unlock()

	_, err := rc.db.Exec(`DELETE FROM result_cache WHERE cache_key = ?`, key)
	return err
}

func (rc *ResultCache) InvalidateAll() error {
	if rc == nil {
		return nil
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	_, err := rc.db.Exec(`DELETE FROM result_cache`)
	return err
}

func (rc *ResultCache) Stats() map[string]interface{} {
	if rc == nil {
		return map[string]interface{}{"enabled": false}
	}

	rc.mu.RLock()
	defer rc.mu.RUnlock()

	var totalEntries int
	var totalHits int64
	if err := rc.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(hit_count), 0) FROM result_cache`).Scan(&totalEntries, &totalHits); err != nil {
		slog.Warn("Cache stats: failed to scan total stats", "error", err)
	}

	var expiredEntries int
	if err := rc.db.QueryRow(`SELECT COUNT(*) FROM result_cache WHERE expires_at <= datetime('now')`).Scan(&expiredEntries); err != nil {
		slog.Warn("Cache stats: failed to scan expired stats", "error", err)
	}

	rows, err := rc.db.Query(`
		SELECT tool_name, COUNT(*), SUM(hit_count) 
		FROM result_cache 
		WHERE expires_at > datetime('now')
		GROUP BY tool_name
	`)
	toolStats := make(map[string]map[string]interface{})
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var count int
			var hits int64
			if err := rows.Scan(&name, &count, &hits); err != nil {
				slog.Warn("Cache stats: failed to scan tool stats row", "error", err)
				continue
			}
			toolStats[name] = map[string]interface{}{
				"entries": count,
				"hits":    hits,
			}
		}
	}

	return map[string]interface{}{
		"enabled":         true,
		"total_entries":   totalEntries,
		"expired_entries": expiredEntries,
		"active_entries":  totalEntries - expiredEntries,
		"total_hits":      totalHits,
		"per_tool":        toolStats,
	}
}

func (rc *ResultCache) Close() error {
	if rc == nil {
		return nil
	}
	return rc.db.Close()
}

func (rc *ResultCache) ttlForTool(toolName string) time.Duration {
	if ttl, ok := rc.config.ToolTTLOverrides[strings.ToLower(toolName)]; ok {
		return ttl
	}
	return rc.config.DefaultTTL
}

func (rc *ResultCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rc.mu.Lock()

		result, err := rc.db.Exec(`DELETE FROM result_cache WHERE expires_at <= datetime('now')`)
		if err == nil {
			if deleted, errRows := result.RowsAffected(); errRows == nil && deleted > 0 {
				slog.Debug("Cache cleanup: removed expired entries", "count", deleted)
			}
		}

		if rc.config.MaxEntries > 0 {
			var count int
			if err := rc.db.QueryRow(`SELECT COUNT(*) FROM result_cache`).Scan(&count); err != nil {
				slog.Warn("Cache cleanup: failed to count database entries", "error", err)
			}
			if count > rc.config.MaxEntries {
				excess := count - rc.config.MaxEntries
				if _, errExec := rc.db.Exec(`
					DELETE FROM result_cache 
					WHERE cache_key IN (
						SELECT cache_key FROM result_cache 
						ORDER BY COALESCE(last_hit_at, created_at) ASC 
						LIMIT ?
					)
				`, excess); errExec != nil {
					slog.Warn("Cache cleanup: LRU eviction query failed", "error", errExec)
				}
				slog.Debug("Cache cleanup: LRU eviction", "evicted", excess)
			}
		}

		rc.mu.Unlock()
	}
}
