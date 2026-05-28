package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

// API wraps the database and provides HTTP handlers.
type API struct {
	db           *storage.DB
	configPath   string
	masterDBPath string
}

// NewAPI creates a new API instance.
func NewAPI(db *storage.DB, configPath, masterDBPath string) *API {
	return &API{db: db, configPath: configPath, masterDBPath: masterDBPath}
}

// GetStats returns aggregate system statistics.
func (a *API) GetStats(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	stats, err := a.db.GetStats(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, stats)
}

// GetScans returns a list of recent scans.
func (a *API) GetScans(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	scans, err := a.db.GetScans(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, scans)
}

// GetEvents returns findings for a specific scan.
func (a *API) GetEvents(w http.ResponseWriter, r *http.Request) {
	scanIDStr := r.URL.Query().Get("scan_id")
	if scanIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "scan_id is required")
		return
	}

	scanID, err := strconv.ParseInt(scanIDStr, 10, 64)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid scan_id")
		return
	}

	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	events, err := a.db.GetEvents(r.Context(), scanID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, events)
}

// respondWithJSON is a helper to send JSON responses.
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write(response); err != nil {
		slog.Warn("failed to write json response", "error", err)
	}
}

// respondWithError is a helper to send error responses.
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// HandleConfig routes config GET and POST requests.
func (a *API) HandleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.GetConfig(w, r)
	case http.MethodPost:
		a.UpdateConfig(w, r)
	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// GetConfig reads and returns the JSON configuration file.
func (a *API) GetConfig(w http.ResponseWriter, r *http.Request) {
	if a.configPath == "" {
		respondWithError(w, http.StatusBadRequest, "config path is not configured")
		return
	}
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to read config file: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		slog.Warn("failed to write config response", "error", err)
	}
}

// UpdateConfig updates the BBPTS configuration file on disk.
func (a *API) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	if a.configPath == "" {
		respondWithError(w, http.StatusBadRequest, "config path is not configured")
		return
	}
	var temp interface{}
	if err := json.NewDecoder(r.Body).Decode(&temp); err != nil {
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON configuration: %v", err))
		return
	}
	// Pretty print and write back to file
	data, err := json.MarshalIndent(temp, "", "  ")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal JSON: %v", err))
		return
	}
	if err := os.WriteFile(a.configPath, data, 0644); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save config: %v", err))
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "configuration updated successfully"})
}

// StreamLogs implements log streaming via Server-Sent Events (SSE).
func (a *API) StreamLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	logChan := make(chan string, 100)
	RegisterLogClient(logChan)
	defer UnregisterLogClient(logChan)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case logLine := <-logChan:
			fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(logLine, "\n", "\ndata: "))
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// HandleFleetSync merges target SQLite databases securely over HTTP.
func (a *API) HandleFleetSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	receivedToken := r.Header.Get("X-Sync-Token")
	if receivedToken == "" {
		respondWithError(w, http.StatusUnauthorized, "sync token required")
		return
	}

	cfg, err := config.LoadFromFile(a.configPath)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load configuration: %v", err))
		return
	}
	expectedToken := cfg.Fleet.SyncToken
	if expectedToken == "" {
		expectedToken = os.Getenv("BBPTS_SYNC_TOKEN")
	}

	if expectedToken == "" || receivedToken != expectedToken {
		respondWithError(w, http.StatusForbidden, "invalid sync token")
		return
	}

	tempFile, err := os.CreateTemp("", "bbpts-sync-*.db")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create temp file: %v", err))
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, r.Body); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save uploaded database: %v", err))
		return
	}
	tempFile.Close()

	if err := services.ImportAndMergeDatabase(a.masterDBPath, tempFile.Name()); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to merge database: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "database merged successfully"})
}
