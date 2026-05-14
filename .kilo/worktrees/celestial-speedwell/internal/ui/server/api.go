// Package server — api.go provides the REST API handlers for the BBPTS dashboard.
// It uses standard library net/http for maximum compatibility.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Developer-Army/BBPTS/internal/core/storage"
)

// API wraps the database and provides HTTP handlers.
type API struct {
	db *storage.DB
}

// NewAPI creates a new API instance.
func NewAPI(db *storage.DB) *API {
	return &API{db: db}
}

// GetStats returns aggregate system statistics.
func (a *API) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := a.db.GetStats()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, stats)
}

// GetScans returns a list of recent scans.
func (a *API) GetScans(w http.ResponseWriter, r *http.Request) {
	scans, err := a.db.GetScans()
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

	events, err := a.db.GetEvents(scanID)
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
