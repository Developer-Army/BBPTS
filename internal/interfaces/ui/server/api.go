package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/security"
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

func getLimitOffset(r *http.Request) (int, int) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	var limit, offset int
	if limitStr != "" {
		limit, _ = strconv.Atoi(limitStr)
	}
	if offsetStr != "" {
		offset, _ = strconv.Atoi(offsetStr)
	}
	return limit, offset
}

// GetScans returns a list of recent scans.
func (a *API) GetScans(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}

	limit, offset := getLimitOffset(r)
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 100
	}

	scans, err := a.db.GetScans(r.Context(), limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(scans) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
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

	limit, offset := getLimitOffset(r)

	events, err := a.db.GetEvents(r.Context(), scanID, limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if limit > 0 && len(events) == limit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+limit))
	}
	respondWithJSON(w, http.StatusOK, events)
}

// respondWithJSON is a helper to send JSON responses.
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	redacted := []byte(security.RedactSecrets(string(response)))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write(redacted); err != nil {
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

const redactPlaceholder = "●●●●●●●●"

func redactConfig(cfg *config.Config) *config.Config {
	redacted := *cfg
	if redacted.APIKeys != nil {
		redacted.APIKeys = make(map[string]string)
		for k, v := range cfg.APIKeys {
			if v != "" {
				redacted.APIKeys[k] = redactPlaceholder
			} else {
				redacted.APIKeys[k] = ""
			}
		}
	}
	if redacted.DashboardToken != "" {
		redacted.DashboardToken = redactPlaceholder
	}
	if redacted.Fleet.SyncToken != "" {
		redacted.Fleet.SyncToken = redactPlaceholder
	}
	if redacted.Notify.TelegramBotToken != "" {
		redacted.Notify.TelegramBotToken = redactPlaceholder
	}
	if redacted.Notify.TelegramChatID != "" {
		redacted.Notify.TelegramChatID = redactPlaceholder
	}
	if redacted.Notify.DiscordWebhook != "" {
		redacted.Notify.DiscordWebhook = redactPlaceholder
	}
	if redacted.Notify.SlackWebhook != "" {
		redacted.Notify.SlackWebhook = redactPlaceholder
	}
	return &redacted
}

// GetConfig reads and returns the JSON configuration file.
func (a *API) GetConfig(w http.ResponseWriter, r *http.Request) {
	if a.configPath == "" {
		respondWithError(w, http.StatusBadRequest, "config path is not configured")
		return
	}
	cfg, err := config.LoadFromFile(a.configPath)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to read config file: %v", err))
		return
	}
	redacted := redactConfig(cfg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(redacted); err != nil {
		slog.Warn("failed to write config response", "error", err)
	}
}

// UpdateConfig updates the BBPTS configuration file on disk.
func (a *API) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	if a.configPath == "" {
		respondWithError(w, http.StatusBadRequest, "config path is not configured")
		return
	}

	// Limit request body size to 2 MB to prevent memory exhaustion attacks
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)

	var incoming config.Config
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON configuration: %v", err))
		return
	}

	// Load existing configuration
	existing, err := config.LoadFromFile(a.configPath)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load existing config: %v", err))
		return
	}

	// Validate and copy allowed fields
	existing.ContainerMode = incoming.ContainerMode

	if incoming.RateLimit >= 0 {
		existing.RateLimit = incoming.RateLimit
	}
	if incoming.Threads > 0 {
		existing.Threads = incoming.Threads
	}
	if incoming.BatchSize > 0 {
		existing.BatchSize = incoming.BatchSize
	}

	// Sanitize paths to prevent directory traversal
	if incoming.WordlistsDir != "" {
		if strings.Contains(incoming.WordlistsDir, "..") {
			respondWithError(w, http.StatusBadRequest, "invalid wordlists directory (traversal detected)")
			return
		}
		existing.WordlistsDir = incoming.WordlistsDir
	}
	if incoming.StateDir != "" {
		if strings.Contains(incoming.StateDir, "..") {
			respondWithError(w, http.StatusBadRequest, "invalid state directory (traversal detected)")
			return
		}
		existing.StateDir = incoming.StateDir
	}

	// Copy and validate wordlist files
	if incoming.Wordlists.DNS != "" {
		if strings.Contains(incoming.Wordlists.DNS, "..") {
			respondWithError(w, http.StatusBadRequest, "invalid dns wordlist filename")
			return
		}
		existing.Wordlists.DNS = incoming.Wordlists.DNS
	}
	if incoming.Wordlists.Directory != "" {
		if strings.Contains(incoming.Wordlists.Directory, "..") {
			respondWithError(w, http.StatusBadRequest, "invalid directory fuzzer wordlist filename")
			return
		}
		existing.Wordlists.Directory = incoming.Wordlists.Directory
	}
	if incoming.Wordlists.Subdomain != "" {
		if strings.Contains(incoming.Wordlists.Subdomain, "..") {
			respondWithError(w, http.StatusBadRequest, "invalid subdomain wordlist filename")
			return
		}
		existing.Wordlists.Subdomain = incoming.Wordlists.Subdomain
	}
	if incoming.Wordlists.API != "" {
		if strings.Contains(incoming.Wordlists.API, "..") {
			respondWithError(w, http.StatusBadRequest, "invalid api wordlist filename")
			return
		}
		existing.Wordlists.API = incoming.Wordlists.API
	}

	// Fleet settings
	if incoming.Fleet.SyncToken != "" && incoming.Fleet.SyncToken != redactPlaceholder {
		for _, r := range incoming.Fleet.SyncToken {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				respondWithError(w, http.StatusBadRequest, "invalid characters in fleet sync token")
				return
			}
		}
		existing.Fleet.SyncToken = incoming.Fleet.SyncToken
	}

	// API Keys whitelist validation
	allowedProviders := map[string]bool{
		"shodan":         true,
		"censys":         true,
		"securitytrails": true,
		"github":         true,
		"chaos":          true,
		"virustotal":     true,
		"passivetotal":   true,
		"binaryedge":     true,
	}

	if existing.APIKeys == nil {
		existing.APIKeys = make(map[string]string)
	}
	for k, v := range incoming.APIKeys {
		kLower := strings.ToLower(k)
		if allowedProviders[kLower] {
			if v != redactPlaceholder {
				existing.APIKeys[kLower] = v
			}
		}
	}

	// Marshal validated configuration
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal JSON: %v", err))
		return
	}

	if err := os.WriteFile(a.configPath, data, 0600); err != nil {
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
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, err := url.Parse(origin)
		if err == nil {
			host := u.Hostname()
			if host == "localhost" || host == "127.0.0.1" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1")
	}

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

	// Limit request body size to 50 MB to prevent disk exhaustion attacks
	r.Body = http.MaxBytesReader(w, r.Body, 50*1024*1024)

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

// GetRiskHistory returns risk history for a specific host, or a general risk trend.
func (a *API) GetRiskHistory(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	host := r.URL.Query().Get("host")
	scope := r.URL.Query().Get("scope")
	limit, offset := getLimitOffset(r)
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 1000
	}

	if host != "" {
		history, err := a.db.GetRiskHistory(r.Context(), host, limit, offset)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(history) == useLimit {
			w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
			w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
		}
		respondWithJSON(w, http.StatusOK, history)
		return
	}

	if scope == "" {
		scope = "default_run"
	}
	trend, err := a.db.GetRiskTrend(r.Context(), scope, limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(trend) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
	}
	respondWithJSON(w, http.StatusOK, trend)
}

// GetTechTrend returns technology trend counts over time.
func (a *API) GetTechTrend(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "default_run"
	}
	limit, offset := getLimitOffset(r)
	trend, err := a.db.GetTechTrend(r.Context(), scope, limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 1000
	}
	if len(trend) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
	}
	respondWithJSON(w, http.StatusOK, trend)
}

// GetOwnershipHistory returns ownership changes over time.
func (a *API) GetOwnershipHistory(w http.ResponseWriter, r *http.Request) {
	assetID := r.URL.Query().Get("asset_id")
	if assetID == "" {
		respondWithError(w, http.StatusBadRequest, "asset_id is required")
		return
	}
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	limit, offset := getLimitOffset(r)
	history, err := a.db.GetOwnershipHistory(r.Context(), assetID, limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 1000
	}
	if len(history) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
	}
	respondWithJSON(w, http.StatusOK, history)
}

// GetAssetHistory returns scan history for a specific asset.
func (a *API) GetAssetHistory(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		respondWithError(w, http.StatusBadRequest, "host is required")
		return
	}
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	limit, offset := getLimitOffset(r)
	history, err := a.db.GetAssetHistory(r.Context(), host, limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 1000
	}
	if len(history) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
	}
	respondWithJSON(w, http.StatusOK, history)
}

// GetFindingHistory returns specific finding history for a target.
func (a *API) GetFindingHistory(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		respondWithError(w, http.StatusBadRequest, "target is required")
		return
	}
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	limit, offset := getLimitOffset(r)
	history, err := a.db.GetFindingHistory(r.Context(), target, limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 1000
	}
	if len(history) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
	}
	respondWithJSON(w, http.StatusOK, history)
}

// GetGraphNodes returns paged asset nodes.
func (a *API) GetGraphNodes(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	limit, offset := getLimitOffset(r)
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 100
	}
	nodes, err := a.db.GetAllAssetNodes(limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(nodes) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
	}
	respondWithJSON(w, http.StatusOK, nodes)
}

// GetGraphEdges returns paged asset edges.
func (a *API) GetGraphEdges(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}
	limit, offset := getLimitOffset(r)
	useLimit := limit
	if useLimit <= 0 {
		useLimit = 100
	}
	edges, err := a.db.GetAllAssetEdges(limit, offset)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(edges) == useLimit {
		w.Header().Set("X-Warning", "Data truncated. Use pagination parameters (limit and offset) to retrieve more records.")
		w.Header().Set("X-Continuation-Token", strconv.Itoa(offset+useLimit))
	}
	respondWithJSON(w, http.StatusOK, edges)
}

var (
	loginAttemptsMu sync.Mutex
	loginAttempts   = make(map[string][]time.Time)
)

func isRateLimited(ip string) bool {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	now := time.Now()
	var validAttempts []time.Time
	for _, t := range loginAttempts[ip] {
		if now.Sub(t) < time.Minute {
			validAttempts = append(validAttempts, t)
		}
	}
	if len(validAttempts) >= 5 {
		loginAttempts[ip] = validAttempts
		return true
	}
	loginAttempts[ip] = append(validAttempts, now)
	return false
}

// Authenticate verifies the user credentials and sets a secure session cookie.
func (a *API) Authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	if isRateLimited(ip) {
		respondWithError(w, http.StatusTooManyRequests, "too many login attempts. please wait one minute.")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	// Limit request body to 1KB to prevent resource exhaustion attacks
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if req.Username == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	role, err := AuthenticateUser(a.db, req.Username, req.Password)
	if err != nil {
		LogAuditEvent(a.db, req.Username, "unknown", "login", "session", ip, "failed")
		respondWithError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := CreateSession(a.db, req.Username, role, 24*time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	LogAuditEvent(a.db, req.Username, role, "login", "session", ip, "success")

	http.SetCookie(w, &http.Cookie{
		Name:     "bbpts_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	respondWithJSON(w, http.StatusOK, map[string]string{
		"status":   "success",
		"username": req.Username,
		"role":     role,
	})
}

// Logout revokes the current session.
func (a *API) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	var receivedToken string
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		receivedToken = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if receivedToken == "" {
		receivedToken = r.Header.Get("X-Dashboard-Token")
	}
	if receivedToken == "" {
		if cookie, err := r.Cookie("bbpts_session"); err == nil {
			receivedToken = cookie.Value
		}
	}

	username, _ := r.Context().Value(UsernameKey).(string)
	role, _ := r.Context().Value(RoleKey).(string)

	if receivedToken != "" {
		_ = RevokeSession(a.db, receivedToken)
		if username != "" {
			LogAuditEvent(a.db, username, role, "logout", "session", ip, "success")
		}
	}

	// Delete cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "bbpts_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})

	respondWithJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// GetSetupToken returns the setup token if no admin/user is registered and query is local.
func (a *API) GetSetupToken(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// Restrict strictly to localhost loopback
	if ip != "127.0.0.1" && ip != "::1" && ip != "localhost" {
		respondWithError(w, http.StatusForbidden, "forbidden: setup token is only accessible from localhost")
		return
	}

	rawDB := a.db.GetDB()
	var userCount int
	_ = rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users").Scan(&userCount)
	if userCount > 0 {
		respondWithError(w, http.StatusForbidden, "forbidden: application already bootstrapped")
		return
	}

	var token string
	err = rawDB.QueryRow("SELECT token FROM setup_tokens LIMIT 1").Scan(&token)
	if err == sql.ErrNoRows {
		respondWithError(w, http.StatusNotFound, "no active setup token found")
		return
	} else if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"token": token})
}

// EnrollAdmin creates the initial admin user using a valid setup token.
func (a *API) EnrollAdmin(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// Restrict strictly to localhost loopback
	if ip != "127.0.0.1" && ip != "::1" && ip != "localhost" {
		respondWithError(w, http.StatusForbidden, "forbidden: enrollment is only allowed from localhost")
		return
	}

	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if req.Token == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "token and password are required")
		return
	}

	rawDB := a.db.GetDB()
	var userCount int
	_ = rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users").Scan(&userCount)
	if userCount > 0 {
		respondWithError(w, http.StatusForbidden, "forbidden: application already bootstrapped")
		return
	}

	var storedToken string
	err = rawDB.QueryRow("SELECT token FROM setup_tokens WHERE token = ?", req.Token).Scan(&storedToken)
	if err == sql.ErrNoRows {
		respondWithError(w, http.StatusForbidden, "invalid setup token")
		return
	} else if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	salt, err := GenerateRandomString(16)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to generate salt")
		return
	}
	hash := HashPassword(req.Password, salt)
	storedValue := salt + "." + hash

	tx, err := rawDB.Begin()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec("INSERT INTO dashboard_users (username, password_hash, role) VALUES (?, ?, ?)", "admin", storedValue, "admin")
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to insert admin user")
		return
	}

	_, _ = tx.Exec("DELETE FROM setup_tokens WHERE token = ?", req.Token)

	if err := tx.Commit(); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	LogAuditEvent(a.db, "SYSTEM", "admin", "enroll_admin", "dashboard_users/admin", ip, "success")
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// GetCurrentUser returns the username and role of the currently logged-in user.
func (a *API) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(UsernameKey).(string)
	role, _ := r.Context().Value(RoleKey).(string)

	if username == "" {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"username": username,
		"role":     role,
		"status":   "success",
	})
}

// UpdateFindingTriage updates a finding's severity and/or workflow state.
func (a *API) UpdateFindingTriage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		ID            int64  `json:"id"`
		Severity      string `json:"severity"`
		WorkflowState string `json:"workflow_state"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if req.ID <= 0 {
		respondWithError(w, http.StatusBadRequest, "finding id is required")
		return
	}

	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}

	if err := a.db.UpdateFindingTriage(req.ID, req.Severity, req.WorkflowState); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Finding triaged successfully",
	})
}

// GetFindings returns all findings.
func (a *API) GetFindings(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		respondWithError(w, http.StatusInternalServerError, "database client is not initialized")
		return
	}

	findings, err := a.db.GetAllFindings()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, findings)
}
