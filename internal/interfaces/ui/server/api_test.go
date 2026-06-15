package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

func TestNewAPI(t *testing.T) {
	api := NewAPI(nil, "", "")

	if api == nil {
		t.Fatal("NewAPI returned nil")
	}

	if api.db != nil {
		t.Error("Expected db to be nil when passed nil")
	}
}

func TestGetStats(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()

	api.GetStats(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] == "" {
		t.Error("Expected error in response")
	}
}

func TestGetScans(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/scans", nil)
	w := httptest.NewRecorder()

	api.GetScans(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestGetEventsMissingScanID(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/events", nil)
	w := httptest.NewRecorder()

	api.GetEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] != "scan_id is required" {
		t.Errorf("Expected error 'scan_id is required', got '%s'", response["error"])
	}
}

func TestGetEventsInvalidScanID(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/events?scan_id=invalid", nil)
	w := httptest.NewRecorder()

	api.GetEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] != "invalid scan_id" {
		t.Errorf("Expected error 'invalid scan_id', got '%s'", response["error"])
	}
}

func TestGetEventsValidScanID(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/events?scan_id=123", nil)
	w := httptest.NewRecorder()

	api.GetEvents(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestRespondWithJSON(t *testing.T) {
	w := httptest.NewRecorder()

	payload := map[string]string{"message": "test"}
	respondWithJSON(w, http.StatusOK, payload)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got '%s'", w.Header().Get("Content-Type"))
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["message"] != "test" {
		t.Errorf("Expected message 'test', got '%s'", response["message"])
	}
}

func TestRespondWithError(t *testing.T) {
	w := httptest.NewRecorder()

	respondWithError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["error"] != "test error" {
		t.Errorf("Expected error 'test error', got '%s'", response["error"])
	}
}

func TestRespondWithJSONNilPayload(t *testing.T) {
	w := httptest.NewRecorder()

	respondWithJSON(w, http.StatusOK, nil)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestRespondWithJSONComplexPayload(t *testing.T) {
	w := httptest.NewRecorder()

	payload := map[string]interface{}{
		"string": "value",
		"number": 123,
		"bool":   true,
		"array":  []int{1, 2, 3},
		"nested": map[string]string{"key": "value"},
	}

	respondWithJSON(w, http.StatusOK, payload)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response["string"] != "value" {
		t.Errorf("Expected string 'value', got '%v'", response["string"])
	}
}

func TestGetEventsWithNegativeScanID(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/events?scan_id=-1", nil)
	w := httptest.NewRecorder()

	api.GetEvents(w, req)

	// Should parse as valid int64, then fail on db call
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestGetEventsWithZeroScanID(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/events?scan_id=0", nil)
	w := httptest.NewRecorder()

	api.GetEvents(w, req)

	// Should parse as valid int64, then fail on db call
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestGetEventsWithLargeScanID(t *testing.T) {
	api := NewAPI(nil, "", "")

	req := httptest.NewRequest("GET", "/api/events?scan_id=999999999999", nil)
	w := httptest.NewRecorder()

	api.GetEvents(w, req)

	// Should parse as valid int64, then fail on db call
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestGetStatsMethod(t *testing.T) {
	api := NewAPI(nil, "", "")

	// Test POST method (should still work, but typically would be GET)
	req := httptest.NewRequest("POST", "/api/stats", nil)
	w := httptest.NewRecorder()

	api.GetStats(w, req)

	// Should still return 500 due to nil db
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestGetScansMethod(t *testing.T) {
	api := NewAPI(nil, "", "")

	// Test POST method
	req := httptest.NewRequest("POST", "/api/scans", nil)
	w := httptest.NewRecorder()

	api.GetScans(w, req)

	// Should still return 500 due to nil db
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestAPIWithMockDB(t *testing.T) {
	// This would require mocking the storage.DB interface
	// For now, we just test the structure
	api := NewAPI(nil, "", "")

	if api.db != nil {
		t.Error("Expected db to be nil")
	}
}

func TestRespondWithJSONContentType(t *testing.T) {
	w := httptest.NewRecorder()

	respondWithJSON(w, http.StatusCreated, nil)

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

func TestRespondWithErrorDifferentCodes(t *testing.T) {
	codes := []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError}

	for _, code := range codes {
		w := httptest.NewRecorder()
		respondWithError(w, code, "error")

		if w.Code != code {
			t.Errorf("Expected status %d, got %d", code, w.Code)
		}
	}
}

func TestHistoricalAPI(t *testing.T) {
	api := NewAPI(nil, "", "")

	// Test GetRiskHistory
	{
		req := httptest.NewRequest("GET", "/api/history/risk?host=test.com", nil)
		w := httptest.NewRecorder()
		api.GetRiskHistory(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for GetRiskHistory, got %d", w.Code)
		}
	}

	// Test GetTechTrend
	{
		req := httptest.NewRequest("GET", "/api/history/tech?scope=default", nil)
		w := httptest.NewRecorder()
		api.GetTechTrend(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for GetTechTrend, got %d", w.Code)
		}
	}

	// Test GetOwnershipHistory missing parameter
	{
		req := httptest.NewRequest("GET", "/api/history/ownership", nil)
		w := httptest.NewRecorder()
		api.GetOwnershipHistory(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400 for GetOwnershipHistory with missing parameter, got %d", w.Code)
		}
	}

	// Test GetOwnershipHistory
	{
		req := httptest.NewRequest("GET", "/api/history/ownership?asset_id=test", nil)
		w := httptest.NewRecorder()
		api.GetOwnershipHistory(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for GetOwnershipHistory, got %d", w.Code)
		}
	}

	// Test GetAssetHistory missing parameter
	{
		req := httptest.NewRequest("GET", "/api/history/asset", nil)
		w := httptest.NewRecorder()
		api.GetAssetHistory(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400 for GetAssetHistory with missing parameter, got %d", w.Code)
		}
	}

	// Test GetAssetHistory
	{
		req := httptest.NewRequest("GET", "/api/history/asset?host=test.com", nil)
		w := httptest.NewRecorder()
		api.GetAssetHistory(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for GetAssetHistory, got %d", w.Code)
		}
	}

	// Test GetFindingHistory missing parameter
	{
		req := httptest.NewRequest("GET", "/api/history/finding", nil)
		w := httptest.NewRecorder()
		api.GetFindingHistory(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400 for GetFindingHistory with missing parameter, got %d", w.Code)
		}
	}

	// Test GetFindingHistory
	{
		req := httptest.NewRequest("GET", "/api/history/finding?target=test", nil)
		w := httptest.NewRecorder()
		api.GetFindingHistory(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for GetFindingHistory, got %d", w.Code)
		}
	}
}

func TestConfigRedaction(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "bbpts-config-test-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testConfig := `{
		"api_keys": {
			"shodan": "secret-shodan-key",
			"github": "secret-github-key"
		},
		"dashboard_token": "secret-token",
		"fleet": {
			"sync_token": "secret-sync-token"
		},
		"notify": {
			"slack_webhook": "https://hooks.slack.com/services/123/456"
		}
	}`
	if _, err := tmpFile.Write([]byte(testConfig)); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	tmpFile.Close()

	api := NewAPI(nil, tmpFile.Name(), "")
	req := httptest.NewRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()

	api.GetConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to parse body: %v", err)
	}

	apiKeys, ok := res["api_keys"].(map[string]interface{})
	if !ok {
		t.Fatal("api_keys missing or invalid in response")
	}
	if apiKeys["shodan"] != "●●●●●●●●" {
		t.Errorf("Expected shodan key to be redacted, got %v", apiKeys["shodan"])
	}
	if apiKeys["github"] != "●●●●●●●●" {
		t.Errorf("Expected github key to be redacted, got %v", apiKeys["github"])
	}

	if res["dashboard_token"] != "●●●●●●●●" {
		t.Errorf("Expected dashboard_token to be redacted, got %v", res["dashboard_token"])
	}

	fleet, ok := res["fleet"].(map[string]interface{})
	if !ok {
		t.Fatal("fleet missing or invalid in response")
	}
	if fleet["sync_token"] != "●●●●●●●●" {
		t.Errorf("Expected sync_token to be redacted, got %v", fleet["sync_token"])
	}

	notify, ok := res["notify"].(map[string]interface{})
	if !ok {
		t.Fatal("notify missing or invalid in response")
	}
	if notify["slack_webhook"] != "●●●●●●●●" {
		t.Errorf("Expected slack_webhook to be redacted, got %v", notify["slack_webhook"])
	}
}

func TestConfigUpdateSecrets(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "bbpts-config-test-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testConfig := `{
		"api_keys": {
			"shodan": "secret-shodan-key",
			"github": "secret-github-key"
		},
		"dashboard_token": "secret-token",
		"fleet": {
			"sync_token": "secret-sync-token"
		}
	}`
	if _, err := tmpFile.Write([]byte(testConfig)); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	tmpFile.Close()

	api := NewAPI(nil, tmpFile.Name(), "")

	updatePayload := `{
		"api_keys": {
			"shodan": "●●●●●●●●",
			"github": "new-github-key"
		},
		"fleet": {
			"sync_token": "●●●●●●●●"
		}
	}`

	req := httptest.NewRequest("POST", "/api/config", strings.NewReader(updatePayload))
	w := httptest.NewRecorder()

	api.UpdateConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	cfgFile, err := config.LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}

	if cfgFile.APIKeys["shodan"] != "secret-shodan-key" {
		t.Errorf("Expected shodan key to be preserved, got %s", cfgFile.APIKeys["shodan"])
	}
	if cfgFile.APIKeys["github"] != "new-github-key" {
		t.Errorf("Expected github key to be updated, got %s", cfgFile.APIKeys["github"])
	}
	if cfgFile.Fleet.SyncToken != "secret-sync-token" {
		t.Errorf("Expected fleet sync token to be preserved, got %s", cfgFile.Fleet.SyncToken)
	}
}

func TestGraphAPI(t *testing.T) {
	api := NewAPI(nil, "", "")

	// Test GetGraphNodes
	{
		req := httptest.NewRequest("GET", "/api/graph/nodes", nil)
		w := httptest.NewRecorder()
		api.GetGraphNodes(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for GetGraphNodes, got %d", w.Code)
		}
	}

	// Test GetGraphEdges
	{
		req := httptest.NewRequest("GET", "/api/graph/edges", nil)
		w := httptest.NewRecorder()
		api.GetGraphEdges(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500 for GetGraphEdges, got %d", w.Code)
		}
	}
}

func TestGetCurrentUser(t *testing.T) {
	api := NewAPI(nil, "", "")

	// Test unauthorized
	{
		req := httptest.NewRequest("GET", "/api/me", nil)
		w := httptest.NewRecorder()
		api.GetCurrentUser(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for unauthorized GetCurrentUser, got %d", w.Code)
		}
	}

	// Test authorized with context keys
	{
		req := httptest.NewRequest("GET", "/api/me", nil)
		ctx := req.Context()
		ctx = context.WithValue(ctx, UsernameKey, "admin")
		ctx = context.WithValue(ctx, RoleKey, "admin")
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		api.GetCurrentUser(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200 for authorized GetCurrentUser, got %d", w.Code)
		}

		var res map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("Failed to parse body: %v", err)
		}
		if res["username"] != "admin" || res["role"] != "admin" {
			t.Errorf("Expected user details admin, got %v", res)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	loginAttemptsMu.Lock()
	loginAttempts = make(map[string][]time.Time)
	loginAttemptsMu.Unlock()

	defer func() {
		loginAttemptsMu.Lock()
		loginAttempts = make(map[string][]time.Time)
		loginAttemptsMu.Unlock()
	}()

	api := NewAPI(nil, "", "")

	// 5 attempts should not be rate limited on the rate limiter itself
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{}`))
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		api.Authenticate(w, req)
		// It might return BadRequest since request body `{}` is invalid or empty, but it shouldn't be TooManyRequests
		if w.Code == http.StatusTooManyRequests {
			t.Errorf("Attempt %d unexpectedly rate limited", i+1)
		}
	}

	// 6th attempt should be rate limited
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{}`))
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	api.Authenticate(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 6th attempt to be rate limited (429), got %d", w.Code)
	}
}

