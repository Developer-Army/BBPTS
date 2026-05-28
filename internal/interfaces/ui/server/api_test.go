package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
