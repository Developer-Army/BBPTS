package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func TestAuthFlow(t *testing.T) {
	// Initialize in-memory SQLite storage
	db, err := storage.NewStorage("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory storage: %v", err)
	}
	defer db.Close()

	// 1. Test BootstrapAdminUser
	os.Setenv("BBPTS_ADMIN_PASSWORD", "testbootstrapadminpass")
	defer os.Unsetenv("BBPTS_ADMIN_PASSWORD")

	err = BootstrapAdminUser(db)
	if err != nil {
		t.Fatalf("failed to bootstrap admin user: %v", err)
	}

	// Verify user exists
	rawDB := db.GetDB()
	var count int
	err = rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users WHERE username = 'admin'").Scan(&count)
	if err != nil || count != 1 {
		t.Fatalf("expected admin user to exist, got count %d, err %v", count, err)
	}

	// 2. Test AuthenticateUser with wrong password
	_, err = AuthenticateUser(db, "admin", "wrongpassword")
	if err == nil {
		t.Error("expected authentication error with wrong password")
	}

	password := "testbootstrapadminpass"

	// Test AuthenticateUser with correct password
	role, err := AuthenticateUser(db, "admin", password)
	if err != nil {
		t.Fatalf("failed to authenticate admin user: %v", err)
	}
	if role != "admin" {
		t.Errorf("expected role 'admin', got '%s'", role)
	}

	// 3. Test CreateSession and ValidateSession
	token, err := CreateSession(db, "admin", "admin", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty session token")
	}

	username, sessionRole, err := ValidateSession(db, token)
	if err != nil {
		t.Fatalf("failed to validate session: %v", err)
	}
	if username != "admin" || sessionRole != "admin" {
		t.Errorf("expected username 'admin' and role 'admin', got '%s'/'%s'", username, sessionRole)
	}

	// Test RevokeSession
	err = RevokeSession(db, token)
	if err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}

	_, _, err = ValidateSession(db, token)
	if err == nil {
		t.Error("expected validation to fail for revoked session")
	}
}

func TestHasPermission(t *testing.T) {
	// Admin permissions
	if !hasPermission("/api/config", "POST", "admin") {
		t.Error("admin should have permission to POST /api/config")
	}
	if !hasPermission("/api/stats", "GET", "admin") {
		t.Error("admin should have permission to GET /api/stats")
	}

	// Operator permissions
	if hasPermission("/api/config", "POST", "operator") {
		t.Error("operator should NOT have permission to POST /api/config")
	}
	if !hasPermission("/api/config", "GET", "operator") {
		t.Error("operator should have permission to GET /api/config")
	}
	if !hasPermission("/api/stats", "GET", "operator") {
		t.Error("operator should have permission to GET /api/stats")
	}

	// Readonly permissions
	if hasPermission("/api/config", "GET", "readonly") {
		t.Error("readonly should NOT have permission to GET /api/config")
	}
	if hasPermission("/api/stats", "POST", "readonly") {
		t.Error("readonly should NOT have permission to POST /api/stats")
	}
	if !hasPermission("/api/stats", "GET", "readonly") {
		t.Error("readonly should have permission to GET /api/stats")
	}
	if !hasPermission("/api/logout", "POST", "readonly") {
		t.Error("readonly should have permission to POST /api/logout")
	}
}

func TestEnrollmentFlow(t *testing.T) {
	db, err := storage.NewStorage("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory storage: %v", err)
	}
	defer db.Close()

	// 1. Bootstrap without env password should generate setup token
	err = BootstrapAdminUser(db)
	if err != nil {
		t.Fatalf("failed to bootstrap admin user: %v", err)
	}

	// Verify setup token exists in database
	rawDB := db.GetDB()
	var token string
	err = rawDB.QueryRow("SELECT token FROM setup_tokens LIMIT 1").Scan(&token)
	if err != nil {
		t.Fatalf("expected setup token to exist in db: %v", err)
	}
	if len(token) != 64 { // hex-encoded 32 bytes = 64 characters
		t.Errorf("expected setup token of length 64, got %d", len(token))
	}

	// 2. Test API handlers
	api := NewAPI(db, "", "")

	// GetSetupToken from non-localhost IP should be forbidden
	reqLocalForbidden := httptest.NewRequest("GET", "/api/setup-token", nil)
	reqLocalForbidden.RemoteAddr = "192.168.1.50:1234"
	w1 := httptest.NewRecorder()
	api.GetSetupToken(w1, reqLocalForbidden)
	if w1.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden from remote IP, got %d", w1.Code)
	}

	// GetSetupToken from localhost should return setup token
	reqLocalSuccess := httptest.NewRequest("GET", "/api/setup-token", nil)
	reqLocalSuccess.RemoteAddr = "127.0.0.1:1234"
	w2 := httptest.NewRecorder()
	api.GetSetupToken(w2, reqLocalSuccess)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 OK from localhost, got %d", w2.Code)
	}

	// 3. Test EnrollAdmin from remote IP should be forbidden
	bodyRemote := strings.NewReader(`{"token": "invalid_token", "password": "newpassword123"}`)
	reqEnrollRemote := httptest.NewRequest("POST", "/api/enroll", bodyRemote)
	reqEnrollRemote.RemoteAddr = "192.168.1.50:1234"
	wRemote := httptest.NewRecorder()
	api.EnrollAdmin(wRemote, reqEnrollRemote)
	if wRemote.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden from remote IP for EnrollAdmin, got %d", wRemote.Code)
	}

	// Test EnrollAdmin with invalid token on localhost
	bodyInvalid := strings.NewReader(`{"token": "invalid_token", "password": "newpassword123"}`)
	reqEnrollInvalid := httptest.NewRequest("POST", "/api/enroll", bodyInvalid)
	reqEnrollInvalid.RemoteAddr = "127.0.0.1:1234"
	w3 := httptest.NewRecorder()
	api.EnrollAdmin(w3, reqEnrollInvalid)
	if w3.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for invalid setup token on localhost, got %d", w3.Code)
	}

	// Test EnrollAdmin with valid token
	bodyValid := strings.NewReader(fmt.Sprintf(`{"token": "%s", "password": "securepassword123"}`, token))
	reqEnrollValid := httptest.NewRequest("POST", "/api/enroll", bodyValid)
	reqEnrollValid.RemoteAddr = "127.0.0.1:1234"
	w4 := httptest.NewRecorder()
	api.EnrollAdmin(w4, reqEnrollValid)
	if w4.Code != http.StatusOK {
		t.Errorf("expected 200 OK for valid setup token, got %d. Body: %s", w4.Code, w4.Body.String())
	}

	// Verify admin user exists now
	var userCount int
	err = rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users WHERE username = 'admin'").Scan(&userCount)
	if err != nil || userCount != 1 {
		t.Fatalf("expected admin user to exist after enrollment, got %d, err %v", userCount, err)
	}

	// Verify setup token is deleted
	var tokenCount int
	err = rawDB.QueryRow("SELECT COUNT(*) FROM setup_tokens").Scan(&tokenCount)
	if err != nil || tokenCount != 0 {
		t.Errorf("expected setup token to be deleted, got count %d, err %v", tokenCount, err)
	}
}
