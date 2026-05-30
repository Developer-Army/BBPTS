package server

import (
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
	err = BootstrapAdminUser(db)
	if err != nil {
		t.Fatalf("failed to bootstrap admin user: %v", err)
	}
	defer os.Remove("admin_bootstrap.txt")

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

	// Read bootstrapped password
	data, err := os.ReadFile("admin_bootstrap.txt")
	if err != nil {
		t.Fatalf("failed to read bootstrap file: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	var password string
	for _, line := range lines {
		if strings.HasPrefix(line, "Password: ") {
			password = strings.TrimPrefix(line, "Password: ")
			break
		}
	}
	if password == "" {
		t.Fatal("password not found in bootstrap file")
	}

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
