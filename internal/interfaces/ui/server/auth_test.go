package server

import (
	"os"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func TestAuthFlow(t *testing.T) {

	db, err := storage.NewStorage("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory storage: %v", err)
	}
	defer db.Close()

	os.Setenv("BBPTS_ADMIN_PASSWORD", "testbootstrapadminpass")
	defer os.Unsetenv("BBPTS_ADMIN_PASSWORD")

	err = BootstrapAdminUser(db)
	if err != nil {
		t.Fatalf("failed to bootstrap admin user: %v", err)
	}

	rawDB := db.GetDB()
	var count int
	err = rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users WHERE username = 'admin'").Scan(&count)
	if err != nil || count != 1 {
		t.Fatalf("expected admin user to exist, got count %d, err %v", count, err)
	}

	_, err = AuthenticateUser(db, "admin", "wrongpassword")
	if err == nil {
		t.Error("expected authentication error with wrong password")
	}

	password := "testbootstrapadminpass"

	role, err := AuthenticateUser(db, "admin", password)
	if err != nil {
		t.Fatalf("failed to authenticate admin user: %v", err)
	}
	if role != "admin" {
		t.Errorf("expected role 'admin', got '%s'", role)
	}

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

	if !hasPermission("/api/config", "POST", "admin") {
		t.Error("admin should have permission to POST /api/config")
	}
	if !hasPermission("/api/stats", "GET", "admin") {
		t.Error("admin should have permission to GET /api/stats")
	}

	if hasPermission("/api/config", "POST", "operator") {
		t.Error("operator should NOT have permission to POST /api/config")
	}
	if !hasPermission("/api/config", "GET", "operator") {
		t.Error("operator should have permission to GET /api/config")
	}
	if !hasPermission("/api/stats", "GET", "operator") {
		t.Error("operator should have permission to GET /api/stats")
	}

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

	err = BootstrapAdminUser(db)
	if err != nil {
		t.Fatalf("failed to bootstrap admin user: %v", err)
	}

	rawDB := db.GetDB()
	var userCount int
	err = rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users WHERE username = 'admin'").Scan(&userCount)
	if err != nil || userCount != 1 {
		t.Fatalf("expected admin user to exist after bootstrap, got %d, err %v", userCount, err)
	}

	role, err := AuthenticateUser(db, "admin", "local-only")
	if err != nil {
		t.Fatalf("failed to authenticate with default password: %v", err)
	}
	if role != "admin" {
		t.Errorf("expected role 'admin', got '%s'", role)
	}

	err = BootstrapAdminUser(db)
	if err != nil {
		t.Fatalf("failed to re-bootstrap: %v", err)
	}
	err = rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users WHERE username = 'admin'").Scan(&userCount)
	if err != nil || userCount != 1 {
		t.Errorf("expected still 1 admin user after re-bootstrap, got %d", userCount)
	}
}
