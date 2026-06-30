package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"golang.org/x/crypto/bcrypt"
)

func AuthenticateUser(db *storage.DB, username, password string) (string, error) {
	rawDB := db.GetDB()
	var storedVal, role string
	err := rawDB.QueryRow("SELECT password_hash, role FROM dashboard_users WHERE username = ?", username).Scan(&storedVal, &role)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("invalid username or password")
	} else if err != nil {
		return "", err
	}

	parts := strings.SplitN(storedVal, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid password hash format in db")
	}
	salt := parts[0]
	hash := parts[1]

	if !VerifyPassword(password, salt, hash) {
		return "", fmt.Errorf("invalid username or password")
	}

	return role, nil
}

type ContextKey string

const (
	UsernameKey ContextKey = "username"
	RoleKey     ContextKey = "role"
)

type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string // "admin", "operator", "readonly"
	CreatedAt    time.Time
}

type Session struct {
	Token     string
	Username  string
	Role      string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func GenerateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HashPassword(password, salt string) string {
	hashed, err := bcrypt.GenerateFromPassword([]byte(salt+password), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(hashed)
}

func VerifyPassword(password, salt, storedHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(salt+password))
	return err == nil
}

func BootstrapAdminUser(db *storage.DB) error {
	rawDB := db.GetDB()
	var count int
	err := rawDB.QueryRow("SELECT COUNT(*) FROM dashboard_users").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to query users count: %w", err)
	}

	if count > 0 {
		return nil
	}

	if envPassword := os.Getenv("BBPTS_ADMIN_PASSWORD"); envPassword != "" {
		salt, err := GenerateRandomString(16)
		if err != nil {
			return fmt.Errorf("failed to generate password salt: %w", err)
		}
		hash := HashPassword(envPassword, salt)
		storedValue := salt + "." + hash
		_, err = rawDB.Exec("INSERT INTO dashboard_users (username, password_hash, role) VALUES (?, ?, ?)", "admin", storedValue, "admin")
		if err != nil {
			return fmt.Errorf("failed to create bootstrap admin user: %w", err)
		}
		return nil
	}

	salt, err := GenerateRandomString(16)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	hash := HashPassword("local-only", salt)
	storedValue := salt + "." + hash
	_, _ = rawDB.Exec("INSERT INTO dashboard_users (username, password_hash, role) VALUES (?, ?, ?)", "admin", storedValue, "admin")

	return nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func ValidateSession(db *storage.DB, token string) (string, string, error) {
	rawDB := db.GetDB()
	var username, role string
	var expiresAtStr string
	hashed := hashToken(token)
	err := rawDB.QueryRow("SELECT username, role, expires_at FROM user_sessions WHERE token = ?", hashed).Scan(&username, &role, &expiresAtStr)
	if err == sql.ErrNoRows {
		return "", "", fmt.Errorf("session not found")
	} else if err != nil {
		return "", "", err
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {

		expiresAt, err = time.Parse("2006-01-02 15:04:05-07:00", expiresAtStr)
		if err != nil {
			expiresAt, err = time.Parse("2006-01-02 15:04:05", expiresAtStr)
			if err != nil {
				return "", "", fmt.Errorf("failed to parse expiry time: %w", err)
			}
		}
	}

	if time.Now().After(expiresAt) {

		_, _ = rawDB.Exec("DELETE FROM user_sessions WHERE token = ?", hashed)
		return "", "", fmt.Errorf("session expired")
	}

	return username, role, nil
}

func CreateSession(db *storage.DB, username, role string, duration time.Duration) (string, error) {
	token, err := GenerateRandomString(24)
	if err != nil {
		return "", err
	}

	hashed := hashToken(token)
	expiresAt := time.Now().Add(duration)
	rawDB := db.GetDB()

	_, _ = rawDB.Exec("DELETE FROM user_sessions WHERE username = ?", username)

	_, err = rawDB.Exec("INSERT INTO user_sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)",
		hashed, username, role, expiresAt.Format(time.RFC3339))
	if err != nil {
		return "", err
	}

	return token, nil
}

func RevokeSession(db *storage.DB, token string) error {
	rawDB := db.GetDB()
	hashed := hashToken(token)
	_, err := rawDB.Exec("DELETE FROM user_sessions WHERE token = ?", hashed)
	return err
}

func LogAuditEvent(db *storage.DB, username, role, action, resource, ip, status string) {
	rawDB := db.GetDB()
	_, err := rawDB.Exec("INSERT INTO audit_logs (username, role, action, resource, ip_address, status) VALUES (?, ?, ?, ?, ?, ?)",
		username, role, action, resource, ip, status)
	if err != nil {
		slog.Error("failed to write audit log to database", "error", err)
	}

	auditLine := fmt.Sprintf("[%s] IP=%s USER=%s ROLE=%s ACTION=%s RESOURCE=%s STATUS=%s\n",
		time.Now().Format(time.RFC3339), ip, username, role, action, resource, status)

	f, err := os.OpenFile("audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(auditLine)
	}
}
