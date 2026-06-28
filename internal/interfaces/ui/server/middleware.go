package server

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

// Check permissions based on path and role
func hasPermission(path string, method string, role string) bool {
	// Admin has access to everything
	if role == "admin" {
		return true
	}

	// Operator has access to everything EXCEPT writing config (POST /api/config)
	if role == "operator" {
		if path == "/api/config" && method == http.MethodPost {
			return false
		}
		return true
	}

	// Readonly has access to stats, scans, events, history, logs/stream, logout, and frontend
	if role == "readonly" {
		if path == "/api/config" {
			return false
		}
		// Deny editing or anything else that changes state
		if method != http.MethodGet && path != "/api/logout" {
			return false
		}
		return true
	}

	return false
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func authMiddleware(db *storage.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow static assets, main UI page, auth/sync, and setup-token/enroll endpoints to bypass token validation
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/api/auth" || r.URL.Path == "/api/fleet/sync" || r.URL.Path == "/api/setup-token" || r.URL.Path == "/api/enroll" {
			next.ServeHTTP(w, r)
			return
		}

		// Bypass token verification for loopback/localhost requests (local operator access)
		if isLoopback(r.RemoteAddr) {
			ctx := context.WithValue(r.Context(), UsernameKey, "local")
			ctx = context.WithValue(ctx, RoleKey, "admin")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Check auth tokens in preference order: Bearer -> X-Dashboard-Token -> Cookie
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

		if receivedToken == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "unauthorized: session token required"}`))
			return
		}

		username, role, err := ValidateSession(db, receivedToken)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "unauthorized: invalid or expired session"}`))
			return
		}

		// Enforce role-based access control (RBAC) permissions
		if !hasPermission(r.URL.Path, r.Method, role) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error": "forbidden: insufficient permissions"}`))
			return
		}

		ctx := context.WithValue(r.Context(), UsernameKey, username)
		ctx = context.WithValue(ctx, RoleKey, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data:; connect-src 'self' ws: wss:;")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

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
		}

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Dashboard-Token, X-Sync-Token")
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
