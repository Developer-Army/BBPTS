package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/security"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

//go:embed static/*
var staticFS embed.FS

// Config holds the web server configuration.
type Config struct {
	Port        int
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
}

// LogBroadcasterWriter multiplexes logs to original writer and dashboard clients.
type LogBroadcasterWriter struct {
	Original io.Writer
}

func (lw *LogBroadcasterWriter) Write(p []byte) (n int, err error) {
	redactedStr := security.RedactSecrets(string(p))
	redactedBytes := []byte(redactedStr)
	_, err = lw.Original.Write(redactedBytes)
	BroadcastLog(redactedStr)
	return len(p), err
}

var (
	logMu      sync.RWMutex
	logClients = make(map[chan string]bool)
)

func RegisterLogClient(c chan string) {
	logMu.Lock()
	defer logMu.Unlock()
	logClients[c] = true
}

func UnregisterLogClient(c chan string) {
	logMu.Lock()
	defer logMu.Unlock()
	delete(logClients, c)
}

func BroadcastLog(msg string) {
	logMu.RLock()
	defer logMu.RUnlock()
	for c := range logClients {
		select {
		case c <- msg:
		default:
		}
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"BBPTS Ingest Authority"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var cert tls.Certificate
	cert.Certificate = append(cert.Certificate, derBytes)
	cert.PrivateKey = priv

	return cert, nil
}

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

func authMiddleware(db *storage.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow static assets, main UI page, auth/sync, and setup-token/enroll endpoints to bypass token validation
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/api/auth" || r.URL.Path == "/api/fleet/sync" || r.URL.Path == "/api/setup-token" || r.URL.Path == "/api/enroll" {
			next.ServeHTTP(w, r)
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
			w.Write([]byte(`{"error": "unauthorized: session token required"}`))
			return
		}

		username, role, err := ValidateSession(db, receivedToken)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized: invalid or expired session"}`))
			return
		}

		// Enforce role-based access control (RBAC) permissions
		if !hasPermission(r.URL.Path, r.Method, role) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "forbidden: insufficient permissions"}`))
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

// Start launches the BBPTS dashboard server on the specified port.
func Start(cfg Config, db *storage.DB, configPath string, masterDBPath string) error {
	if db == nil {
		return fmt.Errorf("database client is required")
	}

	// Bootstrap default admin user
	if err := BootstrapAdminUser(db); err != nil {
		slog.Error("failed to bootstrap admin user", "error", err)
	}

	api := NewAPI(db, configPath, masterDBPath)

	mux := http.NewServeMux()

	// Static Assets
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))

	// API Routes
	mux.HandleFunc("/api/auth", api.Authenticate)
	mux.HandleFunc("/api/logout", api.Logout)
	mux.HandleFunc("/api/me", api.GetCurrentUser)
	mux.HandleFunc("/api/stats", api.GetStats)
	mux.HandleFunc("/api/scans", api.GetScans)
	mux.HandleFunc("/api/events", api.GetEvents)
	mux.HandleFunc("/api/config", api.HandleConfig)
	mux.HandleFunc("/api/logs/stream", api.StreamLogs)
	mux.HandleFunc("/api/fleet/sync", api.HandleFleetSync)
	mux.HandleFunc("/api/setup-token", api.GetSetupToken)
	mux.HandleFunc("/api/enroll", api.EnrollAdmin)
	mux.HandleFunc("/api/history/risk", api.GetRiskHistory)
	mux.HandleFunc("/api/history/tech", api.GetTechTrend)
	mux.HandleFunc("/api/history/ownership", api.GetOwnershipHistory)
	mux.HandleFunc("/api/history/asset", api.GetAssetHistory)
	mux.HandleFunc("/api/history/finding", api.GetFindingHistory)
	mux.HandleFunc("/api/graph/nodes", api.GetGraphNodes)
	mux.HandleFunc("/api/graph/edges", api.GetGraphEdges)
	mux.HandleFunc("/api/findings/triage", api.UpdateFindingTriage)
	mux.HandleFunc("/api/findings", api.GetFindings)

	// Static Frontend (Embedded or simply served from a string for now)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(DashboardHTML)); err != nil {
			slog.Warn("failed to write dashboard html", "error", err)
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)

	handler := securityHeadersMiddleware(authMiddleware(db, mux))

	if cfg.TLSEnabled {
		slog.Info("dashboard server starting with TLS", "addr", "https://"+addr)
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			return http.ListenAndServeTLS(addr, cfg.TLSCertFile, cfg.TLSKeyFile, handler)
		}

		cert, err := generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed to generate self-signed cert: %w", err)
		}
		slog.Info("using generated self-signed certificate for HTTPS")
		server := &http.Server{
			Addr:    addr,
			Handler: handler,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		return server.ListenAndServeTLS("", "")
	}

	slog.Info("dashboard server starting", "addr", "http://"+addr)
	return http.ListenAndServe(addr, handler)
}

// DashboardHTML is the embedded frontend for the BBPTS elite dashboard.
const DashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BBPTS | Mission Control</title>
    <!-- tailwindcss self-hosted -->
    <script src="/static/tailwind.js"></script>
    <script src="/static/chart.js"></script>
    <style>
        body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; background-color: #0b0e14; color: #f8fafc; margin: 0; overflow-x: hidden; }
        .glass { background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.05); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3); }
        .accent-purple { color: #bd93f9; }
        .bg-accent-purple { background-color: #bd93f9; }
        .glow-critical { box-shadow: 0 0 15px rgba(255, 85, 85, 0.3); border: 1px solid rgba(255, 85, 85, 0.5); }
        .glow-high { box-shadow: 0 0 15px rgba(255, 184, 108, 0.3); border: 1px solid rgba(255, 184, 108, 0.5); }
        .sidebar { width: 260px; border-right: 1px solid rgba(255, 255, 255, 0.05); }
        .nav-item { transition: all 0.2s; border-left: 3px solid transparent; cursor: pointer; }
        .nav-item:hover { background: rgba(189, 147, 249, 0.1); border-left-color: #bd93f9; }
        .nav-active { background: rgba(189, 147, 249, 0.15); border-left-color: #bd93f9; color: #bd93f9; }
        .panel { display: none; }
        .panel-active { display: block; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: rgba(0,0,0,0.1); }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
    </style>
</head>
<body class="flex h-screen">
    <!-- Sidebar -->
    <aside class="sidebar glass flex flex-col p-6 shrink-0">
        <div class="mb-10 px-2">
            <h1 class="text-2xl font-bold tracking-tighter"><span class="accent-purple">BBPTS</span><span class="text-slate-500 font-light">.io</span></h1>
            <p class="text-[10px] text-slate-500 uppercase tracking-widest mt-1">Elite Recon Engine</p>
        </div>
        
        <nav class="flex-grow space-y-1">
            <a onclick="switchTab('dashboard')" id="nav-dashboard" class="nav-item nav-active flex items-center gap-3 p-3 rounded-lg text-sm font-medium">
                <span>Dashboard</span>
            </a>
            <a onclick="switchTab('config')" id="nav-config" class="nav-item flex items-center gap-3 p-3 rounded-lg text-sm font-medium text-slate-400">
                <span>Config Editor</span>
            </a>
            <a onclick="switchTab('logs')" id="nav-logs" class="nav-item flex items-center gap-3 p-3 rounded-lg text-sm font-medium text-slate-400">
                <span>Console Logs</span>
            </a>
            <a onclick="switchTab('triage')" id="nav-triage" class="nav-item flex items-center gap-3 p-3 rounded-lg text-sm font-medium text-slate-400">
                <span>Triage Center</span>
            </a>

        </nav>

        <div class="mt-auto pt-6 border-t border-slate-800/50">
            <div class="flex items-center gap-3 px-2 mb-4">
                <div class="w-8 h-8 rounded-full bg-accent-purple/20 flex items-center justify-center text-accent-purple text-xs font-bold" id="user-avatar">DA</div>
                <div>
                    <p class="text-xs font-semibold" id="user-display-name">Developer-Army</p>
                    <p class="text-[10px] text-slate-500 uppercase" id="user-display-role">Operator</p>
                </div>
            </div>
            <button onclick="logout()" class="w-full bg-slate-800/60 hover:bg-slate-800 text-slate-400 hover:text-rose-400 py-1.5 rounded-lg text-xs font-medium transition-colors border border-slate-800">Logout</button>
        </div>
    </aside>

    <!-- Main Content -->
    <div class="flex-grow overflow-y-auto bg-[#0b0e14] relative">
        <!-- Dashboard Panel -->
        <div id="panel-dashboard" class="panel panel-active">
            <header class="p-8 pb-4 flex justify-between items-start">
                <div>
                    <h2 class="text-3xl font-semibold tracking-tight">Mission Control</h2>
                    <p class="text-slate-400 text-sm mt-1">System operational. Monitoring attack surface telemetry.</p>
                </div>
                <button class="glass px-4 py-2 rounded-lg text-xs font-semibold hover:bg-slate-800 transition">Deploy Scanner</button>
            </header>

            <main class="p-8 pt-4">
                <!-- Stats Grid -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                    <div class="glass p-6 rounded-2xl relative overflow-hidden">
                        <h3 class="text-slate-400 text-[10px] uppercase tracking-widest font-bold mb-1">Total Targets</h3>
                        <p id="stat-targets" class="text-3xl font-bold">0</p>
                        <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-blue-500/10 rounded-full blur-xl"></div>
                    </div>
                    <div class="glass p-6 rounded-2xl relative overflow-hidden">
                        <h3 class="text-slate-400 text-[10px] uppercase tracking-widest font-bold mb-1">Active Scans</h3>
                        <p id="stat-scans" class="text-3xl font-bold">0</p>
                        <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-purple-500/10 rounded-full blur-xl"></div>
                    </div>
                    <div class="glass p-6 rounded-2xl relative overflow-hidden glow-critical">
                        <h3 class="text-rose-400 text-[10px] uppercase tracking-widest font-bold mb-1">Critical Vulns</h3>
                        <p id="stat-critical" class="text-3xl font-bold text-rose-500">0</p>
                        <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-rose-500/10 rounded-full blur-xl"></div>
                    </div>
                    <div class="glass p-6 rounded-2xl relative overflow-hidden">
                        <h3 class="text-emerald-400 text-[10px] uppercase tracking-widest font-bold mb-1">Fleet Health</h3>
                        <p class="text-3xl font-bold text-emerald-400">98%</p>
                        <div class="absolute -right-4 -bottom-4 w-16 h-16 bg-emerald-500/10 rounded-full blur-xl"></div>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    <!-- Findings Table -->
                    <div class="lg:col-span-2 glass p-6 rounded-2xl">
                        <div class="flex justify-between items-center mb-6">
                            <h3 class="text-lg font-semibold tracking-tight">Recent Scans</h3>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="w-full text-left">
                                <thead>
                                    <tr class="text-slate-500 text-[10px] uppercase tracking-widest border-b border-slate-800/50">
                                        <th class="pb-4 font-medium">Scope</th>
                                        <th class="pb-4 font-medium">Status</th>
                                        <th class="pb-4 font-medium">Time</th>
                                    </tr>
                                </thead>
                                <tbody id="scan-history" class="divide-y divide-slate-800/50">
                                    <!-- Data injected here -->
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Chart -->
                    <div class="glass p-6 rounded-2xl">
                        <h3 class="text-lg font-semibold tracking-tight mb-6">Attack Surface</h3>
                        <div class="relative h-[250px] flex items-center justify-center">
                            <canvas id="surface-chart"></canvas>
                        </div>
                    </div>
                </div>
            </main>
        </div>

        <!-- Config Editor Panel -->
        <div id="panel-config" class="panel">
            <header class="p-8 pb-4">
                <h2 class="text-3xl font-semibold tracking-tight">Configuration Editor</h2>
                <p class="text-slate-400 text-sm mt-1">Read and update BBPTS global engine settings.</p>
            </header>

            <main class="p-8 pt-4">
                <form id="config-form" class="space-y-8 max-w-4xl" onsubmit="event.preventDefault(); saveConfig();">
                    <!-- Container Mode Toggle -->
                    <div class="glass p-6 rounded-2xl flex items-center justify-between">
                        <div>
                            <h3 class="text-base font-semibold text-slate-200">Docker Tool Isolation (Container Mode)</h3>
                            <p class="text-xs text-slate-400 mt-1">Run active/passive scanners inside secure docker containers instead of locally.</p>
                        </div>
                        <label class="relative inline-flex items-center cursor-pointer">
                            <input type="checkbox" id="cfg-container-mode" class="sr-only peer">
                            <div class="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                        </label>
                    </div>

                    <!-- API Keys -->
                    <div class="glass p-6 rounded-2xl space-y-4">
                        <h3 class="text-lg font-semibold text-purple-400 border-b border-slate-800 pb-2">Provider API Keys</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4" id="api-keys-container">
                            <!-- Injected dynamically -->
                        </div>
                    </div>

                    <!-- Scan Settings -->
                    <div class="glass p-6 rounded-2xl space-y-4">
                        <h3 class="text-lg font-semibold text-purple-400 border-b border-slate-800 pb-2">Scan Parameters</h3>
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Global Rate Limit (RPS)</label>
                                <input type="number" id="cfg-rate-limit" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Threads</label>
                                <input type="number" id="cfg-threads" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Batch Size</label>
                                <input type="number" id="cfg-batch-size" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Wordlists Directory</label>
                                <input type="text" id="cfg-wordlists-dir" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">State Directory</label>
                                <input type="text" id="cfg-state-dir" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                        </div>
                    </div>

                    <!-- Wordlist Mapping -->
                    <div class="glass p-6 rounded-2xl space-y-4">
                        <h3 class="text-lg font-semibold text-purple-400 border-b border-slate-800 pb-2">Wordlist Assignments</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">DNS Enumeration</label>
                                <input type="text" id="cfg-wl-dns" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Directory Fuzzing</label>
                                <input type="text" id="cfg-wl-dir" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Subdomain Brute</label>
                                <input type="text" id="cfg-wl-subdomain" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">API Endpoints</label>
                                <input type="text" id="cfg-wl-api" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                        </div>
                    </div>

                    <!-- Fleet Security -->
                    <div class="glass p-6 rounded-2xl space-y-4">
                        <h3 class="text-lg font-semibold text-purple-400 border-b border-slate-800 pb-2">Fleet Sync Settings</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Fleet Sync Token (X-Sync-Token)</label>
                                <input type="text" id="cfg-fleet-sync-token" placeholder="Secure token for merging node SQLite DBs" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                            </div>
                        </div>
                    </div>

                    <!-- Submit Buttons -->
                    <div class="flex gap-4">
                        <button type="submit" class="bg-purple-600 text-white px-6 py-2.5 rounded-lg font-semibold text-sm hover:bg-purple-700 transition-colors">Save Settings</button>
                        <button type="button" onclick="loadConfig()" class="bg-slate-800 text-slate-300 px-6 py-2.5 rounded-lg font-semibold text-sm hover:bg-slate-700 transition-colors">Discard Changes</button>
                    </div>
                </form>
            </main>
        </div>

        <!-- Console Logs Panel -->
        <div id="panel-logs" class="panel">
            <header class="p-8 pb-4 flex justify-between items-center">
                <div>
                    <h2 class="text-3xl font-semibold tracking-tight">Console Stream</h2>
                    <p class="text-slate-400 text-sm mt-1">Real-time output logs of current active tasks.</p>
                </div>
                <div class="flex items-center gap-3">
                    <span id="log-status" class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/10 text-amber-400">Connecting</span>
                    <button onclick="clearLogs()" class="bg-slate-800 text-xs text-slate-300 px-3 py-1.5 rounded-lg hover:bg-slate-700 transition-colors">Clear Console</button>
                    <label class="flex items-center gap-2 text-xs text-slate-400">
                        <input type="checkbox" id="log-autoscroll" checked class="accent-purple"> Auto-Scroll
                    </label>
                </div>
            </header>

            <main class="px-8 pb-8">
                <div id="log-terminal" class="bg-black/80 font-mono text-xs text-emerald-400/90 p-6 rounded-2xl h-[calc(100vh-210px)] overflow-y-auto border border-slate-800/80 shadow-2xl leading-relaxed whitespace-pre-wrap">
                    <!-- Logs stream here -->
                </div>
            </main>
        </div>

        <!-- Triage Center Panel -->
        <div id="panel-triage" class="panel">
            <header class="p-8 pb-4">
                <h2 class="text-3xl font-semibold tracking-tight">Triage Center</h2>
                <p class="text-slate-400 text-sm mt-1">Review, override severity, and transition findings workflow state.</p>
            </header>

            <main class="p-8 pt-4">
                <div class="glass p-6 rounded-2xl">
                    <div class="overflow-x-auto">
                        <table class="w-full text-left">
                            <thead>
                                <tr class="text-slate-500 text-[10px] uppercase tracking-widest border-b border-slate-800/50">
                                    <th class="pb-4 font-medium">Target / Title</th>
                                    <th class="pb-4 font-medium">Severity</th>
                                    <th class="pb-4 font-medium">Workflow State</th>
                                    <th class="pb-4 font-medium">Override Actions</th>
                                </tr>
                            </thead>
                            <tbody id="triage-findings-body" class="divide-y divide-slate-800/50">
                                <!-- Populated dynamically -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </main>
        </div>
    </div>


    <!-- Login Modal -->
    <div id="login-modal" class="fixed inset-0 bg-black/90 flex items-center justify-center z-50 hidden">
        <div class="glass p-8 rounded-2xl w-full max-w-md border border-slate-800 text-center animate-fade-in">
            <h1 class="text-2xl font-bold tracking-tighter mb-2"><span class="accent-purple">BBPTS</span><span class="text-slate-500 font-light">.io</span></h1>
            <p class="text-slate-400 text-xs uppercase tracking-wider mb-6">Mission Control Access</p>
            <input type="text" id="login-username" placeholder="Username" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none mb-4 text-center text-slate-200">
            <input type="password" id="login-password" placeholder="Password" class="w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none mb-4 text-center text-slate-200">
            <button onclick="submitLogin()" class="w-full bg-purple-600 text-white py-2.5 rounded-lg font-semibold text-sm hover:bg-purple-700 transition-colors">Authenticate</button>
            <p id="login-error" class="text-rose-500 text-xs mt-3 hidden"></p>
        </div>
    </div>

    <script>
        let currentUser = null;

        async function fetchAPI(url, options = {}) {
            const response = await fetch(url, options);
            if (response.status === 401) {
                document.getElementById('login-modal').classList.remove('hidden');
                throw new Error('Unauthorized');
            }
            return response;
        }

        async function checkAuth() {
            try {
                const response = await fetch('/api/me');
                if (response.ok) {
                    const data = await response.json();
                    currentUser = data;
                    document.getElementById('login-modal').classList.add('hidden');
                    updateUserUI();
                    refreshData();
                    startLogStream();
                } else {
                    document.getElementById('login-modal').classList.remove('hidden');
                }
            } catch (e) {
                document.getElementById('login-modal').classList.remove('hidden');
            }
        }

        async function submitLogin() {
            const userVal = document.getElementById('login-username').value;
            const passVal = document.getElementById('login-password').value;
            const errEl = document.getElementById('login-error');
            errEl.classList.add('hidden');
            try {
                const response = await fetch('/api/auth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: userVal, password: passVal })
                });
                if (response.ok) {
                    document.getElementById('login-modal').classList.add('hidden');
                    await checkAuth();
                } else {
                    const data = await response.json();
                    errEl.innerText = data.error || 'Authentication failed';
                    errEl.classList.remove('hidden');
                }
            } catch (e) {
                errEl.innerText = 'Network error: ' + e.message;
                errEl.classList.remove('hidden');
            }
        }

        async function logout() {
            try {
                await fetchAPI('/api/logout', { method: 'POST' });
            } catch (e) {
                console.error(e);
            }
            currentUser = null;
            document.getElementById('login-modal').classList.remove('hidden');
        }

        function updateUserUI() {
            const username = (currentUser && currentUser.username) || 'Guest';
            const role = (currentUser && currentUser.role) || 'Unknown';
            document.getElementById('user-display-name').innerText = username;
            document.getElementById('user-display-role').innerText = role.toUpperCase() + ' OPERATOR';
            if (username && username.length > 0) {
                document.getElementById('user-avatar').innerText = username.substring(0, 2).toUpperCase();
            }
        }

        function switchTab(tabId) {
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('panel-active'));
            document.querySelectorAll('.nav-item').forEach(n => {
                n.classList.remove('nav-active');
                n.classList.add('text-slate-400');
            });

            document.getElementById('panel-' + tabId).classList.add('panel-active');
            const navLink = document.getElementById('nav-' + tabId);
            navLink.classList.add('nav-active');
            navLink.classList.remove('text-slate-400');

            if (tabId === 'config') {
                loadConfig();
            }
            if (tabId === 'triage') {
                loadFindings();
            }
        }

        async function refreshData() {
            try {
                const [statsResp, scansResp] = await Promise.all([
                    fetchAPI('/api/stats'),
                    fetchAPI('/api/scans')
                ]);
                
                const stats = await statsResp.json();
                const scans = await scansResp.json();
                
                document.getElementById('stat-targets').innerText = stats.total_targets.toLocaleString();
                document.getElementById('stat-scans').innerText = stats.total_scans;
                document.getElementById('stat-critical').innerText = stats.critical_vulns;
                
                const tbody = document.getElementById('scan-history');
                tbody.innerHTML = scans.slice(0, 5).map(s => ` + "`" + `
                    <tr class="hover:bg-slate-800/30 transition-colors">
                        <td class="py-4">
                            <p class="text-sm font-semibold">${s.scope}</p>
                            <p class="text-[10px] text-slate-500">SCAN_ID: #${s.id}</p>
                        </td>
                        <td class="py-4">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${s.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}">
                                ${s.status}
                            </span>
                        </td>
                        <td class="py-4 text-slate-400 text-[10px] uppercase">${new Date(s.start_time).toLocaleTimeString()}</td>
                    </tr>
                ` + "`" + `).join('');

                initChart();
            } catch (e) { console.error(e); }
        }

        let chart = null;
        function initChart() {
            const ctx = document.getElementById('surface-chart').getContext('2d');
            if (chart) chart.destroy();
            chart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Subdomains', 'Cloud', 'Exposures', 'Other'],
                    datasets: [{
                        data: [45, 28, 12, 15],
                        backgroundColor: ['#bd93f9', '#8be9fd', '#ff5555', '#44475a'],
                        hoverOffset: 10,
                        borderWidth: 0
                    }]
                },
                options: {
                    cutout: '80%',
                    plugins: { legend: { display: false } },
                    maintainAspectRatio: false
                }
            });
        }

        // --- Log Streaming ---
        let eventSource = null;
        function startLogStream() {
            if (eventSource) {
                eventSource.close();
            }
            const statusIndicator = document.getElementById('log-status');
            const terminal = document.getElementById('log-terminal');
            eventSource = new EventSource('/api/logs/stream');

            eventSource.onopen = () => {
                statusIndicator.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400';
                statusIndicator.innerText = 'Connected';
            };

            eventSource.onerror = (e) => {
                statusIndicator.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/10 text-rose-400';
                statusIndicator.innerText = 'Disconnected';
            };

            eventSource.onmessage = (event) => {
                const line = document.createElement('div');
                line.textContent = event.data;
                terminal.appendChild(line);

                if (document.getElementById('log-autoscroll').checked) {
                    terminal.scrollTop = terminal.scrollHeight;
                }
            };
        }

        function clearLogs() {
            document.getElementById('log-terminal').innerHTML = '';
        }

        // --- Configuration Management ---
        let currentRawConfig = null;

        async function loadConfig() {
            try {
                const response = await fetchAPI('/api/config');
                const cfg = await response.json();
                currentRawConfig = cfg;

                // Set container mode toggle
                document.getElementById('cfg-container-mode').checked = !!cfg.container_mode;

                // Load basic fields
                document.getElementById('cfg-rate-limit').value = cfg.rate_limit || 0;
                document.getElementById('cfg-threads').value = cfg.threads || 0;
                document.getElementById('cfg-batch-size').value = cfg.batch_size || 0;
                document.getElementById('cfg-wordlists-dir').value = cfg.wordlists_dir || '';
                document.getElementById('cfg-state-dir').value = cfg.state_dir || '';

                // Load wordlists
                if (cfg.wordlists) {
                    document.getElementById('cfg-wl-dns').value = cfg.wordlists.dns || '';
                    document.getElementById('cfg-wl-dir').value = cfg.wordlists.directory || '';
                    document.getElementById('cfg-wl-subdomain').value = cfg.wordlists.subdomain || '';
                    document.getElementById('cfg-wl-api').value = cfg.wordlists.api || '';
                }

                // Load fleet sync token
                if (cfg.fleet) {
                    document.getElementById('cfg-fleet-sync-token').value = cfg.fleet.sync_token || '';
                }

                // Dynamically build API key inputs
                const apiKeysContainer = document.getElementById('api-keys-container');
                apiKeysContainer.innerHTML = '';
                const providers = ['shodan', 'censys', 'securitytrails', 'github', 'chaos', 'virustotal', 'passivetotal', 'binaryedge'];
                const keys = cfg.api_keys || {};
                
                providers.forEach(p => {
                    const div = document.createElement('div');
                    div.innerHTML = ` + "`" + `
                        <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">${p}</label>
                        <input type="password" data-provider="${p}" value="${keys[p] || ''}" class="cfg-api-key w-full bg-[#0b0e14]/50 border border-slate-800 rounded-lg p-2.5 text-sm focus:border-purple-600 focus:outline-none">
                    ` + "`" + `;
                    apiKeysContainer.appendChild(div);
                });
            } catch (e) {
                console.error('Error loading configuration: ', e);
            }
        }

        async function saveConfig() {
            if (!currentRawConfig) return;

            // Merge form values back to currentRawConfig
            currentRawConfig.container_mode = document.getElementById('cfg-container-mode').checked;
            currentRawConfig.rate_limit = parseInt(document.getElementById('cfg-rate-limit').value, 10) || 0;
            currentRawConfig.threads = parseInt(document.getElementById('cfg-threads').value, 10) || 0;
            currentRawConfig.batch_size = parseInt(document.getElementById('cfg-batch-size').value, 10) || 0;
            currentRawConfig.wordlists_dir = document.getElementById('cfg-wordlists-dir').value;
            currentRawConfig.state_dir = document.getElementById('cfg-state-dir').value;

            if (!currentRawConfig.wordlists) currentRawConfig.wordlists = {};
            currentRawConfig.wordlists.dns = document.getElementById('cfg-wl-dns').value;
            currentRawConfig.wordlists.directory = document.getElementById('cfg-wl-dir').value;
            currentRawConfig.wordlists.subdomain = document.getElementById('cfg-wl-subdomain').value;
            currentRawConfig.wordlists.api = document.getElementById('cfg-wl-api').value;

            if (!currentRawConfig.fleet) currentRawConfig.fleet = {};
            currentRawConfig.fleet.sync_token = document.getElementById('cfg-fleet-sync-token').value;

            if (!currentRawConfig.api_keys) currentRawConfig.api_keys = {};
            document.querySelectorAll('.cfg-api-key').forEach(input => {
                const provider = input.getAttribute('data-provider');
                currentRawConfig.api_keys[provider] = input.value;
            });

            try {
                const response = await fetchAPI('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(currentRawConfig)
                });
                
                const result = await response.json();
                if (response.ok) {
                    alert('Configuration saved successfully!');
                } else {
                    throw new Error(result.error || 'Failed to save');
                }
            } catch (e) {
                alert('Error saving configuration: ' + e.message);
            }
        }

        async function loadFindings() {
            try {
                const response = await fetchAPI('/api/findings');
                const findings = await response.json();
                const tbody = document.getElementById('triage-findings-body');
                tbody.innerHTML = '';
                if (!findings || findings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-slate-500">No findings registered yet.</td></tr>';
                    return;
                }
                findings.forEach(f => {
                    const tr = document.createElement('tr');
                    tr.className = 'hover:bg-slate-800/30 transition-colors border-b border-slate-800/50';
                    tr.innerHTML = ` + "`" + `
                        <td class="py-4 pr-4">
                            <p class="text-sm font-semibold text-slate-200">${f.target || 'N/A'}</p>
                            <p class="text-xs text-slate-400 mt-0.5">${f.title || 'N/A'}</p>
                            <p class="text-[10px] text-slate-500 mt-1">${f.description || ''}</p>
                        </td>
                        <td class="py-4">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${getSeverityClass(f.severity)}">
                                ${f.severity || 'info'}
                            </span>
                        </td>
                        <td class="py-4">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                                ${f.workflow_state || 'Discovered'}
                            </span>
                        </td>
                        <td class="py-4">
                            <div class="flex gap-2 items-center">
                                <select id="sev-${f.id}" class="bg-[#0b0e14]/80 border border-slate-700 rounded p-1 text-xs text-slate-200 focus:outline-none focus:border-purple-600">
                                    <option value="critical" ${f.severity === 'critical' ? 'selected' : ''}>Critical</option>
                                    <option value="high" ${f.severity === 'high' ? 'selected' : ''}>High</option>
                                    <option value="medium" ${f.severity === 'medium' ? 'selected' : ''}>Medium</option>
                                    <option value="low" ${f.severity === 'low' ? 'selected' : ''}>Low</option>
                                    <option value="info" ${f.severity === 'info' ? 'selected' : ''}>Info</option>
                                </select>
                                <select id="state-${f.id}" class="bg-[#0b0e14]/80 border border-slate-700 rounded p-1 text-xs text-slate-200 focus:outline-none focus:border-purple-600">
                                    <option value="Discovered" ${f.workflow_state === 'Discovered' ? 'selected' : ''}>Discovered</option>
                                    <option value="Triaged" ${f.workflow_state === 'Triaged' ? 'selected' : ''}>Triaged</option>
                                    <option value="Remediating" ${f.workflow_state === 'Remediating' ? 'selected' : ''}>Remediating</option>
                                    <option value="SLA Exception" ${f.workflow_state === 'SLA Exception' ? 'selected' : ''}>SLA Exception</option>
                                </select>
                                <button onclick="overrideFindingTriage(${f.id})" class="bg-purple-600 hover:bg-purple-700 text-white font-semibold text-xs px-2.5 py-1.5 rounded transition">Override</button>
                            </div>
                        </td>
                    ` + "`" + `;
                    tbody.appendChild(tr);
                });
            } catch (e) {
                console.error('Error loading findings: ', e);
            }
        }

        function getSeverityClass(sev) {
            if (!sev) return 'bg-slate-700 text-slate-300';
            switch (sev.toLowerCase()) {
                case 'critical': return 'bg-rose-500/10 text-rose-400 border border-rose-500/20';
                case 'high': return 'bg-amber-500/10 text-amber-400 border border-amber-500/20';
                case 'medium': return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
                case 'low': return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
                default: return 'bg-slate-800 text-slate-300';
            }
        }

        async function overrideFindingTriage(id) {
            const sev = document.getElementById('sev-' + id).value;
            const state = document.getElementById('state-' + id).value;
            try {
                const response = await fetchAPI('/api/findings/triage', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id, severity: sev, workflow_state: state })
                });
                const result = await response.json();
                if (response.ok) {
                    alert('Finding triage updated successfully!');
                    loadFindings();
                } else {
                    throw new Error(result.error || 'Failed to update');
                }
            } catch (e) {
                alert('Error updating triage: ' + e.message);
            }
        }

        window.onload = () => {
            checkAuth();
        };
        setInterval(refreshData, 10000);
    </script>
</body>
</html>
`
