// Package config provides unified configuration management for BBPTS,
// including API key injection, proxy rotation, rate limiting, and state persistence.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"encoding/json"

	"github.com/Developer-Army/BBPTS/internal/domain/security"
)

// Config holds all runtime configuration for the BBPTS toolkit.
type Config struct {
	// APIKeys maps provider names to their API keys.
	// Supported providers: shodan, securitytrails, github, chaos, virustotal, passivetotal, binaryedge
	APIKeys map[string]string `json:"api_keys"`

	// Headers holds custom HTTP headers to pass to active scanners.
	Headers map[string]string `json:"headers"`

	// Proxies is a list of proxy URLs for rotating traffic.
	// Supports HTTP, HTTPS, and SOCKS5 (e.g., "socks5://127.0.0.1:9050").
	Proxies []string `json:"proxies"`

	// RateLimit is the maximum number of requests per second across all tools globally.
	// Set to 0 for unlimited (not recommended against production targets).
	RateLimit int `json:"rate_limit"`

	// StateDir is the directory for persisting scan state for diffing between runs.
	StateDir string `json:"state_dir"`

	// WordlistsDir is the directory where curated SecLists are stored.
	WordlistsDir string `json:"wordlists_dir"`

	// TmpResultsDir is an optional override for streaming per-tool event artifacts.
	// When empty, the app falls back to "<output-dir>/results/tmp".
	TmpResultsDir string `json:"tmp_results_dir"`

	// Wordlists holds tool-specific wordlist configurations.
	Wordlists WordlistConfig `json:"wordlists"`

	// Threads is the default concurrency for the orchestrator.
	Threads int `json:"threads"`

	// Notify holds webhook URLs for alerting (Telegram, Discord, Slack).
	Notify NotifyConfig `json:"notify"`

	// Submit controls optional bug bounty platform submission.
	Submit SubmitConfig `json:"submit"`

	// Fleet holds Axiom distributed fleet configuration.
	Fleet FleetConfig `json:"fleet"`

	// ToolPresets defines named shortcuts for tool lists and timing (see docs/CONFIG.md).
	ToolPresets map[string]ToolPreset `json:"tool_presets"`

	// ProgramProfiles defines per-program defaults and host exclusions.
	ProgramProfiles map[string]ProgramProfile `json:"program_profiles"`

	// Database holds connection settings for Recon Memory.
	Database DatabaseConfig `json:"database"`

	// EventBus holds connection settings for the event-driven core.
	EventBus EventBusConfig `json:"event_bus"`

	// ResourceLimits holds resource limits to configure CPU and memory usage
	ResourceLimits ResourceLimitsConfig `json:"resource_limits"`

	// ToolRateLimits holds rate limits for individual tools.
	ToolRateLimits map[string]int `json:"tool_rate_limits"`

	// AutoUpdate controls whether Nuclei templates are updated automatically.
	AutoUpdate bool `json:"auto_update"`

	// Ports is a comma-separated list of ports for port-scanning tools (naabu).
	// When empty, the built-in default port list is used.
	Ports string `json:"ports"`

	// BatchSize controls how many domains are scanned concurrently.
	// 1 = sequential (default). Higher values trade memory for speed.
	BatchSize int `json:"batch_size"`

	// ReportTemplatePath is an optional path to a custom Go text/template file
	// for generating the HTML report. When empty, the built-in template is used.
	ReportTemplatePath string `json:"report_template"`

	// ContainerMode executes external tools in container environments.
	ContainerMode bool `json:"container_mode"`

	// DockerImages maps tool names to docker images to use.
	DockerImages map[string]string `json:"docker_images"`

	// DashboardTLS configuration for securing the web dashboard.
	DashboardTLS TLSConfig `json:"dashboard_tls"`

	// DashboardToken is the token required to access the dashboard API.
	DashboardToken string `json:"dashboard_token"`

	// InsecureSkipVerify disables SSL/TLS certificate verification for scanners.
	InsecureSkipVerify bool `json:"insecure_skip_verify"`

	// WebEnder holds a custom research identifier tag (e.g., H1{username}).
	WebEnder string `json:"web_ender"`

	// MockMode gates simulated/mock event injection.
	MockMode bool `json:"mock_mode"`

	// FPConfidenceThreshold is the threshold below which events are marked suppressed.
	FPConfidenceThreshold int `json:"fp_confidence_threshold"`

	// FPKeepSuppressed controls whether suppressed events are kept in the output report.
	FPKeepSuppressed bool `json:"fp_keep_suppressed"`
}

// DatabaseConfig holds connection settings for Recon Memory.
type DatabaseConfig struct {
	Type string `json:"type"` // "sqlite" or "sqlite3"; postgres is not enabled in the default build
	DSN  string `json:"dsn"`  // path for sqlite
}

// EventBusConfig holds connection settings for the event-driven core.
type EventBusConfig struct {
	Type string `json:"type"` // "in-memory" or "nats"
	URL  string `json:"url"`  // e.g. "nats://127.0.0.1:4222"
}

// NotifyConfig holds webhook URLs for alerting channels.
type NotifyConfig struct {
	TelegramBotToken string `json:"telegram_bot_token"`
	TelegramChatID   string `json:"telegram_chat_id"`
	DiscordWebhook   string `json:"discord_webhook"`
	SlackWebhook     string `json:"slack_webhook"`
}

// SubmitConfig holds optional bug bounty platform submission settings.
type SubmitConfig struct {
	Platform string `json:"platform"`
}

// FleetConfig holds Axiom distributed fleet configuration.
type FleetConfig struct {
	Enabled     bool   `json:"enabled"`
	WorkerMesh  bool   `json:"worker_mesh"` // Send jobs to NATS instead of Axiom/local
	FleetName   string `json:"fleet_name"`
	FleetSize   int    `json:"fleet_size"`
	DeleteAfter bool   `json:"delete_after"`
	SyncToken   string `json:"sync_token"`
}

// TLSConfig holds configuration for securing the web server/manager with HTTPS.
type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// ResourceLimitsConfig holds configuration for CPU, memory, and GC limits.
type ResourceLimitsConfig struct {
	MaxCPUPercent int `json:"max_cpu_percent"`
	MaxCPUCores   int `json:"max_cpu_cores"`
	MaxMemoryMB   int `json:"max_memory_mb"`
	GCPercent     int `json:"gc_percent"`
}

// WordlistConfig holds tool-specific wordlist configurations.
type WordlistConfig struct {
	// DNS wordlist for subdomain enumeration tools (amass, subfinder, etc.)
	DNS string `json:"dns"`
	// Directory wordlist for content discovery tools (gobuster, ffuf, etc.)
	Directory string `json:"directory"`
	// Subdomain wordlist for subdomain brute-forcing
	Subdomain string `json:"subdomain"`
	// API wordlist for API endpoint discovery
	API string `json:"api"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		APIKeys:            make(map[string]string),
		Headers:            make(map[string]string),
		Proxies:            []string{},
		RateLimit:          50,
		ToolRateLimits:     make(map[string]int),
		AutoUpdate:         false,
		InsecureSkipVerify: false,
		Ports:              "",
		BatchSize:          1,
		ContainerMode:      false,
		DockerImages: map[string]string{
			"nuclei":    "projectdiscovery/nuclei:v3.2.9",
			"subfinder": "projectdiscovery/subfinder:v2.6.6",
			"katana":    "projectdiscovery/katana:v1.1.0",
			"httpx":     "projectdiscovery/httpx:v1.6.4",
			"dnsx":      "projectdiscovery/dnsx:v1.2.1",
			"naabu":     "projectdiscovery/naabu:v2.3.1",
			"tlsx":      "projectdiscovery/tlsx:v1.1.6",
			"amass":     "caffix/amass:v4.2.0",
		},
		StateDir:     filepath.Join(home, ".bbpts", "state"),
		WordlistsDir: filepath.Join(".", "wordlists"),
		Wordlists: WordlistConfig{
			DNS:       "dns-5k.txt",
			Directory: "raft-small-files.txt",
			Subdomain: "subdomains-top1million-5000.txt",
			API:       "api-endpoints.txt",
		},
		Threads: 32,
		Fleet: FleetConfig{
			FleetName:   "bbpts-fleet",
			FleetSize:   10,
			DeleteAfter: true,
		},
		Database: DatabaseConfig{
			Type: "sqlite",
			DSN:  "", // Defaults to <TmpResultsDir>/bbpts.db in app.go
		},
		EventBus: EventBusConfig{
			Type: "nats",
			URL:  "nats://127.0.0.1:4222",
		},
		ResourceLimits: ResourceLimitsConfig{
			MaxCPUPercent: 90,
			MaxCPUCores:   0,
			MaxMemoryMB:   0,
			GCPercent:     0,
		},
		FPConfidenceThreshold: 40,
		FPKeepSuppressed:      true,
	}
}

// LoadFromFile reads a JSON config file and merges it into the config.
// Missing fields retain their default values.
func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// safe to ignore: writing default config helper is non-critical for running with defaults
			_ = WriteDefault(path)
			cfg.RegisterSecrets()
			return cfg, nil // No config file is fine, use defaults
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Fallback to ~/.bbpts/wordlists if local doesn't exist
	if cfg.WordlistsDir == "./wordlists" || cfg.WordlistsDir == "wordlists" {
		if _, err := os.Stat(cfg.WordlistsDir); os.IsNotExist(err) {
			home, _ := os.UserHomeDir()
			globalWordlists := filepath.Join(home, ".bbpts", "wordlists")
			if _, err := os.Stat(globalWordlists); err == nil {
				cfg.WordlistsDir = globalWordlists
			}
		}
	}

	cfg.RegisterSecrets()
	return cfg, nil
}

// LoadFromEnv overlays environment variables onto an existing config.
// Environment variables take precedence over file-based config.
//
// Supported environment variables:
//
//	BBPTS_SHODAN_API_KEY, BBPTS_CENSYS_API_KEY, BBPTS_SECURITYTRAILS_API_KEY,
//	BBPTS_GITHUB_TOKEN, BBPTS_CHAOS_API_KEY, BBPTS_VIRUSTOTAL_API_KEY,
//	BBPTS_PASSIVETOTAL_API_KEY, BBPTS_BINARYEDGE_API_KEY,
//	BBPTS_PROXIES (comma-separated), BBPTS_RATE_LIMIT, BBPTS_STATE_DIR
func (c *Config) LoadFromEnv() {
	envKeys := map[string]string{
		"BBPTS_SHODAN_API_KEY":         "shodan",
		"BBPTS_CENSYS_API_KEY":         "censys",
		"BBPTS_SECURITYTRAILS_API_KEY": "securitytrails",
		"BBPTS_GITHUB_TOKEN":           "github",
		"BBPTS_CHAOS_API_KEY":          "chaos",
		"BBPTS_VIRUSTOTAL_API_KEY":     "virustotal",
		"BBPTS_PASSIVETOTAL_API_KEY":   "passivetotal",
		"BBPTS_BINARYEDGE_API_KEY":     "binaryedge",
		"BBPTS_H1_USERNAME":           "h1_username",
		"BBPTS_H1_API_TOKEN":          "h1_api_token",
		"BBPTS_BUGCROWD_API_TOKEN":    "bugcrowd_api_token",
	}

	for envVar, provider := range envKeys {
		if val := os.Getenv(envVar); val != "" {
			c.APIKeys[provider] = val
		}
	}

	if val := os.Getenv("BBPTS_PROXIES"); val != "" {
		c.Proxies = strings.Split(val, ",")
	}

	if val := os.Getenv("BBPTS_RATE_LIMIT"); val != "" {
		var rl int
		if _, err := fmt.Sscanf(val, "%d", &rl); err == nil && rl > 0 {
			c.RateLimit = rl
		}
	}

	if val := os.Getenv("BBPTS_STATE_DIR"); val != "" {
		c.StateDir = val
	}
	if val := os.Getenv("BBPTS_TMP_RESULTS_DIR"); val != "" {
		c.TmpResultsDir = val
	}
	if val := os.Getenv("BBPTS_INSECURE_SKIP_VERIFY"); val != "" {
		c.InsecureSkipVerify = (strings.ToLower(val) == "true")
	}

	if val := os.Getenv("BBPTS_HEADERS"); val != "" {
		if c.Headers == nil {
			c.Headers = make(map[string]string)
		}
		pairs := strings.Split(val, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				c.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if val := os.Getenv("BBPTS_MAX_CPU_PERCENT"); val != "" {
		var percent int
		if _, err := fmt.Sscanf(val, "%d", &percent); err == nil && percent > 0 && percent <= 100 {
			c.ResourceLimits.MaxCPUPercent = percent
		}
	}
	if val := os.Getenv("BBPTS_MAX_CPU_CORES"); val != "" {
		var cores int
		if _, err := fmt.Sscanf(val, "%d", &cores); err == nil && cores > 0 {
			c.ResourceLimits.MaxCPUCores = cores
		}
	}
	if val := os.Getenv("BBPTS_MAX_MEMORY_MB"); val != "" {
		var mem int
		if _, err := fmt.Sscanf(val, "%d", &mem); err == nil && mem > 0 {
			c.ResourceLimits.MaxMemoryMB = mem
		}
	}
	if val := os.Getenv("BBPTS_GC_PERCENT"); val != "" {
		var gc int
		if _, err := fmt.Sscanf(val, "%d", &gc); err == nil && gc > 0 {
			c.ResourceLimits.GCPercent = gc
		}
	}
	c.RegisterSecrets()
}

// GetAPIKey returns the API key for a given provider, or empty string if not set.
func (c *Config) GetAPIKey(provider string) string {
	return c.APIKeys[strings.ToLower(provider)]
}

// HasProxy returns true if at least one proxy is configured.
func (c *Config) HasProxy() bool {
	return len(c.Proxies) > 0
}

// WriteDefault writes a default config file to the given path for the user to edit.
func WriteDefault(path string) error {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]string{
		"shodan":         "",
		"securitytrails": "",
		"github":         "",
		"chaos":          "",
		"virustotal":     "",
		"passivetotal":   "",
		"binaryedge":     "",
		"h1_username":         "",
		"h1_api_token":        "",
		"bugcrowd_api_token":  "",
	}
	cfg.Proxies = []string{"socks5://127.0.0.1:9050"}
	cfg.Headers = map[string]string{}
	cfg.RateLimit = 50

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// ResolveWebEnder parses a tag format like NAME{value} and populates headers.
func ResolveWebEnder(webEnder string, headers map[string]string) map[string]string {
	if headers == nil {
		headers = make(map[string]string)
	}
	if webEnder == "" {
		return headers
	}
	if strings.Contains(webEnder, "{") && strings.HasSuffix(webEnder, "}") {
		parts := strings.SplitN(webEnder, "{", 2)
		name := strings.ToUpper(strings.TrimSpace(parts[0]))
		val := strings.TrimSuffix(parts[1], "}")
		if name != "" && val != "" {
			headers["X-Research-Tag"] = webEnder
			headers[fmt.Sprintf("X-%s-Research", name)] = val
			if ua, ok := headers["User-Agent"]; ok {
				headers["User-Agent"] = ua + " " + webEnder
			} else {
				headers["User-Agent"] = "BBPTS " + webEnder
			}
		}
	}
	return headers
}

// RegisterSecrets registers sensitive configuration fields with the security package redactor.
func (c *Config) RegisterSecrets() {
	if c.DashboardToken != "" {
		security.RegisterSecretToRedact(c.DashboardToken)
	}
	if c.Fleet.SyncToken != "" {
		security.RegisterSecretToRedact(c.Fleet.SyncToken)
	}
	if c.Notify.TelegramBotToken != "" {
		security.RegisterSecretToRedact(c.Notify.TelegramBotToken)
	}
	if c.Notify.TelegramChatID != "" {
		security.RegisterSecretToRedact(c.Notify.TelegramChatID)
	}
	if c.Notify.DiscordWebhook != "" {
		security.RegisterSecretToRedact(c.Notify.DiscordWebhook)
	}
	if c.Notify.SlackWebhook != "" {
		security.RegisterSecretToRedact(c.Notify.SlackWebhook)
	}
	for _, key := range c.APIKeys {
		if key != "" {
			security.RegisterSecretToRedact(key)
		}
	}
}
