// Package config provides unified configuration management for BBPTS,
// including API key injection, proxy rotation, rate limiting, and state persistence.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"encoding/json"
)

// Config holds all runtime configuration for the BBPTS toolkit.
type Config struct {
	// APIKeys maps provider names to their API keys.
	// Supported providers: shodan, censys, securitytrails, github, chaos, virustotal, passivetotal, binaryedge
	APIKeys map[string]string `json:"api_keys"`

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
		APIKeys:      make(map[string]string),
		Proxies:      []string{},
		RateLimit:    50,
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
			Type: "in-memory",
			URL:  "",
		},
	}
}

// LoadFromFile reads a JSON config file and merges it into the config.
// Missing fields retain their default values.
func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = WriteDefault(path)
			return cfg, nil // No config file is fine, use defaults
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

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
		"censys":         "",
		"securitytrails": "",
		"github":         "",
		"chaos":          "",
		"virustotal":     "",
		"passivetotal":   "",
		"binaryedge":     "",
	}
	cfg.Proxies = []string{"socks5://127.0.0.1:9050"}
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
