package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ValidationError represents a single config validation error.
type ValidationError struct {
	Field   string
	Message string
	Level   string // "error", "warning"
}

func (v ValidationError) String() string {
	prefix := "ERROR"
	if v.Level == "warning" {
		prefix = "WARN"
	}
	return fmt.Sprintf("[%s] %s: %s", prefix, v.Field, v.Message)
}

// ValidationResult holds all validation errors and warnings.
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

// IsValid returns true if no errors were found (warnings are acceptable).
func (vr *ValidationResult) IsValid() bool {
	return len(vr.Errors) == 0
}

// AllIssues returns all errors and warnings combined.
func (vr *ValidationResult) AllIssues() []ValidationError {
	all := make([]ValidationError, 0, len(vr.Errors)+len(vr.Warnings))
	all = append(all, vr.Errors...)
	all = append(all, vr.Warnings...)
	return all
}

// FormatReport returns a human-readable validation report.
func (vr *ValidationResult) FormatReport() string {
	var b strings.Builder

	b.WriteString("\n╔══════════════════════════════════════════════╗\n")
	b.WriteString("║         Configuration Validation             ║\n")
	b.WriteString("╚══════════════════════════════════════════════╝\n\n")

	if vr.IsValid() && len(vr.Warnings) == 0 {
		b.WriteString("  ✓ Configuration is valid. No issues found.\n\n")
		return b.String()
	}

	if len(vr.Errors) > 0 {
		b.WriteString(fmt.Sprintf("  ✗ %d error(s) found:\n\n", len(vr.Errors)))
		for i, err := range vr.Errors {
			b.WriteString(fmt.Sprintf("    %d. [%s] %s\n", i+1, err.Field, err.Message))
		}
		b.WriteString("\n")
	}

	if len(vr.Warnings) > 0 {
		b.WriteString(fmt.Sprintf("  ⚠ %d warning(s) found:\n\n", len(vr.Warnings)))
		for i, warn := range vr.Warnings {
			b.WriteString(fmt.Sprintf("    %d. [%s] %s\n", i+1, warn.Field, warn.Message))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// Validate performs comprehensive validation of the config and returns
// a ValidationResult containing all errors and warnings found.
func Validate(cfg *Config) *ValidationResult {
	result := &ValidationResult{}

	if cfg == nil {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "config",
			Message: "configuration is nil",
			Level:   "error",
		})
		return result
	}

	// Validate threads
	if cfg.Threads <= 0 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "threads",
			Message: "threads must be positive",
			Level:   "error",
		})
	} else if cfg.Threads > 500 {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "threads",
			Message: fmt.Sprintf("threads is very high (%d) — may cause resource exhaustion or WAF bans", cfg.Threads),
			Level:   "warning",
		})
	}

	// Validate rate limit
	if cfg.RateLimit < 0 {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "rate_limit",
			Message: "rate_limit cannot be negative",
			Level:   "error",
		})
	} else if cfg.RateLimit == 0 {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "rate_limit",
			Message: "rate_limit is 0 (unlimited) — not recommended for production targets",
			Level:   "warning",
		})
	}

	// Validate proxies
	for i, proxy := range cfg.Proxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}
		u, err := url.Parse(proxy)
		if err != nil {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("proxies[%d]", i),
				Message: fmt.Sprintf("invalid proxy URL '%s': %v", proxy, err),
				Level:   "error",
			})
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
			result.Warnings = append(result.Warnings, ValidationError{
				Field:   fmt.Sprintf("proxies[%d]", i),
				Message: fmt.Sprintf("unusual proxy scheme '%s' — expected http, https, or socks5", scheme),
				Level:   "warning",
			})
		}
	}

	// Validate state directory
	if strings.TrimSpace(cfg.StateDir) != "" {
		if _, err := os.Stat(cfg.StateDir); os.IsNotExist(err) {
			result.Warnings = append(result.Warnings, ValidationError{
				Field:   "state_dir",
				Message: fmt.Sprintf("state directory '%s' does not exist (will be created on first run)", cfg.StateDir),
				Level:   "warning",
			})
		}
	}

	// Validate wordlists directory
	if strings.TrimSpace(cfg.WordlistsDir) != "" {
		if _, err := os.Stat(cfg.WordlistsDir); os.IsNotExist(err) {
			result.Warnings = append(result.Warnings, ValidationError{
				Field:   "wordlists_dir",
				Message: fmt.Sprintf("wordlists directory '%s' does not exist — fuzzing tools may fail", cfg.WordlistsDir),
				Level:   "warning",
			})
		}
	}

	// Validate API keys
	if len(cfg.APIKeys) == 0 {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "api_keys",
			Message: "no API keys configured — tools like Shodan, Censys will have limited functionality",
			Level:   "warning",
		})
	} else {
		// Check for obviously invalid keys
		for provider, key := range cfg.APIKeys {
			if strings.TrimSpace(key) == "" {
				continue // empty is fine — just means not configured
			}
			if len(key) < 10 {
				result.Warnings = append(result.Warnings, ValidationError{
					Field:   fmt.Sprintf("api_keys.%s", provider),
					Message: "API key seems unusually short — verify it's correct",
					Level:   "warning",
				})
			}
		}
	}

	// Validate fleet config
	if cfg.Fleet.Enabled {
		if strings.TrimSpace(cfg.Fleet.FleetName) == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "fleet.fleet_name",
				Message: "fleet_name is required when fleet is enabled",
				Level:   "error",
			})
		}
		if cfg.Fleet.FleetSize <= 0 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "fleet.fleet_size",
				Message: "fleet_size must be positive when fleet is enabled",
				Level:   "error",
			})
		}
	}

	// Validate event bus config
	if cfg.EventBus.Type == "nats" && strings.TrimSpace(cfg.EventBus.URL) == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "event_bus.url",
			Message: "NATS URL is required when event_bus type is 'nats'",
			Level:   "error",
		})
	}
	if cfg.EventBus.Type != "" && cfg.EventBus.Type != "nats" && cfg.EventBus.Type != "in-memory" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "event_bus.type",
			Message: fmt.Sprintf("unknown event bus type '%s' — expected 'nats' or 'in-memory'", cfg.EventBus.Type),
			Level:   "error",
		})
	}

	// Validate notify config
	if cfg.Notify.TelegramBotToken != "" && cfg.Notify.TelegramChatID == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "notify.telegram_chat_id",
			Message: "telegram_chat_id is required when telegram_bot_token is set",
			Level:   "error",
		})
	}

	// Validate database config
	validDBTypes := map[string]bool{"sqlite": true, "sqlite3": true, "": true}
	if !validDBTypes[cfg.Database.Type] {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "database.type",
			Message: fmt.Sprintf("unsupported database type '%s' — supported: sqlite, sqlite3", cfg.Database.Type),
			Level:   "error",
		})
	}

	return result
}

// ValidateAndPrint validates the config and prints the report.
// Returns true if the config is valid.
func ValidateAndPrint(cfg *Config) bool {
	result := Validate(cfg)
	fmt.Print(result.FormatReport())
	return result.IsValid()
}
