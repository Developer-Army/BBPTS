package config

import (
	"testing"
)

func TestValidateDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	result := Validate(cfg)

	// Default config should have no errors (warnings are ok)
	if !result.IsValid() {
		t.Fatalf("default config should be valid, got errors: %v", result.Errors)
	}
}

func TestValidateNilConfig(t *testing.T) {
	result := Validate(nil)
	if result.IsValid() {
		t.Fatal("nil config should not be valid")
	}
}

func TestValidateInvalidThreads(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Threads = -1
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("negative threads should be invalid")
	}
}

func TestValidateHighThreadsWarning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Threads = 1000
	result := Validate(cfg)
	if len(result.Warnings) == 0 {
		t.Fatal("very high threads should generate a warning")
	}
}

func TestValidateInvalidProxy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Proxies = []string{"://not-a-valid-url"}
	result := Validate(cfg)
	// Should have at least a warning or error about the proxy
	if len(result.Errors)+len(result.Warnings) == 0 {
		t.Fatal("invalid proxy should generate an issue")
	}
}

func TestValidateFleetRequiresName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Fleet.Enabled = true
	cfg.Fleet.FleetName = ""
	cfg.Fleet.FleetSize = 10
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("enabled fleet without name should be invalid")
	}
}

func TestValidateFleetRequiresSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Fleet.Enabled = true
	cfg.Fleet.FleetName = "test-fleet"
	cfg.Fleet.FleetSize = 0
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("enabled fleet with size 0 should be invalid")
	}
}

func TestValidateNATSRequiresURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EventBus.Type = "nats"
	cfg.EventBus.URL = ""
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("NATS bus without URL should be invalid")
	}
}

func TestValidateInvalidEventBusType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EventBus.Type = "kafka"
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("unsupported event bus type should be invalid")
	}
}

func TestValidateTelegramRequiresChatID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Notify.TelegramBotToken = "12345:ABC"
	cfg.Notify.TelegramChatID = ""
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("telegram bot token without chat ID should be invalid")
	}
}

func TestValidateInvalidDBType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Database.Type = "postgres"
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("unsupported database type should be invalid")
	}
}

func TestValidateNegativeRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit = -5
	result := Validate(cfg)
	if result.IsValid() {
		t.Fatal("negative rate limit should be invalid")
	}
}

func TestValidateZeroRateLimitWarning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit = 0
	result := Validate(cfg)
	hasWarning := false
	for _, w := range result.Warnings {
		if w.Field == "rate_limit" {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Fatal("zero rate limit should generate a warning")
	}
}

func TestValidateNoAPIKeysWarning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.APIKeys = map[string]string{}
	result := Validate(cfg)
	hasWarning := false
	for _, w := range result.Warnings {
		if w.Field == "api_keys" {
			hasWarning = true
		}
	}
	if !hasWarning {
		t.Fatal("no API keys should generate a warning")
	}
}

func TestValidationResultAllIssues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Threads = -1
	cfg.RateLimit = 0
	result := Validate(cfg)

	all := result.AllIssues()
	if len(all) != len(result.Errors)+len(result.Warnings) {
		t.Fatal("AllIssues should return combined errors and warnings")
	}
}

func TestFormatReport(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Threads = -1
	result := Validate(cfg)
	report := result.FormatReport()
	if len(report) == 0 {
		t.Fatal("expected non-empty report")
	}
}
