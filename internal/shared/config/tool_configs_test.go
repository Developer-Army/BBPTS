package config

import (
	"os"
	"strings"
	"testing"
)

func TestWriteSubfinderProviderConfig(t *testing.T) {
	keys := map[string]string{
		"shodan":         "shodan-key-123",
		"securitytrails": "st-key-456",
		"github":         "ghp_abc",
		"censys_id":      "censys-id",
		"censys_secret":  "censys-secret",
		"fofa_email":     "test@example.com",
		"fofa_key":       "fofa-key",
		"intelx":         "intelx-key",
	}

	path, err := WriteSubfinderProviderConfig(keys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	content := string(data)

	// Verify simple keys are present
	for _, source := range []string{"shodan", "securitytrails", "github"} {
		if !strings.Contains(content, source+":") {
			t.Errorf("expected source %q in config", source)
		}
	}

	// Verify composite censys key
	if !strings.Contains(content, "censys:") {
		t.Error("expected censys source in config")
	}
	if !strings.Contains(content, "censys-id:censys-secret") {
		t.Error("expected composite censys key format")
	}

	// Verify composite fofa key
	if !strings.Contains(content, "fofa:") {
		t.Error("expected fofa source in config")
	}
	if !strings.Contains(content, "test@example.com:fofa-key") {
		t.Error("expected composite fofa key format")
	}

	// Verify intelx format
	if !strings.Contains(content, "intelx:") {
		t.Error("expected intelx source in config")
	}
	if !strings.Contains(content, "2.intelx.io:intelx-key") {
		t.Error("expected intelx host:key format")
	}
}

func TestWriteSubfinderProviderConfigEmpty(t *testing.T) {
	path, err := WriteSubfinderProviderConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		os.Remove(path)
		t.Error("expected empty path for no keys")
	}
}

func TestWriteAmassDatasourcesConfig(t *testing.T) {
	keys := map[string]string{
		"shodan":         "shodan-key",
		"censys_id":      "censys-id",
		"censys_secret":  "censys-secret",
		"passivetotal":   "pt-key",
		"passivetotal_email": "pt@example.com",
	}

	path, err := WriteAmassDatasourcesConfig(keys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "Shodan") {
		t.Error("expected Shodan datasource")
	}
	if !strings.Contains(content, "Censys") {
		t.Error("expected Censys datasource")
	}
	if !strings.Contains(content, "shodan-key") {
		t.Error("expected shodan apikey in config")
	}
	if !strings.Contains(content, "censys-id") {
		t.Error("expected censys apikey in config")
	}
}

func TestWriteAmassDatasourcesConfigEmpty(t *testing.T) {
	path, err := WriteAmassDatasourcesConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		os.Remove(path)
		t.Error("expected empty path for no keys")
	}
}
