package config

import (
	"os"
	"testing"
)

func TestDefaultConfigHeadersInitialized(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Headers == nil {
		t.Fatal("expected Headers map to be initialized, got nil")
	}
	if len(cfg.Headers) != 0 {
		t.Errorf("expected empty Headers map, got %d items", len(cfg.Headers))
	}
}

func TestLoadFromEnvHeaders(t *testing.T) {
	os.Setenv("BBPTS_HEADERS", "X-HackerOne-Researcher:alice,X-Custom-Auth:secret-token")
	defer os.Unsetenv("BBPTS_HEADERS")

	cfg := DefaultConfig()
	cfg.LoadFromEnv()

	if cfg.Headers == nil {
		t.Fatal("expected Headers map to be loaded, got nil")
	}

	val, ok := cfg.Headers["X-HackerOne-Researcher"]
	if !ok {
		t.Error("expected X-HackerOne-Researcher header to be present")
	}
	if val != "alice" {
		t.Errorf("expected X-HackerOne-Researcher to be 'alice', got '%s'", val)
	}

	val2, ok := cfg.Headers["X-Custom-Auth"]
	if !ok {
		t.Error("expected X-Custom-Auth header to be present")
	}
	if val2 != "secret-token" {
		t.Errorf("expected X-Custom-Auth to be 'secret-token', got '%s'", val2)
	}
}
