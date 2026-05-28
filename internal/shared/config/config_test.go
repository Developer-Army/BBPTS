package config

import (
	"encoding/json"
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

func TestConfigToolRateLimitsAndAutoUpdate(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ToolRateLimits == nil {
		t.Fatal("expected ToolRateLimits map to be initialized, got nil")
	}
	if cfg.AutoUpdate {
		t.Error("expected default AutoUpdate to be false, got true")
	}

	// Test manually loading from JSON simulation
	importJSON := `{
		"tool_rate_limits": {
			"httpx": 15,
			"nuclei": 5
		},
		"auto_update": true
	}`

	var parsed Config
	parsed.ToolRateLimits = make(map[string]int)
	if err := json.Unmarshal([]byte(importJSON), &parsed); err != nil {
		t.Fatalf("failed to unmarshal mock JSON config: %v", err)
	}

	if parsed.ToolRateLimits["httpx"] != 15 {
		t.Errorf("expected httpx rate limit to be 15, got %d", parsed.ToolRateLimits["httpx"])
	}
	if parsed.ToolRateLimits["nuclei"] != 5 {
		t.Errorf("expected nuclei rate limit to be 5, got %d", parsed.ToolRateLimits["nuclei"])
	}
	if !parsed.AutoUpdate {
		t.Error("expected AutoUpdate to be true, got false")
	}
}

func TestResolveWebEnder(t *testing.T) {
	headers := map[string]string{
		"User-Agent": "CustomUA",
	}

	res := ResolveWebEnder("H1{alice}", headers)
	if res["X-Research-Tag"] != "H1{alice}" {
		t.Errorf("expected X-Research-Tag 'H1{alice}', got '%s'", res["X-Research-Tag"])
	}
	if res["X-H1-Research"] != "alice" {
		t.Errorf("expected X-H1-Research 'alice', got '%s'", res["X-H1-Research"])
	}
	if res["User-Agent"] != "CustomUA H1{alice}" {
		t.Errorf("expected User-Agent 'CustomUA H1{alice}', got '%s'", res["User-Agent"])
	}

	// Test without existing headers/User-Agent
	res2 := ResolveWebEnder("HTM{bob}", nil)
	if res2["X-Research-Tag"] != "HTM{bob}" {
		t.Errorf("expected X-Research-Tag 'HTM{bob}', got '%s'", res2["X-Research-Tag"])
	}
	if res2["X-HTM-Research"] != "bob" {
		t.Errorf("expected X-HTM-Research 'bob', got '%s'", res2["X-HTM-Research"])
	}
	if res2["User-Agent"] != "BBPTS HTM{bob}" {
		t.Errorf("expected User-Agent 'BBPTS HTM{bob}', got '%s'", res2["User-Agent"])
	}
}
