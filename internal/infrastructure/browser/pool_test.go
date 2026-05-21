package browser

import (
	"testing"
	"time"
)

func TestDefaultPoolConfig(t *testing.T) {
	cfg := DefaultPoolConfig()

	if cfg.MaxBrowsers != 5 {
		t.Errorf("Expected MaxBrowsers 5, got %d", cfg.MaxBrowsers)
	}

	if cfg.MaxContexts != 20 {
		t.Errorf("Expected MaxContexts 20, got %d", cfg.MaxContexts)
	}

	if cfg.Headless != true {
		t.Error("Expected Headless to be true")
	}

	if len(cfg.ExtraArgs) == 0 {
		t.Error("Expected ExtraArgs to be set")
	}
}

func TestLowResourcePoolConfig(t *testing.T) {
	cfg := LowResourcePoolConfig()

	if cfg.MaxBrowsers != 1 {
		t.Errorf("Expected MaxBrowsers 1, got %d", cfg.MaxBrowsers)
	}

	if cfg.MaxContexts != 3 {
		t.Errorf("Expected MaxContexts 3, got %d", cfg.MaxContexts)
	}

	if cfg.Headless != true {
		t.Error("Expected Headless to be true")
	}

	if len(cfg.ExtraArgs) == 0 {
		t.Error("Expected ExtraArgs to be set")
	}
}

func TestDefaultPoolConfigArgs(t *testing.T) {
	cfg := DefaultPoolConfig()

	expectedArgs := []string{
		"--disable-blink-features=AutomationControlled",
		"--no-sandbox",
		"--disable-setuid-sandbox",
		"--disable-dev-shm-usage",
		"--disable-accelerated-2d-canvas",
		"--disable-gpu",
		"--window-size=1920,1080",
	}

	if len(cfg.ExtraArgs) != len(expectedArgs) {
		t.Errorf("Expected %d args, got %d", len(expectedArgs), len(cfg.ExtraArgs))
	}

	for i, expected := range expectedArgs {
		if cfg.ExtraArgs[i] != expected {
			t.Errorf("Expected arg %d to be '%s', got '%s'", i, expected, cfg.ExtraArgs[i])
		}
	}
}

func TestLowResourcePoolConfigArgs(t *testing.T) {
	cfg := LowResourcePoolConfig()

	// Check for memory-specific args
	hasMemoryLimit := false
	for _, arg := range cfg.ExtraArgs {
		if arg == "--js-flags=--max-old-space-size=256" {
			hasMemoryLimit = true
		}
	}

	if !hasMemoryLimit {
		t.Error("Expected low resource config to have memory limit")
	}

	// Check for smaller window size
	hasSmallWindow := false
	for _, arg := range cfg.ExtraArgs {
		if arg == "--window-size=1280,720" {
			hasSmallWindow = true
		}
	}

	if !hasSmallWindow {
		t.Error("Expected low resource config to have smaller window size")
	}
}

func TestBrowserInstance(t *testing.T) {
	// This is a struct test - just verify the structure
	bi := BrowserInstance{
		contexts: 5,
		lastUsed: time.Now(),
	}

	if bi.contexts != 5 {
		t.Errorf("Expected contexts 5, got %d", bi.contexts)
	}
}

func TestPoolConfigDefaults(t *testing.T) {
	cfg := PoolConfig{}

	// Test zero values
	if cfg.MaxBrowsers != 0 {
		t.Errorf("Expected MaxBrowsers 0, got %d", cfg.MaxBrowsers)
	}

	if cfg.MaxContexts != 0 {
		t.Errorf("Expected MaxContexts 0, got %d", cfg.MaxContexts)
	}

	if cfg.Headless != false {
		t.Error("Expected Headless to be false by default")
	}

	if cfg.ProxyURL != "" {
		t.Error("Expected ProxyURL to be empty by default")
	}

	if cfg.UserAgent != "" {
		t.Error("Expected UserAgent to be empty by default")
	}

	if cfg.ExtraArgs != nil {
		t.Error("Expected ExtraArgs to be nil by default")
	}
}

func TestPoolConfigCustom(t *testing.T) {
	customArgs := []string{"--custom-arg"}
	cfg := PoolConfig{
		MaxBrowsers: 10,
		MaxContexts: 50,
		ContextTTL:  5 * 60 * 1000000000, // 5 minutes in nanoseconds
		Headless:    false,
		ProxyURL:    "http://proxy.acme-corp.io",
		UserAgent:   "CustomAgent/1.0",
		ExtraArgs:   customArgs,
	}

	if cfg.MaxBrowsers != 10 {
		t.Errorf("Expected MaxBrowsers 10, got %d", cfg.MaxBrowsers)
	}

	if cfg.MaxContexts != 50 {
		t.Errorf("Expected MaxContexts 50, got %d", cfg.MaxContexts)
	}

	if cfg.Headless != false {
		t.Error("Expected Headless to be false")
	}

	if cfg.ProxyURL != "http://proxy.acme-corp.io" {
		t.Errorf("Expected ProxyURL 'http://proxy.acme-corp.io', got '%s'", cfg.ProxyURL)
	}

	if cfg.UserAgent != "CustomAgent/1.0" {
		t.Errorf("Expected UserAgent 'CustomAgent/1.0', got '%s'", cfg.UserAgent)
	}

	if len(cfg.ExtraArgs) != 1 {
		t.Errorf("Expected 1 extra arg, got %d", len(cfg.ExtraArgs))
	}

	if cfg.ExtraArgs[0] != "--custom-arg" {
		t.Errorf("Expected extra arg '--custom-arg', got '%s'", cfg.ExtraArgs[0])
	}
}

func TestSelectBrowserLogic(t *testing.T) {
	// Test the logic of selectBrowser without actually calling it
	// This tests the round-robin with capacity check logic

	browsers := []BrowserInstance{
		{contexts: 10},
		{contexts: 50},
		{contexts: 5},
	}

	// Simulate round-robin selection with capacity check
	// Start from index 0, check each browser
	selected := -1
	start := 0
	maxCapacity := 50

	for i := 0; i < len(browsers); i++ {
		idx := (start + i) % len(browsers)
		if browsers[idx].contexts < maxCapacity {
			selected = idx
			break
		}
	}

	if selected != 0 {
		t.Errorf("Expected to select browser at index 0, got %d", selected)
	}

	// Test when first browser is at capacity
	browsers[0].contexts = 50
	selected = -1

	for i := 0; i < len(browsers); i++ {
		idx := (start + i) % len(browsers)
		if browsers[idx].contexts < maxCapacity {
			selected = idx
			break
		}
	}

	if selected != 2 {
		t.Errorf("Expected to select browser at index 2, got %d", selected)
	}

	// Test when all browsers are at capacity
	browsers[2].contexts = 50
	selected = -1

	for i := 0; i < len(browsers); i++ {
		idx := (start + i) % len(browsers)
		if browsers[idx].contexts < maxCapacity {
			selected = idx
			break
		}
	}

	if selected != -1 {
		t.Errorf("Expected no browser to be selected, got %d", selected)
	}
}
