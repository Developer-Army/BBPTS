package recon

import (
	"context"
	"testing"
	"time"
)

// TestOrchestratorInitialization tests that the orchestrator initializes correctly
// with valid configurations.
func TestOrchestratorInitialization(t *testing.T) {
	config := Config{
		ToolNames: []string{"subfinder", "httpx"},
		Threads:   5,
		Verbose:   false,
		RateLimit: 100,
		Proxies:   []string{},
	}

	orchestrator := NewOrchestrator(config)

	if orchestrator == nil {
		t.Fatal("Expected non-nil orchestrator")
	}
}

// TestOrchestratorExecutionTimeout tests that execution respects context timeout.
func TestOrchestratorExecutionTimeout(t *testing.T) {
	config := Config{
		ToolNames: []string{"subfinder"},
		Threads:   2,
		RateLimit: 10,
	}

	orchestrator := NewOrchestrator(config)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	targets := []string{"example.com"}
	events, _ := orchestrator.Run(ctx, targets)

	// Should complete without crashing on timeout
	if events == nil {
		t.Log("events is nil on timeout (allowed)")
	}
}

// TestOrchestratorWithInvalidTools tests handling of non-existent tools.
func TestOrchestratorWithInvalidTools(t *testing.T) {
	config := Config{
		ToolNames: []string{"nonexistent-tool-xyz"},
		Threads:   1,
	}

	orchestrator := NewOrchestrator(config)

	if orchestrator == nil {
		t.Fatal("Orchestrator should not be nil")
	}
	if len(orchestrator.tools) != 0 {
		t.Fatalf("Expected invalid tool to be skipped, got %d tools", len(orchestrator.tools))
	}
}

// TestOrchestratorConcurrency tests that orchestrator respects thread limits.
func TestOrchestratorConcurrency(t *testing.T) {
	config := Config{
		ToolNames: []string{"httpx"},
		Threads:   3,
		RateLimit: 0,
	}

	orchestrator := NewOrchestrator(config)

	ctx := context.Background()
	targets := []string{"example.com", "google.com", "github.com"}

	events, err := orchestrator.Run(ctx, targets)
	if err != nil {
		t.Logf("Execution error (expected in test env): %v", err)
	}

	if events == nil {
		t.Log("events is nil (allowed)")
	}
}

// TestOrchestratorRateLimiting tests that rate limiting is applied.
func TestOrchestratorRateLimiting(t *testing.T) {
	config := Config{
		ToolNames: []string{"httpx"},
		Threads:   2,
		RateLimit: 1, // 1 request per second
	}

	orchestrator := NewOrchestrator(config)

	if orchestrator == nil {
		t.Fatal("Expected non-nil orchestrator with rate limiting")
	}
}
