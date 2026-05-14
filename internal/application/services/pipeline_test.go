package services

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestMockToolInterface verifies MockTool implements the Tool interface.
func TestMockToolInterface(t *testing.T) {
	var _ Tool = &MockTool{} // compile-time check
}

// TestMockToolReturnsEvents verifies mock tools return configured events.
func TestMockToolReturnsEvents(t *testing.T) {
	tool := GetMockTool("subfinder")
	events, err := tool.Run(context.Background(), []string{"example.com"}, 10)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected events, got none")
	}
	if tool.CallCount != 1 {
		t.Fatalf("expected call count 1, got %d", tool.CallCount)
	}
}

// TestFailingMockTool verifies error-returning mock tools.
func TestFailingMockTool(t *testing.T) {
	expectedErr := errors.New("tool binary not found")
	tool := NewFailingMockTool("broken-tool", expectedErr)
	_, err := tool.Run(context.Background(), []string{"example.com"}, 5)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
}

// TestMockPipelineFullFlow verifies NewMockPipeline produces realistic results.
func TestMockPipelineFullFlow(t *testing.T) {
	events := NewMockPipeline("example.com")
	if len(events) == 0 {
		t.Fatal("expected pipeline events, got none")
	}

	// Check we have events from different stages
	sources := make(map[string]int)
	for _, ev := range events {
		sources[ev.Source]++
	}

	expectedSources := []string{"subfinder", "httpx", "katana", "nuclei"}
	for _, src := range expectedSources {
		if sources[src] == 0 {
			t.Errorf("expected events from %s, got none", src)
		}
	}
}

// TestBatchProcessorSplit verifies batch splitting logic.
func TestBatchProcessorSplit(t *testing.T) {
	bp := NewBatchProcessor(BatchConfig{BatchSize: 3})

	// Generate 10 targets
	targets := make([]string, 10)
	for i := range targets {
		targets[i] = fmt.Sprintf("target-%d.example.com", i)
	}

	batches := bp.split(targets)
	if len(batches) != 4 { // 3+3+3+1
		t.Fatalf("expected 4 batches, got %d", len(batches))
	}
	if len(batches[3]) != 1 {
		t.Fatalf("expected last batch to have 1 element, got %d", len(batches[3]))
	}
}

// TestBatchProcessorProcess verifies end-to-end batch processing.
func TestBatchProcessorProcess(t *testing.T) {
	bp := NewBatchProcessor(BatchConfig{
		BatchSize:            5,
		MaxConcurrentBatches: 2,
		DelayBetweenBatches:  10 * time.Millisecond,
	})

	targets := make([]string, 12)
	for i := range targets {
		targets[i] = fmt.Sprintf("host-%d.example.com", i)
	}

	callCount := 0
	events, err := bp.Process(context.Background(), targets, func(ctx context.Context, batchTargets []string) ([]Event, error) {
		callCount++
		result := make([]Event, len(batchTargets))
		for i, t := range batchTargets {
			result[i] = NewEvent(t, "test-tool", "discovery", nil)
		}
		return result, nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(events) != 12 {
		t.Fatalf("expected 12 events, got %d", len(events))
	}
	if callCount != 3 { // 5+5+2
		t.Fatalf("expected 3 batch calls, got %d", callCount)
	}
}

// TestBatchProcessorSingleBatch verifies that a small target list bypasses batching.
func TestBatchProcessorSingleBatch(t *testing.T) {
	bp := NewBatchProcessor(BatchConfig{BatchSize: 100})
	targets := []string{"a.com", "b.com"}

	events, err := bp.Process(context.Background(), targets, func(ctx context.Context, batchTargets []string) ([]Event, error) {
		return []Event{NewEvent("a.com", "test", "discovery", nil)}, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

// TestToolRateLimiterDefaults verifies default rate limits for tools.
func TestToolRateLimiterDefaults(t *testing.T) {
	trl := NewToolRateLimiter()

	// Aggressive tools should have limits
	if limit := trl.GetLimit("ffuf"); limit == 0 {
		t.Fatal("expected ffuf to have a rate limit")
	}

	// Unknown tools should return 0 (unlimited)
	if limit := trl.GetLimit("unknown-tool"); limit != 0 {
		t.Fatalf("expected unknown tool to have unlimited rate, got %d", limit)
	}

	// Custom limit
	trl.SetLimit("custom-tool", 42)
	if limit := trl.GetLimit("custom-tool"); limit != 42 {
		t.Fatalf("expected custom limit 42, got %d", limit)
	}
}

// TestCacheKeyDeterminism verifies cache keys are deterministic.
func TestCacheKeyDeterminism(t *testing.T) {
	targets := []string{"a.com", "b.com", "c.com"}

	key1 := CacheKey("subfinder", targets, 10)
	key2 := CacheKey("subfinder", targets, 10)
	key3 := CacheKey("httpx", targets, 10)
	key4 := CacheKey("subfinder", targets, 20)

	if key1 != key2 {
		t.Fatal("expected same inputs to produce same cache key")
	}
	if key1 == key3 {
		t.Fatal("expected different tools to produce different cache keys")
	}
	if key1 == key4 {
		t.Fatal("expected different thread counts to produce different cache keys")
	}
}

// TestGetAllMockTools verifies we get tools for all registered mock outputs.
func TestGetAllMockTools(t *testing.T) {
	tools := GetAllMockTools()
	if len(tools) == 0 {
		t.Fatal("expected mock tools, got none")
	}
	if len(tools) != len(MockToolOutputs) {
		t.Fatalf("expected %d mock tools, got %d", len(MockToolOutputs), len(tools))
	}
}

// TestMockToolTracksTargets verifies MockTool records what was passed.
func TestMockToolTracksTargets(t *testing.T) {
	tool := GetMockTool("httpx")
	targets := []string{"a.com", "b.com"}
	tool.Run(context.Background(), targets, 5)

	if len(tool.LastTargets) != 2 {
		t.Fatalf("expected 2 recorded targets, got %d", len(tool.LastTargets))
	}
	if tool.LastThreads != 5 {
		t.Fatalf("expected recorded threads=5, got %d", tool.LastThreads)
	}
}
