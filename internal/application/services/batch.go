package services

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// BatchConfig configures batch processing behavior.
type BatchConfig struct {
	// BatchSize is the max number of targets per batch.
	BatchSize int
	// MaxConcurrentBatches is how many batches run in parallel.
	MaxConcurrentBatches int
	// DelayBetweenBatches adds a pause between batch executions to reduce load.
	DelayBetweenBatches time.Duration
}

// DefaultBatchConfig returns sensible defaults for batch processing.
func DefaultBatchConfig() BatchConfig {
	return BatchConfig{
		BatchSize:            50,
		MaxConcurrentBatches: 3,
		DelayBetweenBatches:  500 * time.Millisecond,
	}
}

// BatchResult holds the result of a single batch execution.
type BatchResult struct {
	BatchIndex int
	Events     []Event
	Error      error
	Duration   time.Duration
}

// BatchProcessor handles splitting large target lists into manageable batches
// and running them with controlled concurrency.
type BatchProcessor struct {
	config BatchConfig
}

// NewBatchProcessor creates a new batch processor.
func NewBatchProcessor(config BatchConfig) *BatchProcessor {
	if config.BatchSize <= 0 {
		config.BatchSize = 50
	}
	if config.MaxConcurrentBatches <= 0 {
		config.MaxConcurrentBatches = 3
	}
	return &BatchProcessor{config: config}
}

// Process splits targets into batches and runs the tool function against each.
// Results are merged and returned in order.
func (bp *BatchProcessor) Process(ctx context.Context, targets []string, fn func(ctx context.Context, batchTargets []string) ([]Event, error)) ([]Event, error) {
	batches := bp.split(targets)
	if len(batches) == 0 {
		return nil, nil
	}

	if len(batches) == 1 {
		// No need for batch machinery
		return fn(ctx, batches[0])
	}

	slog.Info("Batch processing started",
		"total_targets", len(targets),
		"batch_size", bp.config.BatchSize,
		"num_batches", len(batches),
		"max_concurrent", bp.config.MaxConcurrentBatches,
	)

	results := make([]BatchResult, len(batches))
	sem := make(chan struct{}, bp.config.MaxConcurrentBatches)
	var wg sync.WaitGroup

	for i, batch := range batches {
		i, batch := i, batch
		wg.Add(1)

		go func() {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = BatchResult{BatchIndex: i, Error: ctx.Err()}
				return
			}

			start := time.Now()
			events, err := fn(ctx, batch)
			results[i] = BatchResult{
				BatchIndex: i,
				Events:     events,
				Error:      err,
				Duration:   time.Since(start),
			}

			slog.Debug("Batch completed",
				"batch", i+1,
				"total", len(batches),
				"targets", len(batch),
				"events", len(events),
				"duration", results[i].Duration,
			)

			// Delay between batches
			if bp.config.DelayBetweenBatches > 0 && i < len(batches)-1 {
				select {
				case <-time.After(bp.config.DelayBetweenBatches):
				case <-ctx.Done():
				}
			}
		}()
	}

	wg.Wait()

	// Merge results in order
	var allEvents []Event
	var errors []error
	for _, result := range results {
		if result.Error != nil {
			errors = append(errors, fmt.Errorf("batch %d: %w", result.BatchIndex, result.Error))
		}
		allEvents = append(allEvents, result.Events...)
	}

	if len(errors) > 0 {
		slog.Warn("Batch processing completed with errors",
			"total_events", len(allEvents),
			"failed_batches", len(errors),
		)
	} else {
		slog.Info("Batch processing completed successfully",
			"total_events", len(allEvents),
			"num_batches", len(batches),
		)
	}

	if len(errors) > 0 && len(allEvents) == 0 {
		return nil, fmt.Errorf("all %d batches failed", len(errors))
	}

	return allEvents, nil
}

// split divides targets into batches of the configured size.
func (bp *BatchProcessor) split(targets []string) [][]string {
	if len(targets) == 0 {
		return nil
	}

	var batches [][]string
	for i := 0; i < len(targets); i += bp.config.BatchSize {
		end := i + bp.config.BatchSize
		if end > len(targets) {
			end = len(targets)
		}
		batches = append(batches, targets[i:end])
	}
	return batches
}

// ToolRateLimiter provides per-tool rate limiting to prevent WAF bans.
type ToolRateLimiter struct {
	limiters map[string]int // tool -> max requests per second
	mu       sync.RWMutex
}

// NewToolRateLimiter creates a per-tool rate limiter with default limits.
func NewToolRateLimiter() *ToolRateLimiter {
	return &ToolRateLimiter{
		limiters: map[string]int{
			// Aggressive tools need lower limits
			"ffuf":        50,
			"feroxbuster": 50,
			"gobuster":    50,
			"nuclei":      30,
			"dalfox":      20,
			// Web probing tools
			"httpx":    100,
			"katana":   30,
			"hakrawler": 30,
			// Passive tools can go faster
			"subfinder":   200,
			"assetfinder": 200,
			"crtsh":       10, // crt.sh is rate-limited
			"chaos":       100,
			// Port scanning
			"naabu": 100,
			// Default for unlisted tools
		},
	}
}

// GetLimit returns the rate limit for a tool. Returns 0 for unlimited.
func (trl *ToolRateLimiter) GetLimit(toolName string) int {
	trl.mu.RLock()
	defer trl.mu.RUnlock()

	if limit, ok := trl.limiters[toolName]; ok {
		return limit
	}
	return 0 // unlimited
}

// SetLimit configures a rate limit for a specific tool.
func (trl *ToolRateLimiter) SetLimit(toolName string, maxPerSecond int) {
	trl.mu.Lock()
	defer trl.mu.Unlock()
	trl.limiters[toolName] = maxPerSecond
}
