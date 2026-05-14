package services

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"time"
)

// RetryConfig configures the exponential backoff retry strategy.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (0 = no retries).
	MaxRetries int
	// BaseDelay is the initial delay before the first retry.
	BaseDelay time.Duration
	// MaxDelay is the cap on the computed backoff delay.
	MaxDelay time.Duration
	// Multiplier is the factor by which the delay increases each retry (default 2.0).
	Multiplier float64
	// JitterFraction is the fraction of the delay to add as random jitter (0.0 to 1.0).
	JitterFraction float64
}

// DefaultRetryConfig returns a production-ready retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     5,
		BaseDelay:      500 * time.Millisecond,
		MaxDelay:       60 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.25,
	}
}

// ToolRetryConfig returns a config tuned for external recon tool execution,
// where tools can be slow and intermittent failures are common.
func ToolRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     3,
		BaseDelay:      1 * time.Second,
		MaxDelay:       30 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.3,
	}
}

// RetryableFunc is a function that can be retried. It returns an error and a boolean
// indicating whether the error is retryable. Non-retryable errors abort immediately.
type RetryableFunc func(ctx context.Context, attempt int) (retryable bool, err error)

// ExecuteWithRetry runs fn with exponential backoff retries.
// If fn returns (false, err), the error is considered permanent and retries stop.
// If fn returns (true, err), the operation will be retried.
// If fn returns (_, nil), the operation succeeded.
func ExecuteWithRetry(ctx context.Context, cfg RetryConfig, fn RetryableFunc) error {
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = 2.0
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 500 * time.Millisecond
	}

	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := computeBackoff(cfg, attempt)
			slog.Debug("Retrying operation",
				"attempt", attempt,
				"max_retries", cfg.MaxRetries,
				"delay", delay,
			)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return fmt.Errorf("retry cancelled after %d attempts: %w", attempt, ctx.Err())
			}
		}

		retryable, err := fn(ctx, attempt)
		if err == nil {
			if attempt > 0 {
				slog.Debug("Operation succeeded after retry", "attempt", attempt)
			}
			return nil
		}

		lastErr = err

		if !retryable {
			return fmt.Errorf("permanent error (attempt %d/%d): %w", attempt+1, cfg.MaxRetries+1, err)
		}

		slog.Debug("Retryable error encountered",
			"attempt", attempt+1,
			"max_retries", cfg.MaxRetries+1,
			"error", err,
		)
	}

	return fmt.Errorf("operation failed after %d attempts: %w", cfg.MaxRetries+1, lastErr)
}

// computeBackoff calculates the next backoff delay with optional jitter.
func computeBackoff(cfg RetryConfig, attempt int) time.Duration {
	// Exponential component: baseDelay * multiplier^(attempt-1)
	backoff := float64(cfg.BaseDelay) * math.Pow(cfg.Multiplier, float64(attempt-1))

	// Cap at max delay
	if backoff > float64(cfg.MaxDelay) {
		backoff = float64(cfg.MaxDelay)
	}

	// Add jitter
	if cfg.JitterFraction > 0 {
		jitter := backoff * cfg.JitterFraction * rand.Float64()
		backoff += jitter
	}

	return time.Duration(backoff)
}

// RunToolWithRetry is a convenience wrapper that executes a recon tool with retries
// and exponential backoff. It wraps the standard Tool.Run call.
func RunToolWithRetry(ctx context.Context, tool Tool, targets []string, threads int, cfg RetryConfig) ([]Event, error) {
	var result []Event
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		events, err := tool.Run(ctx, targets, threads)
		if err != nil {
			// All tool errors are considered retryable unless the context is done
			if ctx.Err() != nil {
				return false, err
			}
			return true, err
		}
		result = events
		return false, nil
	})
	return result, err
}

// RunCommandWithRetry wraps RunCommandStream with exponential backoff retries.
func RunCommandWithRetry(ctx context.Context, cfg RetryConfig, name string, args ...string) ([]string, error) {
	var result []string
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		lines, err := runCommandStreamWithInput(ctx, nil, name, args...)
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			return true, err
		}
		result = lines
		return false, nil
	})
	return result, err
}
