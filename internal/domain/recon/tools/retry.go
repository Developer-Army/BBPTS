package tools

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"time"
)

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

func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     5,
		BaseDelay:      500 * time.Millisecond,
		MaxDelay:       60 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.25,
	}
}

func ToolRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     1,
		BaseDelay:      1 * time.Second,
		MaxDelay:       30 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.3,
	}
}

type RetryableFunc func(ctx context.Context, attempt int) (retryable bool, err error)

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

func computeBackoff(cfg RetryConfig, attempt int) time.Duration {

	backoff := float64(cfg.BaseDelay) * math.Pow(cfg.Multiplier, float64(attempt-1))

	if backoff > float64(cfg.MaxDelay) {
		backoff = float64(cfg.MaxDelay)
	}

	if cfg.JitterFraction > 0 {
		jitter := backoff * cfg.JitterFraction * rand.Float64()
		backoff += jitter
	}

	return time.Duration(backoff)
}
