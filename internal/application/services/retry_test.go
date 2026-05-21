package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExecuteWithRetrySuccess(t *testing.T) {
	callCount := 0
	err := ExecuteWithRetry(context.Background(), RetryConfig{
		MaxRetries: 3,
		BaseDelay:  10 * time.Millisecond,
	}, func(_ context.Context, attempt int) (bool, error) {
		callCount++
		return false, nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}
}

func TestExecuteWithRetryEventualSuccess(t *testing.T) {
	callCount := 0
	err := ExecuteWithRetry(context.Background(), RetryConfig{
		MaxRetries: 5,
		BaseDelay:  10 * time.Millisecond,
		Multiplier: 1.5,
	}, func(_ context.Context, attempt int) (bool, error) {
		callCount++
		if callCount < 3 {
			return true, errors.New("transient error")
		}
		return false, nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if callCount != 3 {
		t.Fatalf("expected 3 calls, got %d", callCount)
	}
}

func TestExecuteWithRetryPermanentError(t *testing.T) {
	callCount := 0
	permanentErr := errors.New("permission denied")
	err := ExecuteWithRetry(context.Background(), RetryConfig{
		MaxRetries: 5,
		BaseDelay:  10 * time.Millisecond,
	}, func(_ context.Context, attempt int) (bool, error) {
		callCount++
		return false, permanentErr // non-retryable
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if callCount != 1 {
		t.Fatalf("expected 1 call for permanent error, got %d", callCount)
	}
	if !errors.Is(err, permanentErr) {
		t.Fatalf("expected wrapped permanent error, got %v", err)
	}
}

func TestExecuteWithRetryExhaustsRetries(t *testing.T) {
	callCount := 0
	err := ExecuteWithRetry(context.Background(), RetryConfig{
		MaxRetries: 2,
		BaseDelay:  10 * time.Millisecond,
	}, func(_ context.Context, attempt int) (bool, error) {
		callCount++
		return true, errors.New("still failing")
	})

	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if callCount != 3 { // initial + 2 retries
		t.Fatalf("expected 3 calls, got %d", callCount)
	}
}

func TestExecuteWithRetryContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := ExecuteWithRetry(ctx, RetryConfig{
		MaxRetries: 10,
		BaseDelay:  200 * time.Millisecond, // longer than context timeout
	}, func(_ context.Context, attempt int) (bool, error) {
		return true, errors.New("keep trying")
	})

	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
}

func TestComputeBackoffExponential(t *testing.T) {
	cfg := RetryConfig{
		BaseDelay:      100 * time.Millisecond,
		MaxDelay:       10 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0, // no jitter for deterministic test
	}

	d1 := computeBackoff(cfg, 1)
	d2 := computeBackoff(cfg, 2)
	d3 := computeBackoff(cfg, 3)

	if d1 != 100*time.Millisecond {
		t.Fatalf("attempt 1: expected 100ms, got %v", d1)
	}
	if d2 != 200*time.Millisecond {
		t.Fatalf("attempt 2: expected 200ms, got %v", d2)
	}
	if d3 != 400*time.Millisecond {
		t.Fatalf("attempt 3: expected 400ms, got %v", d3)
	}
}

func TestComputeBackoffCapsAtMax(t *testing.T) {
	cfg := RetryConfig{
		BaseDelay:      1 * time.Second,
		MaxDelay:       5 * time.Second,
		Multiplier:     3.0,
		JitterFraction: 0,
	}

	d := computeBackoff(cfg, 10) // Would be 3^9 * 1s without cap
	if d != 5*time.Second {
		t.Fatalf("expected delay capped at 5s, got %v", d)
	}
}
