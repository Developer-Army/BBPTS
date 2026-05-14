package network

import (
	"context"
	"testing"
	"time"
)

func TestLimiterUnlimitedReturnsImmediately(t *testing.T) {
	limiter := New(0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("Wait() returned error for unlimited limiter: %v", err)
	}
}

func TestLimiterBlocksUnderLoad(t *testing.T) {
	limiter := New(1)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("first Wait() returned error: %v", err)
	}

	start := time.Now()
	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("second Wait() returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("second Wait() did not block long enough: %s", elapsed)
	}
}

func TestLimiterRespectsContextCancellation(t *testing.T) {
	limiter := New(1)
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait() returned error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	if err := limiter.Wait(ctx); err == nil {
		t.Fatal("Wait() returned nil after context cancellation")
	}
}

func TestLimiterStopIsNoop(t *testing.T) {
	limiter := New(1)
	limiter.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := limiter.Wait(ctx); err != nil {
		t.Fatalf("Wait() after Stop() returned error: %v", err)
	}
}
