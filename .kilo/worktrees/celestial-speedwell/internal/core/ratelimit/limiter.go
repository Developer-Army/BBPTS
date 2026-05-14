// Package ratelimit provides a global token-bucket rate limiter for throttling
// outbound requests across all concurrent recon tools.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter controls the rate of operations using a token bucket algorithm.
// It is safe for concurrent use by multiple goroutines.
type Limiter struct {
	mu       sync.Mutex
	tokens   int
	maxRate  int
	interval time.Duration
	stopCh   chan struct{}
	stopped  bool
}

// New creates a new rate limiter that allows maxPerSecond operations per second.
// If maxPerSecond is <= 0, the limiter is effectively unlimited.
func New(maxPerSecond int) *Limiter {
	if maxPerSecond <= 0 {
		maxPerSecond = 0 // unlimited
	}

	l := &Limiter{
		tokens:   maxPerSecond,
		maxRate:  maxPerSecond,
		interval: time.Second,
		stopCh:   make(chan struct{}),
	}

	if maxPerSecond > 0 {
		go l.refill()
	}

	return l
}

// Wait blocks until a token is available or the context is cancelled.
// For an unlimited limiter (rate=0), it returns immediately.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.maxRate <= 0 {
		return nil // unlimited
	}

	for {
		l.mu.Lock()
		if l.tokens > 0 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.stopCh:
			return nil
		case <-time.After(10 * time.Millisecond):
			// spin-wait with small sleep
		}
	}
}

// Stop halts the refill goroutine. Must be called when the limiter is no longer needed.
func (l *Limiter) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.stopped {
		l.stopped = true
		close(l.stopCh)
	}
}

// refill periodically replenishes tokens.
func (l *Limiter) refill() {
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			l.tokens = l.maxRate
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}
