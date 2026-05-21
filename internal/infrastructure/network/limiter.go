// Package network provides network-related infrastructure components
package network

import (
	"context"

	"golang.org/x/time/rate"
)

// Limiter controls the rate of operations using x/time/rate's token bucket.
// It is safe for concurrent use by multiple goroutines.
type Limiter struct {
	limiter *rate.Limiter
}

// New creates a new rate limiter that allows maxPerSecond operations per second.
// If maxPerSecond is <= 0, the limiter is effectively unlimited.
func New(maxPerSecond int) *Limiter {
	if maxPerSecond <= 0 {
		return &Limiter{}
	}

	return &Limiter{
		limiter: rate.NewLimiter(rate.Limit(maxPerSecond), maxPerSecond),
	}
}

// Wait blocks until a token is available or the context is cancelled.
// For an unlimited limiter (rate=0), it returns immediately.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.limiter == nil {
		return nil // unlimited
	}
	return l.limiter.Wait(ctx)
}

// Stop is retained for callers that previously needed to stop the custom refill goroutine.
func (l *Limiter) Stop() {
	// x/time/rate does not own a goroutine, so there is nothing to stop.
}
