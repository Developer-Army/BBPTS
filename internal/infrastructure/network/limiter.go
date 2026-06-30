// Package network provides network-related infrastructure components
package network

import (
	"context"

	"golang.org/x/time/rate"
)

type Limiter struct {
	limiter *rate.Limiter
}

func New(maxPerSecond int) *Limiter {
	if maxPerSecond <= 0 {
		return &Limiter{}
	}

	return &Limiter{
		limiter: rate.NewLimiter(rate.Limit(maxPerSecond), maxPerSecond),
	}
}

func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.limiter == nil {
		return nil
	}
	return l.limiter.Wait(ctx)
}

func (l *Limiter) Stop() {

}
