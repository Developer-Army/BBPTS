package tools

import (
	"context"
	"log/slog"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// WorkerPool manages rate-limited concurrent target processing.
type WorkerPool struct {
	workers int
	limiter *rate.Limiter
}

// NewWorkerPool creates a new rate-limited worker pool.
func NewWorkerPool(workers int, r rate.Limit) *WorkerPool {
	var lim *rate.Limiter
	if r > 0 {
		lim = rate.NewLimiter(r, int(r)*2)
	}
	return &WorkerPool{
		workers: workers,
		limiter: lim,
	}
}

// Process executes fn on each target concurrently up to the worker limit.
func (p *WorkerPool) Process(ctx context.Context, targets []string, fn func(ctx context.Context, target string) ([]recon.Event, error)) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	g, ctx := errgroup.WithContext(ctx)

	targetChan := make(chan string, len(targets))
	for _, t := range targets {
		targetChan <- t
	}
	close(targetChan)

	var mu sync.Mutex
	var allEvents []recon.Event

	workersCount := p.workers
	if workersCount > len(targets) {
		workersCount = len(targets)
	}
	if workersCount < 1 {
		workersCount = 1
	}

	for i := 0; i < workersCount; i++ {
		g.Go(func() error {
			for target := range targetChan {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				if p.limiter != nil {
					if err := p.limiter.Wait(ctx); err != nil {
						return err
					}
				}

				events, err := fn(ctx, target)
				if err != nil {
					slog.Debug("target execution error", "target", target, "error", err)
					continue
				}

				if len(events) > 0 {
					mu.Lock()
					allEvents = append(allEvents, events...)
					mu.Unlock()
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return allEvents, nil
}
