package tools

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

type requestRateTracker struct {
	mu      sync.Mutex
	buckets [10]int64 // one bucket per second
	idx     int
	lastSec int64
	total   int64
}

var globalRateTracker = &requestRateTracker{}

func RecordHTTPRequest() {
	now := time.Now().Unix()
	t := globalRateTracker
	t.mu.Lock()
	defer t.mu.Unlock()
	if now != t.lastSec {

		steps := int(now - t.lastSec)
		if steps > 10 {
			steps = 10
		}
		for i := 0; i < steps; i++ {
			t.idx = (t.idx + 1) % 10
			t.buckets[t.idx] = 0
		}
		t.lastSec = now
	}
	t.buckets[t.idx]++
	atomic.AddInt64(&t.total, 1)
}

func CurrentRequestRate() int {
	t := globalRateTracker
	t.mu.Lock()
	defer t.mu.Unlock()
	var sum int64
	for _, v := range t.buckets {
		sum += v
	}
	return int(sum / 10)
}

type progressCallbackKey struct{}

type ProgressCallback func(toolName string, done, total int)

func WithProgressCallback(ctx context.Context, cb ProgressCallback) context.Context {
	return context.WithValue(ctx, progressCallbackKey{}, cb)
}

func progressCallbackFromCtx(ctx context.Context) ProgressCallback {
	if cb, ok := ctx.Value(progressCallbackKey{}).(ProgressCallback); ok {
		return cb
	}
	return nil
}

type WorkerPool struct {
	workers  int
	limiter  *rate.Limiter
	toolName string // for progress reporting
}

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

func NewWorkerPoolWithName(workers int, r rate.Limit, toolName string) *WorkerPool {
	p := NewWorkerPool(workers, r)
	p.toolName = toolName
	return p
}

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
	if recon.LowResourceFromCtx(ctx) {
		if workersCount > 2 {
			workersCount = 2
		}
	}
	if workersCount > len(targets) {
		workersCount = len(targets)
	}
	if workersCount < 1 {
		workersCount = 1
	}

	total := len(targets)
	var done int64

	progressCb := progressCallbackFromCtx(ctx)
	toolName := p.toolName

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

				RecordHTTPRequest()

				if len(events) > 0 {
					mu.Lock()
					allEvents = append(allEvents, events...)
					mu.Unlock()
				}

				if progressCb != nil && toolName != "" {
					doneNow := int(atomic.AddInt64(&done, 1))
					progressCb(toolName, doneNow, total)
				} else {
					atomic.AddInt64(&done, 1)
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
