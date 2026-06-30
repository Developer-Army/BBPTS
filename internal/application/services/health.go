package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

type HealthMonitor struct {
	bus     queue.EventBus
	workers map[string]time.Time
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewHealthMonitor(b queue.EventBus) *HealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	h := &HealthMonitor{
		bus:     b,
		workers: make(map[string]time.Time),
		ctx:     ctx,
		cancel:  cancel,
	}
	return h
}

func (h *HealthMonitor) Start() {
	ch := h.bus.Subscribe("worker.heartbeat")

	go func() {
		defer h.bus.Unsubscribe(ch)
		for {
			select {
			case <-h.ctx.Done():
				return
			case ev := <-ch:
				h.mu.Lock()
				h.workers[ev.Source] = time.Now()
				h.mu.Unlock()
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-ticker.C:
				h.checkHealth()
			}
		}
	}()
}

func (h *HealthMonitor) checkHealth() {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	for workerID, lastSeen := range h.workers {

		if now.Sub(lastSeen) > 35*time.Second {
			slog.Warn("Worker node missed heartbeats, evicting from mesh", "worker", workerID)
			delete(h.workers, workerID)

			h.bus.Publish(queue.Event{
				Type:   "worker.dead",
				Source: "monitor",
				Target: workerID,
			})
		}
	}
}

func (h *HealthMonitor) Stop() {
	h.cancel()
}

func BroadcastHeartbeat(ctx context.Context, b queue.EventBus, workerID string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:

			props := map[string]string{
				"status": "healthy",
			}
			b.Publish(queue.Event{
				Type:       "worker.heartbeat",
				Source:     workerID,
				Properties: props,
			})
		}
	}
}
