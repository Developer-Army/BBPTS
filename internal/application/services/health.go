package services

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

// HealthMonitor tracks the active worker nodes in the distributed mesh.
type HealthMonitor struct {
	bus     queue.EventBus
	workers map[string]time.Time
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewHealthMonitor creates a monitor that listens to heartbeat events.
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

// Start begins listening for heartbeats and evicting dead workers.
func (h *HealthMonitor) Start() {
	ch := h.bus.Subscribe("worker.heartbeat")

	go func() {
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
		// If a worker misses 3 heartbeats (assuming 10s interval), consider it dead
		if now.Sub(lastSeen) > 35*time.Second {
			slog.Warn("Worker node missed heartbeats, evicting from mesh", "worker", workerID)
			delete(h.workers, workerID)

			// Publish a dead worker event so the orchestrator can reassign leased workloads
			h.bus.Publish(queue.Event{
				Type:   "worker.dead",
				Source: "monitor",
				Target: workerID,
			})
		}
	}
}

// Stop gracefully shuts down the monitor.
func (h *HealthMonitor) Stop() {
	h.cancel()
}

// BroadcastHeartbeat is called by the worker node to announce it is alive.
func BroadcastHeartbeat(ctx context.Context, b queue.EventBus, workerID string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send telemetry as properties (memory usage, running tasks)
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
