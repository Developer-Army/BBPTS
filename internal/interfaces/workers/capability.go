package workers

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

type CapabilityType string

const (
	CapSubdomainEnum CapabilityType = "subdomain_enum"
	CapPortScan      CapabilityType = "port_scan"
	CapBrowserRecon  CapabilityType = "browser_recon"
	CapJSDiff        CapabilityType = "js_diff"
)

type Worker struct {
	ID             string
	Capabilities   []CapabilityType
	Stream         *queue.StreamManager
	LeaseMgr       *queue.LeaseManager
	IdempotencyMgr *queue.IdempotencyManager
	mu             sync.RWMutex
	isActive       bool
}

func NewWorker(workerID string, stream *queue.StreamManager, leaseMgr *queue.LeaseManager, caps []CapabilityType) *Worker {
	if caps == nil {
		caps = []CapabilityType{}
	}
	return &Worker{
		ID:             workerID,
		Stream:         stream,
		LeaseMgr:       leaseMgr,
		Capabilities:   caps,
		IdempotencyMgr: nil,
	}
}

func (w *Worker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.isActive {
		w.mu.Unlock()
		return fmt.Errorf("worker %s already active", w.ID)
	}
	w.isActive = true
	w.mu.Unlock()

	go w.heartbeat(ctx)
	slog.Info("Worker node started", "workerID", w.ID, "capabilities", w.Capabilities)
	return nil
}

func (w *Worker) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Worker heartbeat stopped", "workerID", w.ID)
			return
		case <-ticker.C:

			payload := map[string]interface{}{
				"worker_id":    w.ID,
				"capabilities": w.Capabilities,
				"timestamp":    time.Now().Unix(),
				"status":       "healthy",
			}
			if err := w.Stream.PublishTask("system.worker.heartbeat", payload); err != nil {
				slog.Warn("Failed to publish worker heartbeat", "workerID", w.ID, "error", err)
			}
		}
	}
}
