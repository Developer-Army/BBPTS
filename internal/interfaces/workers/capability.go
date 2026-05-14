package workers

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

// CapabilityType defines what kind of task a worker can execute.
type CapabilityType string

const (
	CapSubdomainEnum CapabilityType = "subdomain_enum"
	CapPortScan      CapabilityType = "port_scan"
	CapBrowserRecon  CapabilityType = "browser_recon"
	CapJSDiff        CapabilityType = "js_diff"
)

// Worker registers capabilities and manages health heartbeats for the distributed mesh.
type Worker struct {
	ID             string
	Capabilities   []CapabilityType
	Stream         *queue.StreamManager
	LeaseMgr       *queue.LeaseManager
	IdempotencyMgr *queue.IdempotencyManager
	mu             sync.RWMutex
	isActive       bool
}

// NewWorker initializes a new distributed worker node.
func NewWorker(workerID string, stream *queue.StreamManager, leaseMgr *queue.LeaseManager, caps []CapabilityType) *Worker {
	return &Worker{
		ID:             workerID,
		Stream:         stream,
		LeaseMgr:       leaseMgr,
		Capabilities:   caps,
		IdempotencyMgr: nil, // Set by app during initialization
	}
}

// Start makes the worker alive, starting its health heartbeat.
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

// heartbeat continuously publishes the worker's presence and capabilities to the stream.
func (w *Worker) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Worker heartbeat stopped", "workerID", w.ID)
			return
		case <-ticker.C:
			// Publish heartbeat to a system-wide worker registry stream
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
