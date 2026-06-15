package workers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
)

// Task represents a generic executable job pulled from the durable stream.
type Task struct {
	ID        string                 `json:"id"`
	Type      CapabilityType         `json:"type"`
	Target    string                 `json:"target"`
	Payload   map[string]interface{} `json:"payload"`
	SessionID string                 `json:"session_id"`
}

// TaskHandler is the signature for logic executing a specific capability.
type TaskHandler func(ctx context.Context, task Task) error

// Executor pulls tasks from streams mapped to the worker's capabilities.
type Executor struct {
	Worker   *Worker
	Handlers map[CapabilityType]TaskHandler
}

// NewExecutor creates an executor bound to a specific worker.
func NewExecutor(w *Worker) *Executor {
	return &Executor{
		Worker:   w,
		Handlers: make(map[CapabilityType]TaskHandler),
	}
}

// RegisterHandler binds a specific TaskHandler function to a CapabilityType.
func (e *Executor) RegisterHandler(cap CapabilityType, handler TaskHandler) {
	e.Handlers[cap] = handler
}

// Run starts consuming queues for all registered capabilities.
func (e *Executor) Run(ctx context.Context) error {
	if e.Worker == nil {
		return nil
	}

	if e.Worker.Stream == nil {
		return nil
	}

	for _, cap := range e.Worker.Capabilities {
		handler, ok := e.Handlers[cap]
		if !ok {
			slog.Warn("Capability registered but no handler defined", "capability", cap)
			continue
		}

		subject := fmt.Sprintf("task.%s.>", cap)
		queueGroup := fmt.Sprintf("workers_%s", cap)

		err := e.Worker.Stream.SubscribeWorker(ctx, subject, queueGroup, func(data []byte) error {
			var t Task
			if err := json.Unmarshal(data, &t); err != nil {
				// Malformed JSON is considered a poison pill. We should NOT retry it infinitely.
				slog.Error("Poison pill detected: malformed task JSON", "error", err)
				return nil // returning nil AckSyncs it to clear the poison
			}

			// Idempotency check: Skip if task already completed
			if e.Worker.IdempotencyMgr != nil {
				processed, err := e.Worker.IdempotencyMgr.HasBeenProcessed(t.ID)
				if err != nil {
					slog.Warn("Failed to check idempotency", "taskID", t.ID, "error", err)
					return err
				}
				if processed {
					slog.Info("Task already processed (idempotent), skipping", "taskID", t.ID, "target", t.Target)
					return nil // Idempotently skip
				}

				// Register task as claimed
				if err := e.Worker.IdempotencyMgr.Register(context.Background(), t.ID, e.Worker.ID); err != nil {
					if err == queue.ErrTaskAlreadyProcessed {
						slog.Info("Task claimed by another worker (idempotent), skipping", "taskID", t.ID)
						return nil
					}
					return err
				}
			}

			// Distributed Lease: Ensure no other worker is currently executing this exact target in this session
			leaseKey := fmt.Sprintf("lease:%s:%s:%s", t.SessionID, t.Type, t.Target)
			if err := e.Worker.LeaseMgr.Acquire(leaseKey, e.Worker.ID); err != nil {
				if err == queue.ErrLeaseUnavailable {
					slog.Info("Target already locked by another lease, skipping", "taskID", t.ID, "target", t.Target)
					return nil // Already handled
				}
				return err // Retry on NATS error
			}

			// Start KeepAlive for the lease while task runs
			leaseCtx, cancelLease := context.WithCancel(ctx)
			go e.Worker.LeaseMgr.KeepAlive(leaseCtx, leaseKey, e.Worker.ID)

			defer func() {
				cancelLease()
				if err := e.Worker.LeaseMgr.Release(leaseKey); err != nil {
					slog.Warn("Failed to release lease", "key", leaseKey, "error", err)
				}
			}()

			parentID := ""
			if t.Payload != nil {
				if pid, ok := t.Payload["_trace_parent_id"].(string); ok {
					parentID = pid
				}
			}
			workerSpanName := fmt.Sprintf("Worker.%s", t.Type)
			workerCtx, workerSpanID := telemetry.InternalTracer.StartSpan(ctx, workerSpanName, parentID)
			defer func() {
				telemetry.InternalTracer.EndSpan(workerSpanID, map[string]interface{}{
					"task_id": t.ID,
					"target":  t.Target,
				})
			}()

			slog.Info("Worker executing task", "taskID", t.ID, "type", t.Type, "target", t.Target, "span_id", workerSpanID)
			return handler(workerCtx, t)
		})

		if err != nil {
			return fmt.Errorf("failed to bind worker stream for %s: %w", cap, err)
		}
	}

	<-ctx.Done()
	return nil
}
