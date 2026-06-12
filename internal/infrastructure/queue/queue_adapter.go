package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
)

// QueueBackend defines the interface for queue backends (NATS or Redis).
type QueueBackend interface {
	PublishTask(subject string, payload interface{}) error
	SubscribeWorker(ctx context.Context, subject, consumerName string, handler func(data []byte) error) error
	Close() error
}

// QueueAdapter provides a unified interface for switching between NATS and Redis.
type QueueAdapter struct {
	backend     QueueBackend
	backendType string // "nats" or "redis"
}

// NewQueueAdapter creates a queue adapter with the specified backend.
func NewQueueAdapter(backendType, url string) (*QueueAdapter, error) {
	var backend QueueBackend

	switch backendType {
	case "nats":
		sm, err := NewStreamManager(url)
		if err != nil {
			return nil, fmt.Errorf("failed to create NATS stream manager: %w", err)
		}
		backend = sm
	case "redis":
		rsm, err := NewRedisStreamManager(url)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis stream manager: %w", err)
		}
		backend = rsm
	default:
		return nil, fmt.Errorf("unsupported queue backend: %s (must be 'nats' or 'redis')", backendType)
	}

	return &QueueAdapter{
		backend:     backend,
		backendType: backendType,
	}, nil
}

// PublishTask publishes a task to the underlying backend.
func (qa *QueueAdapter) PublishTask(subject string, payload interface{}) error {
	return qa.backend.PublishTask(subject, payload)
}

// SubscribeWorker subscribes a worker to the underlying backend.
func (qa *QueueAdapter) SubscribeWorker(ctx context.Context, subject, consumerName string, handler func(data []byte) error) error {
	return qa.backend.SubscribeWorker(ctx, subject, consumerName, handler)
}

// Close closes the underlying backend connection.
func (qa *QueueAdapter) Close() error {
	return qa.backend.Close()
}

// BackendType returns the type of backend being used.
func (qa *QueueAdapter) BackendType() string {
	return qa.backendType
}

// TaskEvent represents a task that can be queued.
type TaskEvent struct {
	TaskID     string                 `json:"task_id"`
	TaskType   string                 `json:"task_type"`
	Target     string                 `json:"target"`
	Payload    map[string]interface{} `json:"payload"`
	Priority   int                    `json:"priority"` // Higher = more important
	CreatedAt  int64                  `json:"created_at"`
	RetryCount int                    `json:"retry_count"`
	MaxRetries int                    `json:"max_retries"`
}

// TaskHandler defines the interface for handling tasks.
type TaskHandler interface {
	HandleTask(ctx context.Context, task *TaskEvent) error
}

// TaskConsumer consumes tasks from the queue and processes them with a handler.
type TaskConsumer struct {
	adapter      *QueueAdapter
	consumerName string
	handler      TaskHandler
	idempotency  *IdempotencyManager
}

// NewTaskConsumer creates a new task consumer.
func NewTaskConsumer(adapter *QueueAdapter, consumerName string, handler TaskHandler, idempotency *IdempotencyManager) *TaskConsumer {
	return &TaskConsumer{
		adapter:      adapter,
		consumerName: consumerName,
		handler:      handler,
		idempotency:  idempotency,
	}
}

// Start begins consuming tasks from the queue.
func (tc *TaskConsumer) Start(ctx context.Context, subject string) error {
	return tc.adapter.SubscribeWorker(ctx, subject, tc.consumerName, func(data []byte) error {
		var task TaskEvent
		if err := json.Unmarshal(data, &task); err != nil {
			slog.Error("Failed to unmarshal task", "error", err)
			telemetry.QueueDroppedMessages.WithLabelValues(subject, tc.adapter.backendType, "unmarshal_error").Inc()
			return err
		}

		telemetry.QueueMessageRate.WithLabelValues(task.TaskType, tc.adapter.backendType, "subscribe").Inc()

		// Check idempotency - skip if already processed
		alreadyProcessed, err := tc.idempotency.HasBeenProcessed(task.TaskID)
		if err != nil {
			slog.Warn("Failed to check idempotency", "task_id", task.TaskID, "error", err)
		}
		if alreadyProcessed {
			slog.Debug("Task already processed, skipping", "task_id", task.TaskID)
			telemetry.QueueDroppedMessages.WithLabelValues(task.TaskType, tc.adapter.backendType, "duplicate").Inc()
			return nil
		}

		// Register task as being processed
		if err := tc.idempotency.Register(ctx, task.TaskID, tc.consumerName); err != nil {
			if err == ErrTaskAlreadyProcessed {
				slog.Debug("Task already claimed by another worker", "task_id", task.TaskID)
				telemetry.QueueDroppedMessages.WithLabelValues(task.TaskType, tc.adapter.backendType, "claimed").Inc()
				return nil
			}
			return err
		}

		startTime := time.Now()
		// Handle the task
		err = tc.handler.HandleTask(ctx, &task)
		duration := time.Since(startTime).Seconds()

		// Record completion
		status := "success"
		if err != nil {
			status = "failed"
			task.RetryCount++
			if task.RetryCount < task.MaxRetries {
				// Exponential backoff delay
				backoff := time.Duration(1<<uint(task.RetryCount-1)) * time.Second
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
				slog.Warn("Task failed, waiting backoff and re-queueing", "task_id", task.TaskID, "backoff", backoff, "retry", task.RetryCount, "error", err)

				telemetry.QueueRetryCount.WithLabelValues(subject, tc.adapter.backendType).Inc()
				telemetry.WorkerTaskErrors.WithLabelValues(tc.consumerName, task.TaskType, "retry").Inc()

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}

				if publishErr := tc.adapter.PublishTask(subject, task); publishErr != nil {
					slog.Error("Failed to re-queue task", "task_id", task.TaskID, "error", publishErr)
				}
				return err
			} else {
				// DLQ support
				dlqSubject := subject + ".dlq"
				slog.Error("Task max retries reached. Publishing to DLQ", "task_id", task.TaskID, "dlq", dlqSubject)
				telemetry.QueueDroppedMessages.WithLabelValues(subject, tc.adapter.backendType, "dlq").Inc()
				telemetry.WorkerTaskErrors.WithLabelValues(tc.consumerName, task.TaskType, "dlq").Inc()
				if dlqErr := tc.adapter.PublishTask(dlqSubject, task); dlqErr != nil {
					slog.Error("Failed to publish to DLQ", "task_id", task.TaskID, "error", dlqErr)
				}
			}
		} else {
			telemetry.QueueMessageRate.WithLabelValues(task.TaskType, tc.adapter.backendType, "process_success").Inc()
			telemetry.WorkerTaskDuration.WithLabelValues(tc.consumerName, task.TaskType).Observe(duration)
		}

		// Mark as complete
		if completeErr := tc.idempotency.Complete(task.TaskID, tc.consumerName, status, 0, nil, err); completeErr != nil {
			slog.Warn("Failed to mark task complete", "task_id", task.TaskID, "error", completeErr)
		}

		return err
	})
}
