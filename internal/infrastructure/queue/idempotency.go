package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	ErrTaskAlreadyProcessed = errors.New("task already processed (idempotent)")
	ErrTaskNotFound         = errors.New("task result not found in replay store")
)

// TaskResult holds the output of a completed task for replay purposes.
type TaskResult struct {
	TaskID      string                   `json:"task_id"`
	Status      string                   `json:"status"` // "success", "failed", "skipped"
	EventCount  int                      `json:"event_count"`
	Events      []map[string]interface{} `json:"events,omitempty"`
	Error       string                   `json:"error,omitempty"`
	CompletedAt int64                    `json:"completed_at"`
	WorkerID    string                   `json:"worker_id"`
}

// IdempotencyManager ensures tasks are executed exactly once and enables replay.
// It uses NATS KeyValue for durable, distributed idempotency tracking.
type IdempotencyManager struct {
	kv nats.KeyValue
}

// NewIdempotencyManager creates a manager for task deduplication and replay.
func NewIdempotencyManager(js nats.JetStreamContext, bucketName string) (*IdempotencyManager, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Task Idempotency and Replay Store for BBPTS",
				TTL:         72 * time.Hour, // Keep results for 3 days for replay
				Storage:     nats.FileStorage,
				Replicas:    1,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create idempotency KV bucket: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to bind to idempotency KV bucket: %w", err)
		}
	}

	return &IdempotencyManager{kv: kv}, nil
}

// Register marks a task as started (claims it). Returns error if already claimed.
func (im *IdempotencyManager) Register(ctx context.Context, taskID, workerID string) error {
	key := fmt.Sprintf("task:%s:claimed", taskID)

	// Try to create the key (fails if already exists)
	_, err := im.kv.Create(key, []byte(workerID))
	if err != nil {
		if errors.Is(err, nats.ErrKeyExists) {
			return ErrTaskAlreadyProcessed
		}
		return fmt.Errorf("failed to register task: %w", err)
	}

	slog.Debug("Task registered for execution", "task_id", taskID, "worker_id", workerID)
	return nil
}

// Complete records the task result for replay and idempotency.
func (im *IdempotencyManager) Complete(taskID, workerID, status string, eventCount int, events []map[string]interface{}, taskErr error) error {
	result := TaskResult{
		TaskID:      taskID,
		Status:      status,
		EventCount:  eventCount,
		Events:      events,
		CompletedAt: time.Now().Unix(),
		WorkerID:    workerID,
	}

	if taskErr != nil {
		result.Error = taskErr.Error()
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal task result: %w", err)
	}

	key := fmt.Sprintf("task:%s:result", taskID)
	_, err = im.kv.Put(key, resultJSON)
	if err != nil {
		return fmt.Errorf("failed to store task result: %w", err)
	}

	slog.Debug("Task result stored", "task_id", taskID, "status", status, "event_count", eventCount)
	return nil
}

// GetResult retrieves a previously completed task for replay.
func (im *IdempotencyManager) GetResult(taskID string) (*TaskResult, error) {
	key := fmt.Sprintf("task:%s:result", taskID)

	entry, err := im.kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return nil, ErrTaskNotFound
		}
		return nil, fmt.Errorf("failed to retrieve task result: %w", err)
	}

	var result TaskResult
	if err := json.Unmarshal(entry.Value(), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal task result: %w", err)
	}

	slog.Debug("Task result retrieved from store", "task_id", taskID, "status", result.Status)
	return &result, nil
}

// HasBeenProcessed checks if a task has already been completed (idempotency check).
func (im *IdempotencyManager) HasBeenProcessed(taskID string) (bool, error) {
	key := fmt.Sprintf("task:%s:result", taskID)

	_, err := im.kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check task status: %w", err)
	}

	return true, nil
}

// EventDeduper tracks which events have been published to prevent duplicates.
type EventDeduper struct {
	kv nats.KeyValue
}

// NewEventDeduper creates a deduplication tracker for events.
func NewEventDeduper(js nats.JetStreamContext, bucketName string) (*EventDeduper, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Event Deduplication Store for BBPTS",
				TTL:         72 * time.Hour, // Keep event hashes for 3 days
				Storage:     nats.FileStorage,
				Replicas:    1,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create event dedup KV bucket: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to bind to event dedup KV bucket: %w", err)
		}
	}

	return &EventDeduper{kv: kv}, nil
}

// RecordEvent marks an event as published. Uses event hash (target+source+type) as key.
func (ed *EventDeduper) RecordEvent(target, source, eventType string) error {
	key := fmt.Sprintf("event:%s:%s:%s", eventType, source, target)
	_, err := ed.kv.Put(key, []byte(time.Now().Format(time.RFC3339)))
	return err
}

// IsDuplicate checks if an event has already been published.
func (ed *EventDeduper) IsDuplicate(target, source, eventType string) (bool, error) {
	key := fmt.Sprintf("event:%s:%s:%s", eventType, source, target)
	_, err := ed.kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check event dedup: %w", err)
	}
	return true, nil
}

// SessionReplayLog tracks all events/tasks in a scan session for replay and audit.
type SessionReplayLog struct {
	kv nats.KeyValue
}

// NewSessionReplayLog creates a logger for session events.
func NewSessionReplayLog(js nats.JetStreamContext, bucketName string) (*SessionReplayLog, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Session Replay Log for BBPTS scans",
				TTL:         7 * 24 * time.Hour, // Keep session logs for a week
				Storage:     nats.FileStorage,
				Replicas:    1,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create session replay log KV bucket: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to bind to session replay log KV bucket: %w", err)
		}
	}

	return &SessionReplayLog{kv: kv}, nil
}

// LogTaskInSession records a task execution in a session.
func (srl *SessionReplayLog) LogTaskInSession(sessionID, taskID, status string, eventCount int) error {
	key := fmt.Sprintf("session:%s:task:%s", sessionID, taskID)
	logEntry := map[string]interface{}{
		"task_id":     taskID,
		"status":      status,
		"event_count": eventCount,
		"timestamp":   time.Now().Unix(),
	}
	data, err := json.Marshal(logEntry)
	if err != nil {
		return err
	}
	_, err = srl.kv.Put(key, data)
	return err
}

// GetSessionTasks retrieves all tasks executed in a session (useful for audit/replay).
// Note: Full session audit would require external analytics layer (ClickHouse, Elasticsearch).
func (srl *SessionReplayLog) GetSessionTasks(sessionID string) ([]map[string]interface{}, error) {
	slog.Debug("Session audit trail retrieval (integrate with analytics)", "session_id", sessionID)
	return []map[string]interface{}{}, nil
}
