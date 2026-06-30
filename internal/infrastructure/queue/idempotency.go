package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	ErrTaskAlreadyProcessed = errors.New("task already processed (idempotent)")
	ErrTaskNotFound         = errors.New("task result not found in replay store")
)

type TaskResult struct {
	TaskID      string                   `json:"task_id"`
	Status      string                   `json:"status"` // "success", "failed", "skipped"
	EventCount  int                      `json:"event_count"`
	Events      []map[string]interface{} `json:"events,omitempty"`
	Error       string                   `json:"error,omitempty"`
	CompletedAt int64                    `json:"completed_at"`
	WorkerID    string                   `json:"worker_id"`
}

type IdempotencyManager struct {
	kv nats.KeyValue
}

func NewIdempotencyManager(js nats.JetStreamContext, bucketName string) (*IdempotencyManager, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Task Idempotency and Replay Store for BBPTS",
				TTL:         72 * time.Hour,
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

func (im *IdempotencyManager) Register(ctx context.Context, taskID, workerID string) error {
	if im.kv == nil {
		return errors.New("kv store is nil")
	}

	key := fmt.Sprintf("task:%s:claimed", taskID)

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

func (im *IdempotencyManager) Complete(taskID, workerID, status string, eventCount int, events []map[string]interface{}, taskErr error) error {
	if im.kv == nil {
		return errors.New("kv store is nil")
	}

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

func (im *IdempotencyManager) GetResult(taskID string) (*TaskResult, error) {
	if im.kv == nil {
		return nil, errors.New("kv store is nil")
	}

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

func (im *IdempotencyManager) HasBeenProcessed(taskID string) (bool, error) {
	if im.kv == nil {
		return false, errors.New("kv store is nil")
	}

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

type EventDeduper struct {
	kv nats.KeyValue
}

func NewEventDeduper(js nats.JetStreamContext, bucketName string) (*EventDeduper, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Event Deduplication Store for BBPTS",
				TTL:         72 * time.Hour,
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

func (ed *EventDeduper) RecordEvent(target, source, eventType string) error {
	if ed.kv == nil {
		return errors.New("kv store is nil")
	}

	key := fmt.Sprintf("event:%s:%s:%s", eventType, source, target)
	_, err := ed.kv.Put(key, []byte(time.Now().Format(time.RFC3339)))
	return err
}

func (ed *EventDeduper) IsDuplicate(target, source, eventType string) (bool, error) {
	if ed.kv == nil {
		return false, errors.New("kv store is nil")
	}

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

type SessionReplayLog struct {
	kv nats.KeyValue
}

func NewSessionReplayLog(js nats.JetStreamContext, bucketName string) (*SessionReplayLog, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Session Replay Log for BBPTS scans",
				TTL:         7 * 24 * time.Hour,
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

func (srl *SessionReplayLog) LogTaskInSession(sessionID, taskID, status string, eventCount int) error {
	if srl.kv == nil {
		return errors.New("kv store is nil")
	}

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

func (srl *SessionReplayLog) GetSessionTasks(sessionID string) ([]map[string]interface{}, error) {
	if srl.kv == nil {
		return nil, errors.New("kv store is nil")
	}

	keys, err := srl.kv.Keys()
	if err != nil {
		if errors.Is(err, nats.ErrNoKeysFound) {
			return []map[string]interface{}{}, nil
		}
		return nil, err
	}

	var tasks []map[string]interface{}
	prefix := fmt.Sprintf("session:%s:task:", sessionID)
	for _, key := range keys {
		if strings.HasPrefix(key, prefix) {
			entry, err := srl.kv.Get(key)
			if err != nil {
				continue
			}
			var task map[string]interface{}
			if err := json.Unmarshal(entry.Value(), &task); err == nil {
				tasks = append(tasks, task)
			}
		}
	}
	return tasks, nil
}
