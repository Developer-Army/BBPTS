package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	ErrCheckpointNotFound = errors.New("checkpoint not found")
)

// Checkpoint represents a saved state in the recon pipeline.
type Checkpoint struct {
	SessionID   string                 `json:"session_id"`
	Stage       string                 `json:"stage"` // e.g., "subdomain_enum", "port_scan", "crawl"
	Target      string                 `json:"target"`
	Status      string                 `json:"status"`   // "pending", "in_progress", "completed", "failed"
	Progress    float64                `json:"progress"` // 0.0 to 1.0
	Data        map[string]interface{} `json:"data,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CreatedAt   int64                  `json:"created_at"`
	UpdatedAt   int64                  `json:"updated_at"`
	WorkerID    string                 `json:"worker_id"`
	LeaseExpiry int64                  `json:"lease_expiry,omitempty"`
}

// CheckpointManager manages checkpoint state for resumable scans.
type CheckpointManager struct {
	kv     nats.KeyValue
	leases *LeaseManager
	mu     sync.RWMutex
}

// NewCheckpointManager creates a manager for checkpointing scan progress.
func NewCheckpointManager(js nats.JetStreamContext, bucketName string, leases *LeaseManager) (*CheckpointManager, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Checkpoint Store for BBPTS resumable scans",
				TTL:         7 * 24 * time.Hour, // Keep checkpoints for a week
				Storage:     nats.FileStorage,
				Replicas:    1,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create checkpoint KV bucket: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to bind to checkpoint KV bucket: %w", err)
		}
	}

	return &CheckpointManager{
		kv:     kv,
		leases: leases,
	}, nil
}

// SaveCheckpoint saves or updates a checkpoint.
func (cm *CheckpointManager) SaveCheckpoint(cp *Checkpoint) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cp.UpdatedAt = time.Now().Unix()
	if cp.CreatedAt == 0 {
		cp.CreatedAt = cp.UpdatedAt
	}

	key := fmt.Sprintf("checkpoint:%s:%s:%s", cp.SessionID, cp.Stage, cp.Target)
	data, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	_, err = cm.kv.Put(key, data)
	if err != nil {
		return fmt.Errorf("failed to save checkpoint: %w", err)
	}

	slog.Debug("Checkpoint saved", "session", cp.SessionID, "stage", cp.Stage, "target", cp.Target, "progress", cp.Progress)
	return nil
}

// GetCheckpoint retrieves a checkpoint for a specific session, stage, and target.
func (cm *CheckpointManager) GetCheckpoint(sessionID, stage, target string) (*Checkpoint, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	key := fmt.Sprintf("checkpoint:%s:%s:%s", sessionID, stage, target)
	entry, err := cm.kv.Get(key)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("failed to retrieve checkpoint: %w", err)
	}

	var cp Checkpoint
	if err := json.Unmarshal(entry.Value(), &cp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}

	return &cp, nil
}

// GetSessionCheckpoints retrieves all checkpoints for a session.
func (cm *CheckpointManager) GetSessionCheckpoints(sessionID string) ([]*Checkpoint, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Use a watcher to iterate through keys matching the pattern
	watcher, err := cm.kv.Watch(fmt.Sprintf("checkpoint:%s>", sessionID))
	if err != nil {
		return nil, fmt.Errorf("failed to create key watcher: %w", err)
	}
	defer watcher.Stop()

	var checkpoints []*Checkpoint
	for entry := range watcher.Updates() {
		if entry == nil {
			break
		}

		var cp Checkpoint
		if err := json.Unmarshal(entry.Value(), &cp); err != nil {
			slog.Warn("Failed to unmarshal checkpoint", "key", entry.Key(), "error", err)
			continue
		}

		checkpoints = append(checkpoints, &cp)
	}

	return checkpoints, nil
}

// DeleteCheckpoint removes a checkpoint.
func (cm *CheckpointManager) DeleteCheckpoint(sessionID, stage, target string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	key := fmt.Sprintf("checkpoint:%s:%s:%s", sessionID, stage, target)
	return cm.kv.Delete(key)
}

// DeleteSession removes all checkpoints for a session.
func (cm *CheckpointManager) DeleteSession(sessionID string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Use a watcher to iterate through keys matching the pattern
	watcher, err := cm.kv.Watch(fmt.Sprintf("checkpoint:%s>", sessionID))
	if err != nil {
		return fmt.Errorf("failed to create key watcher: %w", err)
	}
	defer watcher.Stop()

	for entry := range watcher.Updates() {
		if entry == nil {
			break
		}

		if err := cm.kv.Delete(entry.Key()); err != nil {
			slog.Warn("Failed to delete checkpoint", "key", entry.Key(), "error", err)
		}
	}

	slog.Info("Session checkpoints deleted", "session", sessionID)
	return nil
}

// AcquireStageLease acquires a lease for processing a specific stage of a target.
// This ensures only one worker processes a stage at a time.
func (cm *CheckpointManager) AcquireStageLease(ctx context.Context, sessionID, stage, target, workerID string, ttl time.Duration) error {
	leaseKey := fmt.Sprintf("lease:%s:%s:%s", sessionID, stage, target)

	// Try to acquire lease
	if err := cm.leases.Acquire(leaseKey, workerID); err != nil {
		if err == ErrLeaseUnavailable {
			// Lease is held by another worker
			return ErrLeaseUnavailable
		}
		return fmt.Errorf("failed to acquire stage lease: %w", err)
	}

	// Update checkpoint with lease info
	cp, err := cm.GetCheckpoint(sessionID, stage, target)
	if err != nil && err != ErrCheckpointNotFound {
		return err
	}

	if cp == nil {
		cp = &Checkpoint{
			SessionID: sessionID,
			Stage:     stage,
			Target:    target,
			Status:    "in_progress",
			WorkerID:  workerID,
		}
	} else {
		cp.Status = "in_progress"
		cp.WorkerID = workerID
	}
	cp.LeaseExpiry = time.Now().Add(ttl).Unix()

	if err := cm.SaveCheckpoint(cp); err != nil {
		// Rollback lease if checkpoint save fails
		cm.leases.Release(leaseKey)
		return err
	}

	// Start lease renewal in background
	go cm.leases.KeepAlive(ctx, leaseKey, workerID)

	return nil
}

// ReleaseStageLease releases a lease for a stage.
func (cm *CheckpointManager) ReleaseStageLease(sessionID, stage, target string) error {
	leaseKey := fmt.Sprintf("lease:%s:%s:%s", sessionID, stage, target)

	if err := cm.leases.Release(leaseKey); err != nil {
		return fmt.Errorf("failed to release stage lease: %w", err)
	}

	// Update checkpoint
	cp, err := cm.GetCheckpoint(sessionID, stage, target)
	if err == nil && cp != nil {
		cp.LeaseExpiry = 0
		_ = cm.SaveCheckpoint(cp)
	}

	return nil
}

// UpdateProgress updates the progress of a checkpoint.
func (cm *CheckpointManager) UpdateProgress(sessionID, stage, target string, progress float64, data map[string]interface{}) error {
	cp, err := cm.GetCheckpoint(sessionID, stage, target)
	if err != nil {
		if err == ErrCheckpointNotFound {
			// Create new checkpoint
			cp = &Checkpoint{
				SessionID: sessionID,
				Stage:     stage,
				Target:    target,
				Status:    "in_progress",
				Progress:  progress,
				Data:      data,
			}
		} else {
			return err
		}
	} else {
		cp.Progress = progress
		if data != nil {
			if cp.Data == nil {
				cp.Data = make(map[string]interface{})
			}
			for k, v := range data {
				cp.Data[k] = v
			}
		}
	}

	return cm.SaveCheckpoint(cp)
}

// MarkCompleted marks a checkpoint as completed.
func (cm *CheckpointManager) MarkCompleted(sessionID, stage, target string, data map[string]interface{}) error {
	cp, err := cm.GetCheckpoint(sessionID, stage, target)
	if err != nil {
		if err == ErrCheckpointNotFound {
			cp = &Checkpoint{
				SessionID: sessionID,
				Stage:     stage,
				Target:    target,
				Status:    "completed",
				Progress:  1.0,
				Data:      data,
			}
		} else {
			return err
		}
	} else {
		cp.Status = "completed"
		cp.Progress = 1.0
		if data != nil {
			if cp.Data == nil {
				cp.Data = make(map[string]interface{})
			}
			for k, v := range data {
				cp.Data[k] = v
			}
		}
	}

	if err := cm.SaveCheckpoint(cp); err != nil {
		return err
	}

	// Release lease
	_ = cm.ReleaseStageLease(sessionID, stage, target)

	return nil
}

// MarkFailed marks a checkpoint as failed.
func (cm *CheckpointManager) MarkFailed(sessionID, stage, target string, errorMsg string) error {
	cp, err := cm.GetCheckpoint(sessionID, stage, target)
	if err != nil {
		if err == ErrCheckpointNotFound {
			cp = &Checkpoint{
				SessionID: sessionID,
				Stage:     stage,
				Target:    target,
				Status:    "failed",
				Error:     errorMsg,
			}
		} else {
			return err
		}
	} else {
		cp.Status = "failed"
		cp.Error = errorMsg
	}

	if err := cm.SaveCheckpoint(cp); err != nil {
		return err
	}

	// Release lease
	_ = cm.ReleaseStageLease(sessionID, stage, target)

	return nil
}

// GetResumePlan returns a plan for resuming a scan from checkpoints.
func (cm *CheckpointManager) GetResumePlan(sessionID string) (*ResumePlan, error) {
	checkpoints, err := cm.GetSessionCheckpoints(sessionID)
	if err != nil {
		return nil, err
	}

	plan := &ResumePlan{
		SessionID:  sessionID,
		Completed:  make(map[string][]string),
		InProgress: make(map[string][]string),
		Pending:    make(map[string][]string),
		Failed:     make(map[string][]string),
	}

	for _, cp := range checkpoints {
		switch cp.Status {
		case "completed":
			plan.Completed[cp.Stage] = append(plan.Completed[cp.Stage], cp.Target)
		case "in_progress":
			// Check if lease is expired
			if cp.LeaseExpiry > 0 && time.Now().Unix() > cp.LeaseExpiry {
				// Lease expired, treat as pending for retry
				plan.Pending[cp.Stage] = append(plan.Pending[cp.Stage], cp.Target)
			} else {
				plan.InProgress[cp.Stage] = append(plan.InProgress[cp.Stage], cp.Target)
			}
		case "pending":
			plan.Pending[cp.Stage] = append(plan.Pending[cp.Stage], cp.Target)
		case "failed":
			plan.Failed[cp.Stage] = append(plan.Failed[cp.Stage], cp.Target)
		}
	}

	return plan, nil
}

// ResumePlan represents a plan for resuming a scan.
type ResumePlan struct {
	SessionID  string
	Completed  map[string][]string // stage -> targets
	InProgress map[string][]string // stage -> targets
	Pending    map[string][]string // stage -> targets
	Failed     map[string][]string // stage -> targets
}

// CanResume checks if a session can be resumed.
func (rp *ResumePlan) CanResume() bool {
	return len(rp.Pending) > 0 || len(rp.InProgress) > 0 || len(rp.Failed) > 0
}

// GetNextTargets returns the next targets to process for a given stage.
func (rp *ResumePlan) GetNextTargets(stage string) []string {
	// Return pending targets first
	if targets, ok := rp.Pending[stage]; ok && len(targets) > 0 {
		return targets
	}
	// Then failed targets (for retry)
	if targets, ok := rp.Failed[stage]; ok && len(targets) > 0 {
		return targets
	}
	return nil
}
