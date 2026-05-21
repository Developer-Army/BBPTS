package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Checkpoint tracks the execution state of an ongoing scan.
// If the orchestrator crashes, it can load this file to resume.
type Checkpoint struct {
	Scope           string     `json:"scope"`
	StartTime       time.Time  `json:"start_time"`
	TargetsPending  []string   `json:"targets_pending"`
	TargetsComplete []string   `json:"targets_complete"`
	Mu              sync.Mutex `json:"-"`
	FilePath        string     `json:"-"`
}

// NewCheckpoint creates or loads a checkpoint for the given scope.
func NewCheckpoint(dir, scope string, targets []string) (*Checkpoint, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, scope+"_checkpoint.json")

	// Try to load existing
	if data, err := os.ReadFile(path); err == nil {
		var cp Checkpoint
		if err := json.Unmarshal(data, &cp); err == nil {
			cp.FilePath = path
			return &cp, nil
		}
	}

	// Create new
	cp := &Checkpoint{
		Scope:          scope,
		StartTime:      time.Now().UTC(),
		TargetsPending: targets,
		FilePath:       path,
	}
	cp.Save()
	return cp, nil
}

// MarkComplete moves a target from pending to complete and saves state.
func (c *Checkpoint) MarkComplete(target string) {
	c.Mu.Lock()
	defer c.Mu.Unlock()

	var newPending []string
	for _, t := range c.TargetsPending {
		if t != target {
			newPending = append(newPending, t)
		}
	}
	c.TargetsPending = newPending
	c.TargetsComplete = append(c.TargetsComplete, target)

	// In a real high-throughput system, we might debounce this save
	c.saveInternal()
}

// Save persists the checkpoint to disk.
func (c *Checkpoint) Save() {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.saveInternal()
}

func (c *Checkpoint) saveInternal() {
	data, err := json.Marshal(c)
	if err == nil {
		_ = os.WriteFile(c.FilePath, data, 0600)
	}
}

// Clear removes the checkpoint file (called upon successful scan completion).
func (c *Checkpoint) Clear() {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	_ = os.Remove(c.FilePath)
}
