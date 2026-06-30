package utils

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

type Checkpoint struct {
	Scope           string        `json:"scope"`
	StartTime       time.Time     `json:"start_time"`
	TargetsPending  []string      `json:"targets_pending"`
	TargetsComplete []string      `json:"targets_complete"`
	CompletedStages []int         `json:"completed_stages"`
	CurrentTargets  []string      `json:"current_targets"`
	Events          []recon.Event `json:"events"`
	Mu              sync.Mutex    `json:"-"`
	FilePath        string        `json:"-"`
}

func NewCheckpoint(dir, scope string, targets []string) (*Checkpoint, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, scope+"_checkpoint.json")

	if data, err := os.ReadFile(path); err == nil {
		var cp Checkpoint
		if err := json.Unmarshal(data, &cp); err == nil {
			cp.FilePath = path
			return &cp, nil
		}
	}

	cp := &Checkpoint{
		Scope:          scope,
		StartTime:      time.Now().UTC(),
		TargetsPending: targets,
		FilePath:       path,
	}
	cp.Save()
	return cp, nil
}

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

	c.saveInternal()
}

func (c *Checkpoint) Save() {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.saveInternal()
}

func (c *Checkpoint) saveInternal() {
	data, err := json.Marshal(c)
	if err == nil {
		if errWrite := os.WriteFile(c.FilePath, data, 0600); errWrite != nil {
			slog.Warn("Failed to write checkpoint file", "path", c.FilePath, "error", errWrite)
		}
	}
}

func (c *Checkpoint) Clear() {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if err := os.Remove(c.FilePath); err != nil && !os.IsNotExist(err) {
		slog.Warn("Failed to remove checkpoint file", "path", c.FilePath, "error", err)
	}
}
