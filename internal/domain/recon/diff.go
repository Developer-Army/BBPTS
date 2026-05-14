package recon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Artifact represents a historical reconnaissance object.
type Artifact struct {
	ID        string
	Type      string // "endpoint", "js_file", "subdomain"
	Value     string
	Hash      string // Hash of the content/response body
	FirstSeen time.Time
	LastSeen  time.Time
}

// DiffStore manages historical artifacts to enable differential intelligence.
type DiffStore struct {
	// In a real DB, this is backed by KV or SQL. In-memory for now.
	store map[string]Artifact
}

func NewDiffStore() *DiffStore {
	return &DiffStore{
		store: make(map[string]Artifact),
	}
}

// DiffResult contains the changes detected during the current recon wave.
type DiffResult struct {
	NewTargets []Artifact
	Changed    []Artifact
}

// AnalyzeChanges compares the current recon wave against historical memory.
// It returns only the intelligence that is NEW or CHANGED.
func (d *DiffStore) AnalyzeChanges(currentWave []Artifact) *DiffResult {
	res := &DiffResult{}

	for _, curr := range currentWave {
		id := fmt.Sprintf("%s:%s", curr.Type, curr.Value)
		past, exists := d.store[id]

		if !exists {
			// Net-new attack surface discovered
			curr.FirstSeen = time.Now()
			curr.LastSeen = time.Now()
			curr.ID = id
			d.store[id] = curr
			res.NewTargets = append(res.NewTargets, curr)
			slog.Info("Differential Recon: New attack surface discovered", "type", curr.Type, "value", curr.Value)
			continue
		}

		// The target exists. Let's check if its signature/hash changed.
		if past.Hash != curr.Hash && curr.Hash != "" {
			past.Hash = curr.Hash
			past.LastSeen = time.Now()
			d.store[id] = past
			res.Changed = append(res.Changed, curr)
			slog.Info("Differential Recon: Target changed state", "type", curr.Type, "value", curr.Value)
		} else {
			// No change, just update LastSeen
			past.LastSeen = time.Now()
			d.store[id] = past
		}
	}

	return res
}

// CalculateHash provides a consistent string hash for diffing response bodies or JS ASTs.
func CalculateHash(content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}
