package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FindingFingerprint is a unique hash of a finding for deduplication.
type FindingFingerprint struct {
	Hash      string    `json:"hash"`
	Source    string    `json:"source"` // Tool name (subfinder, naabu, etc.)
	Type      string    `json:"type"`   // Finding type (subdomain, port, js_endpoint, etc.)
	Target    string    `json:"target"` // The actual finding (domain, IP:port, endpoint, etc.)
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"` // How many times we've seen this
}

// BaselineStore persists baseline findings for differential scanning.
type BaselineStore struct {
	baseDir       string
	sessionID     string
	findings      map[string]*FindingFingerprint // hash -> finding
	mu            sync.RWMutex
	lastSaved     time.Time
	autoSaveEvery time.Duration
}

// NewBaselineStore creates a new baseline store for a scanning session.
func NewBaselineStore(baseDir string, sessionID string) (*BaselineStore, error) {
	// Create baseline directory if it doesn't exist
	baselineDir := filepath.Join(baseDir, ".baseline")
	if err := os.MkdirAll(baselineDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create baseline dir: %w", err)
	}

	bs := &BaselineStore{
		baseDir:       baselineDir,
		sessionID:     sessionID,
		findings:      make(map[string]*FindingFingerprint),
		autoSaveEvery: 1 * time.Minute,
	}

	// Load existing baseline if available
	if err := bs.loadBaseline(); err != nil {
		slog.Warn("Failed to load baseline (fresh scan)", "session", sessionID, "error", err)
	}

	// Start auto-save goroutine
	go bs.autoSaveLoop()

	return bs, nil
}

// loadBaseline loads existing baseline from disk.
func (bs *BaselineStore) loadBaseline() error {
	baselineFile := filepath.Join(bs.baseDir, "baseline.json")
	if _, err := os.Stat(baselineFile); os.IsNotExist(err) {
		return fmt.Errorf("no existing baseline found")
	}

	data, err := os.ReadFile(baselineFile)
	if err != nil {
		return fmt.Errorf("failed to read baseline: %w", err)
	}

	var findings map[string]*FindingFingerprint
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("failed to unmarshal baseline: %w", err)
	}

	bs.mu.Lock()
	bs.findings = findings
	bs.mu.Unlock()

	slog.Info("Baseline loaded", "session", bs.sessionID, "count", len(findings))
	return nil
}

// AddFinding adds a new finding to the current session.
// Returns true if finding is NEW (not in baseline), false if it's in baseline.
func (bs *BaselineStore) AddFinding(source, ftype, target string) (bool, *FindingFingerprint, error) {
	hash := bs.hashFinding(source, ftype, target)

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if existing, ok := bs.findings[hash]; ok {
		// Finding exists in baseline
		existing.LastSeen = time.Now()
		existing.Count++
		return false, existing, nil
	}

	// NEW finding not in baseline
	fp := &FindingFingerprint{
		Hash:      hash,
		Source:    source,
		Type:      ftype,
		Target:    target,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Count:     1,
	}

	bs.findings[hash] = fp
	slog.Debug("New finding detected", "type", ftype, "target", target, "source", source)
	return true, fp, nil
}

// hashFinding creates a deterministic hash of a finding.
func (bs *BaselineStore) hashFinding(source, ftype, target string) string {
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%s:%s:%s", source, ftype, target)))
	return hex.EncodeToString(hasher.Sum(nil))
}

// GetDiff returns findings that are new since baseline load.
func (bs *BaselineStore) GetDiff() []*FindingFingerprint {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	var newFindings []*FindingFingerprint
	now := time.Now()

	for _, fp := range bs.findings {
		// Findings added in this session (within last hour) are considered "new"
		if fp.FirstSeen.After(now.Add(-1 * time.Hour)) {
			newFindings = append(newFindings, fp)
		}
	}

	return newFindings
}

// GetNewByType returns new findings grouped by type.
func (bs *BaselineStore) GetNewByType() map[string]int {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	result := make(map[string]int)
	now := time.Now()

	for _, fp := range bs.findings {
		if fp.FirstSeen.After(now.Add(-1 * time.Hour)) {
			result[fp.Type]++
		}
	}

	return result
}

// SaveBaseline persists current findings as the new baseline.
func (bs *BaselineStore) SaveBaseline() error {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	baselineFile := filepath.Join(bs.baseDir, "baseline.json")
	data, err := json.MarshalIndent(bs.findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if err := os.WriteFile(baselineFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}

	slog.Info("Baseline saved", "file", baselineFile, "count", len(bs.findings))
	return nil
}

// autoSaveLoop periodically saves the baseline to disk.
func (bs *BaselineStore) autoSaveLoop() {
	ticker := time.NewTicker(bs.autoSaveEvery)
	defer ticker.Stop()

	for range ticker.C {
		if err := bs.SaveBaseline(); err != nil {
			slog.Warn("Auto-save baseline failed", "error", err)
		}
	}
}

// SaveSessionDiff saves new findings to a session-specific diff file.
func (bs *BaselineStore) SaveSessionDiff() error {
	newFindings := bs.GetDiff()
	if len(newFindings) == 0 {
		slog.Info("No new findings to save")
		return nil
	}

	diffFile := filepath.Join(bs.baseDir, fmt.Sprintf("diff_%s.json", bs.sessionID))
	data, err := json.MarshalIndent(newFindings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal diff: %w", err)
	}

	if err := os.WriteFile(diffFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write diff: %w", err)
	}

	slog.Info("Session diff saved", "file", diffFile, "new_count", len(newFindings))
	return nil
}

// GetStats returns baseline statistics.
func (bs *BaselineStore) GetStats() map[string]interface{} {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	typeCount := make(map[string]int)
	sourceCount := make(map[string]int)

	for _, fp := range bs.findings {
		typeCount[fp.Type]++
		sourceCount[fp.Source]++
	}

	return map[string]interface{}{
		"total_findings": len(bs.findings),
		"by_type":        typeCount,
		"by_source":      sourceCount,
		"last_saved":     bs.lastSaved,
	}
}

// Close closes the baseline store and saves final state.
func (bs *BaselineStore) Close() error {
	return bs.SaveBaseline()
}
