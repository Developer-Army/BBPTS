package recon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// Asset represents a discovered asset from reconnaissance.
type Asset struct {
	Type      string    `json:"type"`      // subdomain, url, port, etc.
	Value     string    `json:"value"`     // the actual asset value
	Source    string    `json:"source"`    // tool that discovered it
	Timestamp time.Time `json:"timestamp"` // when it was discovered
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // additional data
	Checksum  string    `json:"checksum"`  // content hash for comparison
}

// ScanResult represents the complete result of a reconnaissance scan.
type ScanResult struct {
	SessionID   string    `json:"session_id"`
	Target      string    `json:"target"`
	Timestamp   time.Time `json:"timestamp"`
	Assets      []Asset   `json:"assets"`
	ScanConfig  map[string]interface{} `json:"scan_config,omitempty"`
}

// DiffChange represents a single change between two scans.
type DiffChange struct {
	Type     string `json:"type"`     // added, removed, changed
	Asset    Asset  `json:"asset"`
	Previous *Asset `json:"previous,omitempty"` // for changed assets
}

// DiffReport represents the comparison between two scan results.
type DiffReport struct {
	SessionID     string       `json:"session_id"`
	PreviousID    string       `json:"previous_id"`
	Target        string       `json:"target"`
	Timestamp     time.Time    `json:"timestamp"`
	Changes       []DiffChange `json:"changes"`
	Summary       DiffSummary  `json:"summary"`
}

// DiffSummary provides a high-level summary of changes.
type DiffSummary struct {
	TotalAssets    int `json:"total_assets"`
	NewAssets      int `json:"new_assets"`
	RemovedAssets  int `json:"removed_assets"`
	ChangedAssets  int `json:"changed_assets"`
	UnchangedAssets int `json:"unchanged_assets"`
}

// DiffEngine manages differential reconnaissance by comparing scan results.
type DiffEngine struct {
	storage    Storage
	mu         sync.RWMutex
}

// Storage defines the interface for storing and retrieving scan results.
type Storage interface {
	Store(result *ScanResult) error
	Get(sessionID string) (*ScanResult, error)
	GetLatest(target string) (*ScanResult, error)
	List(target string, limit int) ([]*ScanResult, error)
	Delete(sessionID string) error
}

// NewDiffEngine creates a new differential reconnaissance engine.
func NewDiffEngine(storage Storage) *DiffEngine {
	return &DiffEngine{
		storage: storage,
	}
}

// StoreResult stores a scan result for later comparison.
func (de *DiffEngine) StoreResult(result *ScanResult) error {
	de.mu.Lock()
	defer de.mu.Unlock()

	// Compute checksums for all assets
	for i := range result.Assets {
		result.Assets[i].Checksum = computeAssetChecksum(result.Assets[i])
	}

	return de.storage.Store(result)
}

// CompareWithLatest compares a scan result with the latest previous scan for the same target.
func (de *DiffEngine) CompareWithLatest(result *ScanResult) (*DiffReport, error) {
	de.mu.RLock()
	defer de.mu.RUnlock()

	// Get the latest previous scan
	previous, err := de.storage.GetLatest(result.Target)
	if err != nil {
		slog.Warn("Failed to get previous scan for diff", "target", result.Target, "error", err)
		return nil, fmt.Errorf("no previous scan found for target: %w", err)
	}

	return de.Compare(result, previous)
}

// Compare compares two scan results and returns a diff report.
func (de *DiffEngine) Compare(current, previous *ScanResult) (*DiffReport, error) {
	// Compute checksums if not already done
	for i := range current.Assets {
		if current.Assets[i].Checksum == "" {
			current.Assets[i].Checksum = computeAssetChecksum(current.Assets[i])
		}
	}
	for i := range previous.Assets {
		if previous.Assets[i].Checksum == "" {
			previous.Assets[i].Checksum = computeAssetChecksum(previous.Assets[i])
		}
	}

	// Create asset maps for efficient lookup
	previousMap := make(map[string]Asset)
	for _, asset := range previous.Assets {
		key := assetKey(asset)
		previousMap[key] = asset
	}

	currentMap := make(map[string]Asset)
	for _, asset := range current.Assets {
		key := assetKey(asset)
		currentMap[key] = asset
	}

	var changes []DiffChange
	summary := DiffSummary{}

	// Find new and changed assets
	for key, currentAsset := range currentMap {
		if previousAsset, exists := previousMap[key]; exists {
			// Asset exists in both - check if changed
			if currentAsset.Checksum != previousAsset.Checksum {
				changes = append(changes, DiffChange{
					Type:     "changed",
					Asset:    currentAsset,
					Previous: &previousAsset,
				})
				summary.ChangedAssets++
			} else {
				summary.UnchangedAssets++
			}
		} else {
			// New asset
			changes = append(changes, DiffChange{
				Type:  "added",
				Asset: currentAsset,
			})
			summary.NewAssets++
		}
	}

	// Find removed assets
	for key, previousAsset := range previousMap {
		if _, exists := currentMap[key]; !exists {
			changes = append(changes, DiffChange{
				Type:  "removed",
				Asset: previousAsset,
			})
			summary.RemovedAssets++
		}
	}

	summary.TotalAssets = len(current.Assets)

	report := &DiffReport{
		SessionID:  current.SessionID,
		PreviousID: previous.SessionID,
		Target:     current.Target,
		Timestamp:  time.Now(),
		Changes:    changes,
		Summary:    summary,
	}

	slog.Info("Diff comparison complete",
		"target", current.Target,
		"new", summary.NewAssets,
		"removed", summary.RemovedAssets,
		"changed", summary.ChangedAssets,
		"unchanged", summary.UnchangedAssets,
	)

	return report, nil
}

// GetHistory retrieves the scan history for a target.
func (de *DiffEngine) GetHistory(target string, limit int) ([]*ScanResult, error) {
	de.mu.RLock()
	defer de.mu.RUnlock()

	return de.storage.List(target, limit)
}

// assetKey creates a unique key for an asset based on type and value.
func assetKey(asset Asset) string {
	return fmt.Sprintf("%s:%s", asset.Type, asset.Value)
}

// computeAssetChecksum computes a checksum for an asset for comparison.
func computeAssetChecksum(asset Asset) string {
	// Create a normalized representation
	data := fmt.Sprintf("%s:%s:%s", asset.Type, asset.Value, asset.Source)
	
	// Include metadata if present
	if len(asset.Metadata) > 0 {
		// Sort metadata keys for consistent hashing
		keys := make([]string, 0, len(asset.Metadata))
		for k := range asset.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		
		for _, k := range keys {
			data += fmt.Sprintf(":%s=%v", k, asset.Metadata[k])
		}
	}

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes for shorter checksum
}

// FilterChanges filters diff changes by type and asset type.
func (dr *DiffReport) FilterChanges(changeType, assetType string) []DiffChange {
	var filtered []DiffChange
	
	for _, change := range dr.Changes {
		if changeType != "" && change.Type != changeType {
			continue
		}
		if assetType != "" && change.Asset.Type != assetType {
			continue
		}
		filtered = append(filtered, change)
	}
	
	return filtered
}

// ToMarkdown converts the diff report to a markdown summary.
func (dr *DiffReport) ToMarkdown() string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("# Differential Reconnaissance Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", dr.Target))
	sb.WriteString(fmt.Sprintf("**Previous Scan:** %s\n\n", dr.PreviousID))
	sb.WriteString(fmt.Sprintf("**Current Scan:** %s\n\n", dr.SessionID))
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", dr.Timestamp.Format(time.RFC3339)))
	
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Assets:** %d\n", dr.Summary.TotalAssets))
	sb.WriteString(fmt.Sprintf("- **New Assets:** %d\n", dr.Summary.NewAssets))
	sb.WriteString(fmt.Sprintf("- **Removed Assets:** %d\n", dr.Summary.RemovedAssets))
	sb.WriteString(fmt.Sprintf("- **Changed Assets:** %d\n", dr.Summary.ChangedAssets))
	sb.WriteString(fmt.Sprintf("- **Unchanged Assets:** %d\n\n", dr.Summary.UnchangedAssets))
	
	// Group changes by type
	byType := make(map[string][]DiffChange)
	for _, change := range dr.Changes {
		byType[change.Type] = append(byType[change.Type], change)
	}
	
	// Output changes by category
	for _, changeType := range []string{"added", "removed", "changed"} {
		changes := byType[changeType]
		if len(changes) == 0 {
			continue
		}
		
		sb.WriteString(fmt.Sprintf("## %s Assets (%d)\n\n", strings.Title(changeType), len(changes)))
		
		for _, change := range changes {
			sb.WriteString(fmt.Sprintf("- **%s** `%s` (from %s)\n", 
				change.Asset.Type, 
				change.Asset.Value, 
				change.Asset.Source))
			
			if changeType == "changed" && change.Previous != nil {
				sb.WriteString(fmt.Sprintf("  - Previous: `%s`\n", change.Previous.Value))
			}
		}
		sb.WriteString("\n")
	}
	
	return sb.String()
}

// ToJSON converts the diff report to JSON.
func (dr *DiffReport) ToJSON() (string, error) {
	data, err := json.MarshalIndent(dr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// InMemoryStorage provides an in-memory implementation of Storage for testing.
type InMemoryStorage struct {
	results map[string]*ScanResult
	byTarget map[string][]string
	mu      sync.RWMutex
}

// NewInMemoryStorage creates a new in-memory storage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		results:  make(map[string]*ScanResult),
		byTarget: make(map[string][]string),
	}
}

// Store stores a scan result.
func (ims *InMemoryStorage) Store(result *ScanResult) error {
	ims.mu.Lock()
	defer ims.mu.Unlock()
	
	ims.results[result.SessionID] = result
	
	// Update target index
	ims.byTarget[result.Target] = append(ims.byTarget[result.Target], result.SessionID)
	
	return nil
}

// Get retrieves a scan result by session ID.
func (ims *InMemoryStorage) Get(sessionID string) (*ScanResult, error) {
	ims.mu.RLock()
	defer ims.mu.RUnlock()
	
	result, exists := ims.results[sessionID]
	if !exists {
		return nil, fmt.Errorf("scan result not found: %s", sessionID)
	}
	
	return result, nil
}

// GetLatest retrieves the latest scan result for a target.
func (ims *InMemoryStorage) GetLatest(target string) (*ScanResult, error) {
	ims.mu.RLock()
	defer ims.mu.RUnlock()
	
	sessionIDs, exists := ims.byTarget[target]
	if !exists || len(sessionIDs) == 0 {
		return nil, fmt.Errorf("no scans found for target: %s", target)
	}
	
	// Get the most recent scan
	var latest *ScanResult
	var latestTime time.Time
	
	for _, sessionID := range sessionIDs {
		result := ims.results[sessionID]
		if result.Timestamp.After(latestTime) {
			latest = result
			latestTime = result.Timestamp
		}
	}
	
	if latest == nil {
		return nil, fmt.Errorf("no valid scans found for target: %s", target)
	}
	
	return latest, nil
}

// List retrieves scan results for a target, limited by count.
func (ims *InMemoryStorage) List(target string, limit int) ([]*ScanResult, error) {
	ims.mu.RLock()
	defer ims.mu.RUnlock()
	
	sessionIDs, exists := ims.byTarget[target]
	if !exists {
		return []*ScanResult{}, nil
	}
	
	var results []*ScanResult
	for _, sessionID := range sessionIDs {
		if result, ok := ims.results[sessionID]; ok {
			results = append(results, result)
		}
	}
	
	// Sort by timestamp descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})
	
	// Apply limit
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	
	return results, nil
}

// Delete deletes a scan result.
func (ims *InMemoryStorage) Delete(sessionID string) error {
	ims.mu.Lock()
	defer ims.mu.Unlock()
	
	result, exists := ims.results[sessionID]
	if !exists {
		return fmt.Errorf("scan result not found: %s", sessionID)
	}
	
	// Remove from target index
	target := result.Target
	var newSessionIDs []string
	for _, sid := range ims.byTarget[target] {
		if sid != sessionID {
			newSessionIDs = append(newSessionIDs, sid)
		}
	}
	ims.byTarget[target] = newSessionIDs
	
	// Remove from results
	delete(ims.results, sessionID)
	
	return nil
}
