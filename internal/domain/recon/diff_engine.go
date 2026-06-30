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

type Asset struct {
	Type      string                 `json:"type"`               // subdomain, url, port, etc.
	Value     string                 `json:"value"`              // the actual asset value
	Source    string                 `json:"source"`             // tool that discovered it
	Timestamp time.Time              `json:"timestamp"`          // when it was discovered
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // additional data
	Checksum  string                 `json:"checksum"`           // content hash for comparison
}

type ScanResult struct {
	SessionID  string                 `json:"session_id"`
	Target     string                 `json:"target"`
	Timestamp  time.Time              `json:"timestamp"`
	Assets     []Asset                `json:"assets"`
	ScanConfig map[string]interface{} `json:"scan_config,omitempty"`
}

type DiffChange struct {
	Type     string `json:"type"` // added, removed, changed
	Asset    Asset  `json:"asset"`
	Previous *Asset `json:"previous,omitempty"` // for changed assets
}

type DiffReport struct {
	SessionID  string       `json:"session_id"`
	PreviousID string       `json:"previous_id"`
	Target     string       `json:"target"`
	Timestamp  time.Time    `json:"timestamp"`
	Changes    []DiffChange `json:"changes"`
	Summary    DiffSummary  `json:"summary"`
}

type DiffSummary struct {
	TotalAssets     int `json:"total_assets"`
	NewAssets       int `json:"new_assets"`
	RemovedAssets   int `json:"removed_assets"`
	ChangedAssets   int `json:"changed_assets"`
	UnchangedAssets int `json:"unchanged_assets"`
}

type DiffEngine struct {
	storage Storage
	mu      sync.RWMutex
}

type Storage interface {
	Store(result *ScanResult) error
	Get(sessionID string) (*ScanResult, error)
	GetLatest(target string) (*ScanResult, error)
	List(target string, limit int) ([]*ScanResult, error)
	Delete(sessionID string) error
}

func NewDiffEngine(storage Storage) *DiffEngine {
	return &DiffEngine{
		storage: storage,
	}
}

func (de *DiffEngine) StoreResult(result *ScanResult) error {
	de.mu.Lock()
	defer de.mu.Unlock()

	for i := range result.Assets {
		result.Assets[i].Checksum = computeAssetChecksum(result.Assets[i])
	}

	return de.storage.Store(result)
}

func (de *DiffEngine) CompareWithLatest(result *ScanResult) (*DiffReport, error) {
	de.mu.RLock()
	defer de.mu.RUnlock()

	previous, err := de.storage.GetLatest(result.Target)
	if err != nil {
		slog.Warn("Failed to get previous scan for diff", "target", result.Target, "error", err)
		return nil, fmt.Errorf("no previous scan found for target: %w", err)
	}

	return de.Compare(result, previous)
}

func (de *DiffEngine) Compare(current, previous *ScanResult) (*DiffReport, error) {

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

	for key, currentAsset := range currentMap {
		if previousAsset, exists := previousMap[key]; exists {

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

			changes = append(changes, DiffChange{
				Type:  "added",
				Asset: currentAsset,
			})
			summary.NewAssets++
		}
	}

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

func (de *DiffEngine) GetHistory(target string, limit int) ([]*ScanResult, error) {
	de.mu.RLock()
	defer de.mu.RUnlock()

	return de.storage.List(target, limit)
}

func assetKey(asset Asset) string {
	return fmt.Sprintf("%s:%s", asset.Type, asset.Value)
}

func computeAssetChecksum(asset Asset) string {

	data := fmt.Sprintf("%s:%s", asset.Type, asset.Value)

	if len(asset.Metadata) > 0 {

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
	return fmt.Sprintf("%x", hash[:16])
}

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

func (dr *DiffReport) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# Differential Reconnaissance Report\n\n")
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

	byType := make(map[string][]DiffChange)
	for _, change := range dr.Changes {
		byType[change.Type] = append(byType[change.Type], change)
	}

	for _, changeType := range []string{"added", "removed", "changed"} {
		changes := byType[changeType]
		if len(changes) == 0 {
			continue
		}

		title := strings.ToUpper(changeType[:1]) + changeType[1:]
		sb.WriteString(fmt.Sprintf("## %s Assets (%d)\n\n", title, len(changes)))

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

func (dr *DiffReport) ToJSON() (string, error) {
	data, err := json.MarshalIndent(dr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type InMemoryStorage struct {
	results  map[string]*ScanResult
	byTarget map[string][]string
	mu       sync.RWMutex
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		results:  make(map[string]*ScanResult),
		byTarget: make(map[string][]string),
	}
}

func (ims *InMemoryStorage) Store(result *ScanResult) error {
	ims.mu.Lock()
	defer ims.mu.Unlock()

	ims.results[result.SessionID] = result

	ims.byTarget[result.Target] = append(ims.byTarget[result.Target], result.SessionID)

	return nil
}

func (ims *InMemoryStorage) Get(sessionID string) (*ScanResult, error) {
	ims.mu.RLock()
	defer ims.mu.RUnlock()

	result, exists := ims.results[sessionID]
	if !exists {
		return nil, fmt.Errorf("scan result not found: %s", sessionID)
	}

	return result, nil
}

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

	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

func (ims *InMemoryStorage) Delete(sessionID string) error {
	ims.mu.Lock()
	defer ims.mu.Unlock()

	result, exists := ims.results[sessionID]
	if !exists {
		return fmt.Errorf("scan result not found: %s", sessionID)
	}

	target := result.Target
	var newSessionIDs []string
	for _, sid := range ims.byTarget[target] {
		if sid != sessionID {
			newSessionIDs = append(newSessionIDs, sid)
		}
	}
	ims.byTarget[target] = newSessionIDs

	delete(ims.results, sessionID)

	return nil
}
