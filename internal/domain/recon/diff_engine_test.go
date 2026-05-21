package recon

import (
	"testing"
	"time"
)

func TestNewDiffEngine(t *testing.T) {
	storage := NewInMemoryStorage()
	de := NewDiffEngine(storage)

	if de == nil {
		t.Fatal("NewDiffEngine returned nil")
	}
	if de.storage == nil {
		t.Error("storage not initialized")
	}
}

func TestNewInMemoryStorage(t *testing.T) {
	ims := NewInMemoryStorage()

	if ims == nil {
		t.Fatal("NewInMemoryStorage returned nil")
	}
	if ims.results == nil {
		t.Error("results map not initialized")
	}
	if ims.byTarget == nil {
		t.Error("byTarget map not initialized")
	}
}

func TestInMemoryStorage_Store(t *testing.T) {
	ims := NewInMemoryStorage()

	result := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
		Assets: []Asset{
			{Type: "subdomain", Value: "api.acme-corp.io", Source: "subfinder"},
		},
	}

	err := ims.Store(result)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Verify it was stored
	stored, err := ims.Get("session1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if stored.SessionID != "session1" {
		t.Errorf("expected session ID 'session1', got '%s'", stored.SessionID)
	}
}

func TestInMemoryStorage_Get(t *testing.T) {
	ims := NewInMemoryStorage()

	result := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
	}

	_ = ims.Store(result)

	// Test getting existing result
	stored, err := ims.Get("session1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if stored.SessionID != "session1" {
		t.Errorf("expected session ID 'session1', got '%s'", stored.SessionID)
	}

	// Test getting non-existent result
	_, err = ims.Get("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent session ID")
	}
}

func TestInMemoryStorage_GetLatest(t *testing.T) {
	ims := NewInMemoryStorage()

	// Store multiple scans for the same target
	result1 := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-2 * time.Hour),
	}

	result2 := &ScanResult{
		SessionID: "session2",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-1 * time.Hour),
	}

	result3 := &ScanResult{
		SessionID: "session3",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
	}

	_ = ims.Store(result1)
	_ = ims.Store(result2)
	_ = ims.Store(result3)

	// Get latest
	latest, err := ims.GetLatest("acme-corp.io")
	if err != nil {
		t.Fatalf("GetLatest failed: %v", err)
	}

	if latest.SessionID != "session3" {
		t.Errorf("expected latest session ID 'session3', got '%s'", latest.SessionID)
	}

	// Test non-existent target
	_, err = ims.GetLatest("nonexistent.com")
	if err == nil {
		t.Error("expected error for non-existent target")
	}
}

func TestInMemoryStorage_List(t *testing.T) {
	ims := NewInMemoryStorage()

	// Store multiple scans
	result1 := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-2 * time.Hour),
	}

	result2 := &ScanResult{
		SessionID: "session2",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-1 * time.Hour),
	}

	result3 := &ScanResult{
		SessionID: "session3",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
	}

	_ = ims.Store(result1)
	_ = ims.Store(result2)
	_ = ims.Store(result3)

	// List all
	results, err := ims.List("acme-corp.io", 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// List with limit
	results, err = ims.List("acme-corp.io", 2)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results with limit, got %d", len(results))
	}

	// Test non-existent target
	results, err = ims.List("nonexistent.com", 0)
	if err != nil {
		t.Fatalf("List failed for non-existent target: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for non-existent target, got %d", len(results))
	}
}

func TestInMemoryStorage_Delete(t *testing.T) {
	ims := NewInMemoryStorage()

	result := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
	}

	_ = ims.Store(result)

	// Delete
	err := ims.Delete("session1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it was deleted
	_, err = ims.Get("session1")
	if err == nil {
		t.Error("expected error after deletion")
	}

	// Test deleting non-existent
	err = ims.Delete("nonexistent")
	if err == nil {
		t.Error("expected error for deleting non-existent session")
	}
}

func TestDiffEngine_StoreResult(t *testing.T) {
	storage := NewInMemoryStorage()
	de := NewDiffEngine(storage)

	result := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
		Assets: []Asset{
			{Type: "subdomain", Value: "api.acme-corp.io", Source: "subfinder"},
		},
	}

	err := de.StoreResult(result)
	if err != nil {
		t.Fatalf("StoreResult failed: %v", err)
	}

	// Verify checksums were computed
	stored, _ := storage.Get("session1")
	if stored.Assets[0].Checksum == "" {
		t.Error("checksum should be computed")
	}
}

func TestDiffEngine_Compare(t *testing.T) {
	storage := NewInMemoryStorage()
	de := NewDiffEngine(storage)

	previous := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-1 * time.Hour),
		Assets: []Asset{
			{Type: "subdomain", Value: "api.acme-corp.io", Source: "subfinder"},
			{Type: "subdomain", Value: "www.acme-corp.io", Source: "subfinder"},
		},
	}

	current := &ScanResult{
		SessionID: "session2",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
		Assets: []Asset{
			{Type: "subdomain", Value: "api.acme-corp.io", Source: "subfinder"}, // unchanged
			{Type: "subdomain", Value: "new.acme-corp.io", Source: "subfinder"}, // new
			// www.acme-corp.io removed
		},
	}

	report, err := de.Compare(current, previous)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report == nil {
		t.Fatal("report should not be nil")
	}

	if report.SessionID != "session2" {
		t.Errorf("expected session ID 'session2', got '%s'", report.SessionID)
	}

	if report.PreviousID != "session1" {
		t.Errorf("expected previous ID 'session1', got '%s'", report.PreviousID)
	}

	// Should have 1 new and 1 removed
	if report.Summary.NewAssets != 1 {
		t.Errorf("expected 1 new asset, got %d", report.Summary.NewAssets)
	}

	if report.Summary.RemovedAssets != 1 {
		t.Errorf("expected 1 removed asset, got %d", report.Summary.RemovedAssets)
	}

	if report.Summary.ChangedAssets != 0 {
		t.Errorf("expected 0 changed assets, got %d", report.Summary.ChangedAssets)
	}

	if report.Summary.UnchangedAssets != 1 {
		t.Errorf("expected 1 unchanged asset, got %d", report.Summary.UnchangedAssets)
	}
}

func TestDiffEngine_CompareWithLatest(t *testing.T) {
	storage := NewInMemoryStorage()
	de := NewDiffEngine(storage)

	// Store previous scan
	previous := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-1 * time.Hour),
		Assets: []Asset{
			{Type: "subdomain", Value: "api.acme-corp.io", Source: "subfinder"},
		},
	}

	_ = de.StoreResult(previous)

	// Compare with latest
	current := &ScanResult{
		SessionID: "session2",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
		Assets: []Asset{
			{Type: "subdomain", Value: "new.acme-corp.io", Source: "subfinder"},
		},
	}

	report, err := de.CompareWithLatest(current)
	if err != nil {
		t.Fatalf("CompareWithLatest failed: %v", err)
	}

	if report == nil {
		t.Fatal("report should not be nil")
	}

	// Test with no previous scan
	current2 := &ScanResult{
		SessionID: "session3",
		Target:    "nonexistent.com",
		Timestamp: time.Now(),
		Assets:    []Asset{},
	}

	_, err = de.CompareWithLatest(current2)
	if err == nil {
		t.Error("expected error when no previous scan exists")
	}
}

func TestDiffEngine_GetHistory(t *testing.T) {
	storage := NewInMemoryStorage()
	de := NewDiffEngine(storage)

	// Store multiple scans
	result1 := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-2 * time.Hour),
	}

	result2 := &ScanResult{
		SessionID: "session2",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-1 * time.Hour),
	}

	_ = de.StoreResult(result1)
	_ = de.StoreResult(result2)

	// Get history
	history, err := de.GetHistory("acme-corp.io", 0)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}

	if len(history) != 2 {
		t.Errorf("expected 2 results, got %d", len(history))
	}

	// Get history with limit
	history, err = de.GetHistory("acme-corp.io", 1)
	if err != nil {
		t.Fatalf("GetHistory with limit failed: %v", err)
	}

	if len(history) != 1 {
		t.Errorf("expected 1 result with limit, got %d", len(history))
	}
}

func TestAssetKey(t *testing.T) {
	asset := Asset{
		Type:  "subdomain",
		Value: "api.acme-corp.io",
	}

	key := assetKey(asset)
	expected := "subdomain:api.acme-corp.io"

	if key != expected {
		t.Errorf("expected key '%s', got '%s'", expected, key)
	}
}

func TestComputeAssetChecksum(t *testing.T) {
	asset := Asset{
		Type:   "subdomain",
		Value:  "api.acme-corp.io",
		Source: "subfinder",
	}

	checksum1 := computeAssetChecksum(asset)
	checksum2 := computeAssetChecksum(asset)

	if checksum1 != checksum2 {
		t.Error("checksums should be consistent")
	}

	if checksum1 == "" {
		t.Error("checksum should not be empty")
	}

	// Different assets should have different checksums
	asset2 := Asset{
		Type:   "subdomain",
		Value:  "www.acme-corp.io",
		Source: "subfinder",
	}

	checksum3 := computeAssetChecksum(asset2)
	if checksum1 == checksum3 {
		t.Error("different assets should have different checksums")
	}
}

func TestComputeAssetChecksum_WithMetadata(t *testing.T) {
	asset := Asset{
		Type:   "subdomain",
		Value:  "api.acme-corp.io",
		Source: "subfinder",
		Metadata: map[string]interface{}{
			"ip": "1.2.3.4",
		},
	}

	checksum := computeAssetChecksum(asset)
	if checksum == "" {
		t.Error("checksum should not be empty")
	}

	// Asset with different metadata should have different checksum
	asset2 := Asset{
		Type:   "subdomain",
		Value:  "api.acme-corp.io",
		Source: "subfinder",
		Metadata: map[string]interface{}{
			"ip": "5.6.7.8",
		},
	}

	checksum2 := computeAssetChecksum(asset2)
	if checksum == checksum2 {
		t.Error("assets with different metadata should have different checksums")
	}
}

func TestDiffReport_FilterChanges(t *testing.T) {
	report := &DiffReport{
		Changes: []DiffChange{
			{Type: "added", Asset: Asset{Type: "subdomain", Value: "new.acme-corp.io"}},
			{Type: "removed", Asset: Asset{Type: "subdomain", Value: "old.acme-corp.io"}},
			{Type: "changed", Asset: Asset{Type: "url", Value: "https://acme-corp.io/api"}},
		},
	}

	// Filter by type
	added := report.FilterChanges("added", "")
	if len(added) != 1 {
		t.Errorf("expected 1 added change, got %d", len(added))
	}

	// Filter by asset type
	subdomains := report.FilterChanges("", "subdomain")
	if len(subdomains) != 2 {
		t.Errorf("expected 2 subdomain changes, got %d", len(subdomains))
	}

	// Filter by both
	addedSubdomains := report.FilterChanges("added", "subdomain")
	if len(addedSubdomains) != 1 {
		t.Errorf("expected 1 added subdomain change, got %d", len(addedSubdomains))
	}
}

func TestDiffReport_ToMarkdown(t *testing.T) {
	report := &DiffReport{
		SessionID:  "session2",
		PreviousID: "session1",
		Target:     "acme-corp.io",
		Timestamp:  time.Now(),
		Summary: DiffSummary{
			TotalAssets:     3,
			NewAssets:       1,
			RemovedAssets:   1,
			ChangedAssets:   1,
			UnchangedAssets: 0,
		},
		Changes: []DiffChange{
			{Type: "added", Asset: Asset{Type: "subdomain", Value: "new.acme-corp.io", Source: "subfinder"}},
			{Type: "removed", Asset: Asset{Type: "subdomain", Value: "old.acme-corp.io", Source: "subfinder"}},
			{Type: "changed", Asset: Asset{Type: "url", Value: "https://acme-corp.io/api", Source: "httpx"}},
		},
	}

	markdown := report.ToMarkdown()

	if markdown == "" {
		t.Error("ToMarkdown should not return empty string")
	}

	// Verify markdown contains expected sections
	expectedSections := []string{"Differential Reconnaissance Report", "Summary", "Added Assets", "Removed Assets", "Changed Assets"}
	for _, section := range expectedSections {
		if !contains(markdown, section) {
			t.Errorf("Markdown should contain section '%s'", section)
		}
	}
}

func TestDiffReport_ToJSON(t *testing.T) {
	report := &DiffReport{
		SessionID:  "session2",
		PreviousID: "session1",
		Target:     "acme-corp.io",
		Timestamp:  time.Now(),
		Summary: DiffSummary{
			TotalAssets: 3,
		},
		Changes: []DiffChange{},
	}

	json, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if json == "" {
		t.Error("ToJSON should not return empty string")
	}

	// Verify it contains expected fields
	if !contains(json, "session_id") {
		t.Error("JSON should contain session_id")
	}

	if !contains(json, "target") {
		t.Error("JSON should contain target")
	}
}

func TestDiffEngine_Compare_ChangedAssets(t *testing.T) {
	storage := NewInMemoryStorage()
	de := NewDiffEngine(storage)

	previous := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-1 * time.Hour),
		Assets: []Asset{
			{Type: "subdomain", Value: "api.acme-corp.io", Source: "subfinder", Metadata: map[string]interface{}{"ip": "1.2.3.4"}},
		},
	}

	current := &ScanResult{
		SessionID: "session2",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
		Assets: []Asset{
			{Type: "subdomain", Value: "api.acme-corp.io", Source: "subfinder", Metadata: map[string]interface{}{"ip": "5.6.7.8"}},
		},
	}

	report, err := de.Compare(current, previous)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.Summary.ChangedAssets != 1 {
		t.Errorf("expected 1 changed asset, got %d", report.Summary.ChangedAssets)
	}
}

func TestDiffEngine_Compare_EmptyScans(t *testing.T) {
	storage := NewInMemoryStorage()
	de := NewDiffEngine(storage)

	previous := &ScanResult{
		SessionID: "session1",
		Target:    "acme-corp.io",
		Timestamp: time.Now().Add(-1 * time.Hour),
		Assets:    []Asset{},
	}

	current := &ScanResult{
		SessionID: "session2",
		Target:    "acme-corp.io",
		Timestamp: time.Now(),
		Assets:    []Asset{},
	}

	report, err := de.Compare(current, previous)
	if err != nil {
		t.Fatalf("Compare failed: %v", err)
	}

	if report.Summary.TotalAssets != 0 {
		t.Errorf("expected 0 total assets, got %d", report.Summary.TotalAssets)
	}
}
