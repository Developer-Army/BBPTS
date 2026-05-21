package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewBaselineStore(t *testing.T) {
	tmpDir := t.TempDir()

	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}

	if store == nil {
		t.Fatal("NewBaselineStore returned nil")
	}

	if store.sessionID != "test-session" {
		t.Errorf("Expected sessionID 'test-session', got '%s'", store.sessionID)
	}

	store.Close()
}

func TestAddFinding(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	// Test adding a new finding
	isNew, fp, err := store.AddFinding("subfinder", "subdomain", "acme-corp.io")
	if err != nil {
		t.Fatalf("AddFinding failed: %v", err)
	}

	if !isNew {
		t.Error("Expected finding to be new")
	}

	if fp == nil {
		t.Fatal("Expected fingerprint to be non-nil")
	}

	if fp.Source != "subfinder" {
		t.Errorf("Expected source 'subfinder', got '%s'", fp.Source)
	}

	if fp.Type != "subdomain" {
		t.Errorf("Expected type 'subdomain', got '%s'", fp.Type)
	}

	if fp.Target != "acme-corp.io" {
		t.Errorf("Expected target 'acme-corp.io', got '%s'", fp.Target)
	}

	if fp.Count != 1 {
		t.Errorf("Expected count 1, got %d", fp.Count)
	}
}

func TestAddFindingDuplicate(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	// Add finding first time
	isNew1, _, err := store.AddFinding("subfinder", "subdomain", "acme-corp.io")
	if err != nil {
		t.Fatalf("First AddFinding failed: %v", err)
	}

	if !isNew1 {
		t.Error("Expected first finding to be new")
	}

	// Add same finding again
	isNew2, fp2, err := store.AddFinding("subfinder", "subdomain", "acme-corp.io")
	if err != nil {
		t.Fatalf("Second AddFinding failed: %v", err)
	}

	if isNew2 {
		t.Error("Expected second finding to not be new")
	}

	if fp2.Count != 2 {
		t.Errorf("Expected count 2 after duplicate, got %d", fp2.Count)
	}
}

func TestHashFinding(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	hash1 := store.hashFinding("subfinder", "subdomain", "acme-corp.io")
	hash2 := store.hashFinding("subfinder", "subdomain", "acme-corp.io")

	if hash1 != hash2 {
		t.Error("Expected same hash for same input")
	}

	hash3 := store.hashFinding("subfinder", "subdomain", "different.com")
	if hash1 == hash3 {
		t.Error("Expected different hash for different input")
	}
}

func TestGetDiff(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	// Add a finding (should be considered new within the hour)
	_, _, _ = store.AddFinding("subfinder", "subdomain", "acme-corp.io")

	diff := store.GetDiff()

	if len(diff) != 1 {
		t.Errorf("Expected 1 new finding, got %d", len(diff))
	}

	if diff[0].Target != "acme-corp.io" {
		t.Errorf("Expected target 'acme-corp.io', got '%s'", diff[0].Target)
	}
}

func TestGetNewByType(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	// Add findings of different types
	_, _, _ = store.AddFinding("subfinder", "subdomain", "acme-corp.io")
	_, _, _ = store.AddFinding("subfinder", "subdomain", "test.com")
	_, _, _ = store.AddFinding("naabu", "port", "acme-corp.io:80")

	byType := store.GetNewByType()

	if byType["subdomain"] != 2 {
		t.Errorf("Expected 2 subdomain findings, got %d", byType["subdomain"])
	}

	if byType["port"] != 1 {
		t.Errorf("Expected 1 port finding, got %d", byType["port"])
	}
}

func TestSaveBaseline(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}

	// Add some findings
	_, _, _ = store.AddFinding("subfinder", "subdomain", "acme-corp.io")
	_, _, _ = store.AddFinding("naabu", "port", "acme-corp.io:80")

	// Save baseline
	err = store.SaveBaseline()
	if err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	// Check that file exists
	baselineFile := filepath.Join(tmpDir, ".baseline", "baseline.json")
	if _, err := os.Stat(baselineFile); os.IsNotExist(err) {
		t.Error("Baseline file was not created")
	}

	// Verify file contents
	data, err := os.ReadFile(baselineFile)
	if err != nil {
		t.Fatalf("Failed to read baseline file: %v", err)
	}

	var findings map[string]*FindingFingerprint
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("Failed to unmarshal baseline: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("Expected 2 findings in baseline, got %d", len(findings))
	}

	store.Close()
}

func TestLoadBaseline(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a baseline file with existing data
	baselineDir := filepath.Join(tmpDir, ".baseline")
	if err := os.MkdirAll(baselineDir, 0755); err != nil {
		t.Fatalf("Failed to create baseline dir: %v", err)
	}

	// Compute real hash
	storeDummy := &BaselineStore{}
	realHash := storeDummy.hashFinding("subfinder", "subdomain", "existing.com")

	existingFindings := map[string]*FindingFingerprint{
		realHash: {
			Hash:      realHash,
			Source:    "subfinder",
			Type:      "subdomain",
			Target:    "existing.com",
			FirstSeen: time.Now().Add(-2 * time.Hour),
			LastSeen:  time.Now().Add(-1 * time.Hour),
			Count:     5,
		},
	}

	data, err := json.MarshalIndent(existingFindings, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal existing findings: %v", err)
	}

	baselineFile := filepath.Join(baselineDir, "baseline.json")
	if err := os.WriteFile(baselineFile, data, 0644); err != nil {
		t.Fatalf("Failed to write baseline file: %v", err)
	}

	// Create store and load baseline
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	// Add a new finding
	isNew, _, err := store.AddFinding("subfinder", "subdomain", "new.com")
	if err != nil {
		t.Fatalf("AddFinding failed: %v", err)
	}

	if !isNew {
		t.Error("Expected new finding to be new")
	}

	// Try to add existing finding
	isNew2, _, err := store.AddFinding("subfinder", "subdomain", "existing.com")
	if err != nil {
		t.Fatalf("AddFinding for existing failed: %v", err)
	}

	if isNew2 {
		t.Error("Expected existing finding to not be new")
	}
}

func TestSaveSessionDiff(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	// Add findings
	_, _, _ = store.AddFinding("subfinder", "subdomain", "acme-corp.io")
	_, _, _ = store.AddFinding("naabu", "port", "acme-corp.io:80")

	// Save session diff
	err = store.SaveSessionDiff()
	if err != nil {
		t.Fatalf("SaveSessionDiff failed: %v", err)
	}

	// Check that diff file exists
	diffFile := filepath.Join(tmpDir, ".baseline", "diff_test-session.json")
	if _, err := os.Stat(diffFile); os.IsNotExist(err) {
		t.Error("Diff file was not created")
	}

	// Verify file contents
	data, err := os.ReadFile(diffFile)
	if err != nil {
		t.Fatalf("Failed to read diff file: %v", err)
	}

	var findings []*FindingFingerprint
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("Failed to unmarshal diff: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("Expected 2 findings in diff, got %d", len(findings))
	}
}

func TestGetStats(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}
	defer store.Close()

	// Add findings
	_, _, _ = store.AddFinding("subfinder", "subdomain", "acme-corp.io")
	_, _, _ = store.AddFinding("subfinder", "subdomain", "test.com")
	_, _, _ = store.AddFinding("naabu", "port", "acme-corp.io:80")

	stats := store.GetStats()

	totalFindings, ok := stats["total_findings"].(int)
	if !ok {
		t.Error("Expected total_findings to be an int")
	}

	if totalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", totalFindings)
	}

	byType, ok := stats["by_type"].(map[string]int)
	if !ok {
		t.Error("Expected by_type to be a map[string]int")
	}

	if byType["subdomain"] != 2 {
		t.Errorf("Expected 2 subdomain findings, got %d", byType["subdomain"])
	}

	bySource, ok := stats["by_source"].(map[string]int)
	if !ok {
		t.Error("Expected by_source to be a map[string]int")
	}

	if bySource["subfinder"] != 2 {
		t.Errorf("Expected 2 subfinder findings, got %d", bySource["subfinder"])
	}
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewBaselineStore(tmpDir, "test-session")
	if err != nil {
		t.Fatalf("NewBaselineStore failed: %v", err)
	}

	// Add findings
	_, _, _ = store.AddFinding("subfinder", "subdomain", "acme-corp.io")

	// Close should save baseline
	err = store.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify baseline was saved
	baselineFile := filepath.Join(tmpDir, ".baseline", "baseline.json")
	if _, err := os.Stat(baselineFile); os.IsNotExist(err) {
		t.Error("Baseline file was not saved on close")
	}
}
