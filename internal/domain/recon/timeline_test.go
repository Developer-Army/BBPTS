package recon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewFingerprintTimeline(t *testing.T) {
	tmpDir := t.TempDir()

	ft, err := NewFingerprintTimeline(tmpDir)
	if err != nil {
		t.Fatalf("NewFingerprintTimeline failed: %v", err)
	}

	if ft == nil {
		t.Fatal("NewFingerprintTimeline returned nil")
	}

	if ft.baseDir != tmpDir {
		t.Errorf("expected baseDir %s, got %s", tmpDir, ft.baseDir)
	}

	if ft.history == nil {
		t.Error("history map not initialized")
	}
}

func TestNewFingerprintTimeline_CreateDir(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "timeline")

	ft, err := NewFingerprintTimeline(baseDir)
	if err != nil {
		t.Fatalf("NewFingerprintTimeline failed: %v", err)
	}

	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		t.Error("baseDir was not created")
	}

	_ = ft
}

func TestFingerprintTimeline_Record(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
		TLSIssuer:   "Let's Encrypt",
		TLSSubject:  "acme-corp.io",
	}

	err := ft.Record("session1", result)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	ft.mu.RLock()
	history := ft.history["acme-corp.io"]
	ft.mu.RUnlock()

	if len(history) != 1 {
		t.Errorf("expected 1 record in history, got %d", len(history))
	}

	if history[0].Host != "acme-corp.io" {
		t.Errorf("expected host 'acme-corp.io', got '%s'", history[0].Host)
	}
}

func TestFingerprintTimeline_Record_Prune(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
	}

	for i := 0; i < 35; i++ {
		_ = ft.Record("session1", result)
		time.Sleep(10 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	ft.mu.RLock()
	history := ft.history["acme-corp.io"]
	ft.mu.RUnlock()

	if len(history) != 30 {
		t.Errorf("expected history to be pruned to 30, got %d", len(history))
	}
}

func TestFingerprintTimeline_GetHistory(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
	}

	_ = ft.Record("session1", result)
	time.Sleep(50 * time.Millisecond)
	_ = ft.Record("session2", result)
	time.Sleep(50 * time.Millisecond)

	history := ft.GetHistory("acme-corp.io", 0)

	if len(history) != 2 {
		t.Errorf("expected 2 records, got %d", len(history))
	}

	time.Sleep(500 * time.Millisecond)
}

func TestFingerprintTimeline_GetHistory_WithLimit(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
	}

	_ = ft.Record("session1", result)
	time.Sleep(50 * time.Millisecond)
	_ = ft.Record("session2", result)
	time.Sleep(50 * time.Millisecond)
	_ = ft.Record("session3", result)
	time.Sleep(50 * time.Millisecond)

	history := ft.GetHistory("acme-corp.io", 2)

	if len(history) != 2 {
		t.Errorf("expected 2 records with limit, got %d", len(history))
	}

	time.Sleep(500 * time.Millisecond)
}

func TestFingerprintTimeline_GetHistory_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	history := ft.GetHistory("nonexistent.com", 0)

	if history != nil {
		t.Error("expected nil for non-existent host")
	}
}

func TestFingerprintTimeline_GetChanges(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result1 := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
		TLSIssuer:   "Issuer1",
	}
	_ = ft.Record("session1", result1)
	time.Sleep(100 * time.Millisecond)

	result2 := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm789",
		FaviconHash: "fav456",
		TLSIssuer:   "Issuer1",
	}
	_ = ft.Record("session2", result2)
	time.Sleep(100 * time.Millisecond)

	changes := ft.GetChanges(24 * time.Hour)

	if changes == nil {
		t.Error("expected changes map to be non-nil")
	}
}

func TestFingerprintTimeline_GetChanges_NoChange(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
	}

	_ = ft.Record("session1", result)
	time.Sleep(100 * time.Millisecond)
	_ = ft.Record("session2", result)
	time.Sleep(100 * time.Millisecond)

	changes := ft.GetChanges(1 * time.Hour)

	if len(changes) != 0 {
		t.Errorf("expected 0 changes when fingerprint unchanged, got %d", len(changes))
	}
}

func TestFingerprintTimeline_GetChanges_InsufficientHistory(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
	}

	_ = ft.Record("session1", result)
	time.Sleep(100 * time.Millisecond)

	changes := ft.GetChanges(1 * time.Hour)

	if len(changes) != 0 {
		t.Errorf("expected 0 changes with insufficient history, got %d", len(changes))
	}
}

func TestFingerprintTimeline_ClusterByInfrastructure(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result1 := Result{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
	}

	result2 := Result{
		Host:        "test.com",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
	}

	result3 := Result{
		Host:        "different.com",
		JARMHash:    "jarm789",
		FaviconHash: "fav999",
	}

	_ = ft.Record("session1", result1)
	time.Sleep(50 * time.Millisecond)
	_ = ft.Record("session1", result2)
	time.Sleep(50 * time.Millisecond)
	_ = ft.Record("session1", result3)
	time.Sleep(50 * time.Millisecond)

	clusters := ft.ClusterByInfrastructure()

	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(clusters))
	}
}

func TestFingerprintTimeline_ClusterByInfrastructure_EmptyFingerprints(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	result := Result{
		Host:        "acme-corp.io",
		JARMHash:    "",
		FaviconHash: "",
	}

	_ = ft.Record("session1", result)
	time.Sleep(100 * time.Millisecond)

	clusters := ft.ClusterByInfrastructure()

	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters for empty fingerprints, got %d", len(clusters))
	}

	time.Sleep(500 * time.Millisecond)
}

func TestSanitizeHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{"with port", "acme-corp.io:443", "acme-corp.io"},
		{"with path", "acme-corp.io/test", "acme-corp.io"},
		{"uppercase", "ACME-CORP.IO", "acme-corp.io"},
		{"mixed case", "AcMe-CoRp.Io", "acme-corp.io"},
		{"simple", "acme-corp.io", "acme-corp.io"},
		{"with port and path", "acme-corp.io:443/test", "acme-corp.io"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeHost(tt.host)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestSafeHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected string
	}{
		{"short hash", "abc", "abc"},
		{"exact length", "12345678", "12345678"},
		{"long hash", "12345678901234567890", "12345678"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeHash(tt.hash)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestFingerprintTimeline_computeRecordChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	rec := FingerprintRecord{
		Host:        "acme-corp.io",
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
		TLSIssuer:   "Issuer1",
		TLSSubject:  "Subject1",
	}

	checksum1 := ft.computeRecordChecksum(rec)
	checksum2 := ft.computeRecordChecksum(rec)

	if checksum1 != checksum2 {
		t.Error("checksums should be consistent")
	}

	if checksum1 == "" {
		t.Error("checksum should not be empty")
	}
}

func TestFingerprintTimeline_diffFields(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	prev := FingerprintRecord{
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
		TLSIssuer:   "Issuer1",
		TLSSubject:  "Subject1",
	}

	curr := FingerprintRecord{
		JARMHash:    "jarm789",
		FaviconHash: "fav456",
		TLSIssuer:   "Issuer2",
		TLSSubject:  "Subject1",
	}

	changed := ft.diffFields(prev, curr)

	if len(changed) != 2 {
		t.Errorf("expected 2 changed fields, got %d", len(changed))
	}
}

func TestFingerprintTimeline_diffFields_NoChange(t *testing.T) {
	tmpDir := t.TempDir()
	ft, _ := NewFingerprintTimeline(tmpDir)

	rec := FingerprintRecord{
		JARMHash:    "jarm123",
		FaviconHash: "fav456",
		TLSIssuer:   "Issuer1",
		TLSSubject:  "Subject1",
	}

	changed := ft.diffFields(rec, rec)

	if len(changed) != 0 {
		t.Errorf("expected 0 changed fields when identical, got %d", len(changed))
	}
}
