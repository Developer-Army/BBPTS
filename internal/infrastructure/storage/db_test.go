package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAndClose(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	if db == nil {
		t.Fatal("Expected non-nil DB")
	}

	if err := db.Close(); err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}
}

func TestOpenCreatesDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "subdir", "nested")
	dbPath := filepath.Join(nested, "bbpts.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database with nested directory: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Fatal("Expected Open to create the directory")
	}
}

func TestStartAndFinishScan(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	scanID, err := db.StartScan(ctx, "test-scope")
	if err != nil {
		t.Fatalf("Failed to start scan: %v", err)
	}
	if scanID <= 0 {
		t.Fatalf("Expected positive scan ID, got %d", scanID)
	}

	if err := db.FinishScan(ctx, scanID); err != nil {
		t.Fatalf("Failed to finish scan: %v", err)
	}
}

func TestSaveTargets(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	scanID := mustStartScan(t, ctx, db)

	targets := []string{"acme-corp.io", "api.acme-corp.io", "admin.acme-corp.io"}
	if err := db.SaveTargets(ctx, scanID, targets); err != nil {
		t.Fatalf("Failed to save targets: %v", err)
	}

	saved, err := db.GetTargets(ctx, scanID)
	if err != nil {
		t.Fatalf("Failed to get targets: %v", err)
	}
	if len(saved) != len(targets) {
		t.Fatalf("Expected %d targets, got %d", len(targets), len(saved))
	}
	for i, tgt := range targets {
		if saved[i] != tgt {
			t.Errorf("Expected target '%s', got '%s'", tgt, saved[i])
		}
	}
}

func TestSaveEvents(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	scanID := mustStartScan(t, ctx, db)

	events := []EventRecord{
		{Target: "acme-corp.io", Source: "subfinder", Type: "subdomain", Properties: map[string]string{"confidence": "high"}},
		{Target: "acme-corp.io", Source: "httpx", Type: "service", Properties: nil},
	}

	if err := db.SaveEvents(ctx, scanID, events); err != nil {
		t.Fatalf("Failed to save events: %v", err)
	}

	saved, err := db.GetEvents(ctx, scanID)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}
	if len(saved) != len(events) {
		t.Fatalf("Expected %d events, got %d", len(events), len(saved))
	}
	if saved[0].Target != "acme-corp.io" {
		t.Errorf("Expected target 'acme-corp.io', got '%s'", saved[0].Target)
	}
	if saved[0].Properties["confidence"] != "high" {
		t.Errorf("Expected confidence 'high', got '%s'", saved[0].Properties["confidence"])
	}
}

func TestSaveEventsWithNilProperties(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	scanID := mustStartScan(t, ctx, db)

	events := []EventRecord{
		{Target: "acme-corp.io", Source: "test", Type: "discovery", Properties: nil},
	}

	if err := db.SaveEvents(ctx, scanID, events); err != nil {
		t.Fatalf("Failed to save events with nil properties: %v", err)
	}

	saved, err := db.GetEvents(ctx, scanID)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}
	if len(saved) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(saved))
	}
}

func TestGetScans(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	mustStartScan(t, ctx, db)
	mustStartScan(t, ctx, db)
	mustFinishScan(t, ctx, db, 1)
	mustFinishScan(t, ctx, db, 2)

	scans, err := db.GetScans(ctx)
	if err != nil {
		t.Fatalf("Failed to get scans: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("Expected 2 scans, got %d", len(scans))
	}
	if scans[0].Scope != "test-scope" {
		t.Errorf("Expected scope 'test-scope', got '%s'", scans[0].Scope)
	}
}

func TestGetLastScanID(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	id1 := mustStartScan(t, ctx, db)
	id2 := mustStartScan(t, ctx, db)
	mustFinishScan(t, ctx, db, id1)
	mustFinishScan(t, ctx, db, id2)

	lastID, err := db.GetLastScanID(ctx, "test-scope")
	if err != nil {
		t.Fatalf("Failed to get last scan ID: %v", err)
	}
	if lastID != id2 {
		t.Errorf("Expected last scan ID %d, got %d", id2, lastID)
	}
}

func TestGetLastScanIDNoScans(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	id, err := db.GetLastScanID(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Failed to get last scan ID: %v", err)
	}
	if id != 0 {
		t.Errorf("Expected 0 for no scans, got %d", id)
	}
}

func TestGetScanDiff(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	// First scan
	id1 := mustStartScan(t, ctx, db)
	mustSaveTargets(t, ctx, db, id1, []string{"acme-corp.io", "api.acme-corp.io"})
	mustFinishScan(t, ctx, db, id1)

	// Second scan
	id2 := mustStartScan(t, ctx, db)
	mustSaveTargets(t, ctx, db, id2, []string{"acme-corp.io", "new.acme-corp.io"})
	mustFinishScan(t, ctx, db, id2)

	diff, err := db.GetScanDiff(ctx, "test-scope", id2)
	if err != nil {
		t.Fatalf("Failed to get scan diff: %v", err)
	}
	if diff == nil {
		t.Fatal("Expected non-nil diff")
	}
	if len(diff.NewTargets) != 1 || diff.NewTargets[0] != "new.acme-corp.io" {
		t.Errorf("Expected new target 'new.acme-corp.io', got %v", diff.NewTargets)
	}
}

func TestGetScanDiffNoPrevious(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	id := mustStartScan(t, ctx, db)
	mustFinishScan(t, ctx, db, id)

	diff, err := db.GetScanDiff(ctx, "test-scope", id)
	if err != nil {
		t.Fatalf("Failed to get scan diff: %v", err)
	}
	if diff != nil {
		t.Fatal("Expected nil diff when no previous scan exists")
	}
}

func TestGetNewFindings(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	id1 := mustStartScan(t, ctx, db)
	mustSaveEvents(t, ctx, db, id1, []EventRecord{
		{Target: "acme-corp.io", Source: "nuclei", Type: "vuln"},
	})
	mustFinishScan(t, ctx, db, id1)

	id2 := mustStartScan(t, ctx, db)
	mustSaveEvents(t, ctx, db, id2, []EventRecord{
		{Target: "acme-corp.io", Source: "nuclei", Type: "vuln"},
		{Target: "new.acme-corp.io", Source: "nuclei", Type: "vuln"},
	})
	mustFinishScan(t, ctx, db, id2)

	findings, err := db.GetNewFindings(ctx, "test-scope", id2)
	if err != nil {
		t.Fatalf("Failed to get new findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Expected 1 new finding, got %d", len(findings))
	}
	if findings[0].Target != "new.acme-corp.io" {
		t.Errorf("Expected new finding for 'new.acme-corp.io', got '%s'", findings[0].Target)
	}
}

func TestGetStats(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	id := mustStartScan(t, ctx, db)
	mustSaveTargets(t, ctx, db, id, []string{"a.com", "b.com"})
	mustSaveEvents(t, ctx, db, id, []EventRecord{
		{Target: "a.com", Source: "nuclei", Type: "vuln"},
	})
	mustFinishScan(t, ctx, db, id)

	stats, err := db.GetStats(ctx)
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}
	if stats.TotalScans != 1 {
		t.Errorf("Expected 1 scan, got %d", stats.TotalScans)
	}
	if stats.TotalTargets != 2 {
		t.Errorf("Expected 2 targets, got %d", stats.TotalTargets)
	}
	if stats.TotalEvents != 1 {
		t.Errorf("Expected 1 event, got %d", stats.TotalEvents)
	}
}

func TestGetStatsEmpty(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	stats, err := db.GetStats(ctx)
	if err != nil {
		t.Fatalf("Failed to get stats on empty DB: %v", err)
	}
	if stats.TotalScans != 0 {
		t.Errorf("Expected 0 scans, got %d", stats.TotalScans)
	}
	if stats.TotalTargets != 0 {
		t.Errorf("Expected 0 targets, got %d", stats.TotalTargets)
	}
	if stats.TotalEvents != 0 {
		t.Errorf("Expected 0 events, got %d", stats.TotalEvents)
	}
}

func TestMultipleScopes(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	id1 := mustStartScanScope(t, ctx, db, "scope-a")
	mustFinishScan(t, ctx, db, id1)

	id2 := mustStartScanScope(t, ctx, db, "scope-b")
	mustFinishScan(t, ctx, db, id2)

	lastA, err := db.GetLastScanID(ctx, "scope-a")
	if err != nil {
		t.Fatalf("Failed to get last scan for scope-a: %v", err)
	}
	if lastA != id1 {
		t.Errorf("Expected scan %d for scope-a, got %d", id1, lastA)
	}

	lastB, err := db.GetLastScanID(ctx, "scope-b")
	if err != nil {
		t.Fatalf("Failed to get last scan for scope-b: %v", err)
	}
	if lastB != id2 {
		t.Errorf("Expected scan %d for scope-b, got %d", id2, lastB)
	}
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	done := make(chan struct{}, 3)
	for i := 0; i < 3; i++ {
		go func(idx int) {
			for j := 0; j < 5; j++ {
				target := string(rune('a' + idx)) + ".com"
				id, err := db.StartScan(ctx, "test-scope")
				if err != nil {
					t.Logf("Warning: failed to start scan: %v", err)
					continue
				}
				_ = db.SaveTargets(ctx, id, []string{target})
				_ = db.SaveEvents(ctx, id, []EventRecord{
					{Target: target, Source: "test", Type: "discovery"},
				})
				_ = db.FinishScan(ctx, id)
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-done:
			// success
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for goroutine")
		}
	}

	scans, err := db.GetScans(ctx)
	if err != nil {
		t.Fatalf("Failed to get scans: %v", err)
	}
	if len(scans) < 1 {
		t.Errorf("Expected at least some scans, got %d", len(scans))
	}
}

// helpers

func mustOpen(t *testing.T, dir string) *DB {
	t.Helper()
	dbPath := filepath.Join(dir, "bbpts.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	return db
}

func mustStartScan(t *testing.T, ctx context.Context, db *DB) int64 {
	t.Helper()
	return mustStartScanScope(t, ctx, db, "test-scope")
}

func mustStartScanScope(t *testing.T, ctx context.Context, db *DB, scope string) int64 {
	t.Helper()
	id, err := db.StartScan(ctx, scope)
	if err != nil {
		t.Fatalf("Failed to start scan: %v", err)
	}
	return id
}

func mustFinishScan(t *testing.T, ctx context.Context, db *DB, id int64) {
	t.Helper()
	if err := db.FinishScan(ctx, id); err != nil {
		t.Fatalf("Failed to finish scan %d: %v", id, err)
	}
}

func mustSaveTargets(t *testing.T, ctx context.Context, db *DB, scanID int64, targets []string) {
	t.Helper()
	if err := db.SaveTargets(ctx, scanID, targets); err != nil {
		t.Fatalf("Failed to save targets: %v", err)
	}
}

func mustSaveEvents(t *testing.T, ctx context.Context, db *DB, scanID int64, events []EventRecord) {
	t.Helper()
	if err := db.SaveEvents(ctx, scanID, events); err != nil {
		t.Fatalf("Failed to save events: %v", err)
	}
}
