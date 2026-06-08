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

	saved, err := db.GetTargets(ctx, scanID, 0, 0)
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

	saved, err := db.GetEvents(ctx, scanID, 0, 0)
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

	saved, err := db.GetEvents(ctx, scanID, 0, 0)
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

	scans, err := db.GetScans(ctx, 0, 0)
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
				target := string(rune('a'+idx)) + ".com"
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

	scans, err := db.GetScans(ctx, 0, 0)
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

func TestHistoricalTrends(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	// Create and save two scans
	// Scan 1
	id1 := mustStartScanScope(t, ctx, db, "program-x")
	mustSaveTargets(t, ctx, db, id1, []string{"target1.com"})
	mustSaveEvents(t, ctx, db, id1, []EventRecord{
		{Target: "target1.com", Source: "subfinder", Type: "subdomain"},
	})
	insights1 := []InsightRecord{
		{Host: "target1.com", Priority: "medium", Score: 50, Tags: []string{"subdomain"}},
	}
	if err := db.SaveInsights(ctx, id1, insights1); err != nil {
		t.Fatalf("Failed to save insights 1: %v", err)
	}
	mustFinishScan(t, ctx, db, id1)
	_, _ = db.db.Exec(`UPDATE scans SET start_time = '2026-06-12 10:00:00' WHERE id = ?`, id1)

	// Scan 2
	id2 := mustStartScanScope(t, ctx, db, "program-x")
	mustSaveTargets(t, ctx, db, id2, []string{"target1.com", "target2.com"})
	mustSaveEvents(t, ctx, db, id2, []EventRecord{
		{Target: "target1.com", Source: "subfinder", Type: "subdomain"},
		{Target: "target2.com", Source: "httpx", Type: "service"},
	})
	insights2 := []InsightRecord{
		{Host: "target1.com", Priority: "high", Score: 80, Tags: []string{"subdomain", "vulnerable"}},
		{Host: "target2.com", Priority: "low", Score: 20, Tags: []string{"service"}},
	}
	if err := db.SaveInsights(ctx, id2, insights2); err != nil {
		t.Fatalf("Failed to save insights 2: %v", err)
	}
	mustFinishScan(t, ctx, db, id2)
	_, _ = db.db.Exec(`UPDATE scans SET start_time = '2026-06-12 10:05:00' WHERE id = ?`, id2)

	// 1. Test GetRiskHistory
	riskHistory, err := db.GetRiskHistory(ctx, "target1.com", 0, 0)
	if err != nil {
		t.Fatalf("Failed to get risk history: %v", err)
	}
	if len(riskHistory) != 2 {
		t.Fatalf("Expected 2 risk history entries, got %d", len(riskHistory))
	}
	if riskHistory[0].Score != 50 || riskHistory[1].Score != 80 {
		t.Errorf("Unexpected scores in history: %v", riskHistory)
	}

	// 2. Test GetRiskTrend
	riskTrend, err := db.GetRiskTrend(ctx, "program-x", 0, 0)
	if err != nil {
		t.Fatalf("Failed to get risk trend: %v", err)
	}
	if len(riskTrend) != 2 {
		t.Fatalf("Expected 2 risk trend entries, got %d", len(riskTrend))
	}

	// 3. Test GetTechTrend
	techTrend, err := db.GetTechTrend(ctx, "program-x", 0, 0)
	if err != nil {
		t.Fatalf("Failed to get tech trend: %v", err)
	}
	if len(techTrend) != 2 {
		t.Fatalf("Expected 2 tech trend entries, got %d", len(techTrend))
	}

	// 4. Test GetAssetHistory
	assetHistory, err := db.GetAssetHistory(ctx, "target1.com", 0, 0)
	if err != nil {
		t.Fatalf("Failed to get asset history: %v", err)
	}
	if len(assetHistory) != 2 {
		t.Fatalf("Expected 2 asset history entries, got %d", len(assetHistory))
	}

	// 5. Test GetFindingHistory
	findingHistory, err := db.GetFindingHistory(ctx, "target1.com", 0, 0)
	if err != nil {
		t.Fatalf("Failed to get finding history: %v", err)
	}
	if len(findingHistory) != 2 {
		t.Fatalf("Expected 2 finding history entries, got %d", len(findingHistory))
	}

	// 6. Test GetOwnershipHistory
	// First manually insert teams, owners and ownership mappings
	_, err = db.db.Exec(`INSERT INTO teams (name) VALUES ('Team A')`)
	if err != nil {
		t.Fatalf("Failed to insert team: %v", err)
	}
	_, err = db.db.Exec(`INSERT INTO owners (name, email) VALUES ('Owner A', 'owner@a.com')`)
	if err != nil {
		t.Fatalf("Failed to insert owner: %v", err)
	}
	_, err = db.db.Exec(`INSERT INTO asset_ownership (asset_id, owner_id, team_id, start_time, change_reason) VALUES ('target1.com', 1, 1, CURRENT_TIMESTAMP, 'initial assignment')`)
	if err != nil {
		t.Fatalf("Failed to insert asset ownership: %v", err)
	}

	ownHistory, err := db.GetOwnershipHistory(ctx, "target1.com", 0, 0)
	if err != nil {
		t.Fatalf("Failed to get ownership history: %v", err)
	}
	if len(ownHistory) != 1 {
		t.Fatalf("Expected 1 ownership history entry, got %d", len(ownHistory))
	}
	if ownHistory[0].OwnerName != "Owner A" || ownHistory[0].TeamName != "Team A" || ownHistory[0].ChangeReason != "initial assignment" {
		t.Errorf("Unexpected ownership details: %+v", ownHistory[0])
	}
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	// 1. Pagination for GetScans
	id1 := mustStartScanScope(t, ctx, db, "scope1")
	mustFinishScan(t, ctx, db, id1)
	id2 := mustStartScanScope(t, ctx, db, "scope2")
	mustFinishScan(t, ctx, db, id2)
	id3 := mustStartScanScope(t, ctx, db, "scope3")
	mustFinishScan(t, ctx, db, id3)

	scans, err := db.GetScans(ctx, 2, 1)
	if err != nil {
		t.Fatalf("Failed to get scans with pagination: %v", err)
	}
	// order is DESC (id3 first, then id2, then id1)
	// limit 2, offset 1 should give: id2, id1
	if len(scans) != 2 {
		t.Fatalf("Expected 2 scans, got %d", len(scans))
	}
	if scans[0].ID != id2 || scans[1].ID != id1 {
		t.Errorf("Unexpected page contents: scan 0 is ID %d, scan 1 is ID %d", scans[0].ID, scans[1].ID)
	}

	// 2. Pagination for GetTargets
	mustSaveTargets(t, ctx, db, id1, []string{"t1", "t2", "t3", "t4"})
	targets, err := db.GetTargets(ctx, id1, 2, 1)
	if err != nil {
		t.Fatalf("Failed to get targets with pagination: %v", err)
	}
	// limit 2, offset 1 should give: t2, t3
	if len(targets) != 2 || targets[0] != "t2" || targets[1] != "t3" {
		t.Errorf("Unexpected targets page contents: %v", targets)
	}

	// 3. Pagination for GetEvents
	mustSaveEvents(t, ctx, db, id1, []EventRecord{
		{Target: "t1", Source: "src1", Type: "type1"},
		{Target: "t2", Source: "src2", Type: "type2"},
		{Target: "t3", Source: "src3", Type: "type3"},
	})
	events, err := db.GetEvents(ctx, id1, 1, 1)
	if err != nil {
		t.Fatalf("Failed to get events with pagination: %v", err)
	}
	// limit 1, offset 1 should give: t2
	if len(events) != 1 || events[0].Target != "t2" {
		t.Errorf("Unexpected events page contents: %v", events)
	}
}

func TestSaveAndGetEvidence(t *testing.T) {
	dir := t.TempDir()
	db := mustOpen(t, dir)
	defer db.Close()

	id := "evidence-001"
	assetID := "asset-sub.acme-corp.io"
	source := "nuclei"
	confidence := 0.95
	rawData := []byte(`{"vulnerability": "SQL Injection"}`)
	hash := "a1b2c3d4e5f6"

	err := db.SaveEvidence(id, assetID, source, confidence, rawData, hash)
	if err != nil {
		t.Fatalf("Failed to save evidence: %v", err)
	}

	evList, err := db.GetEvidenceByAssetID(assetID)
	if err != nil {
		t.Fatalf("Failed to retrieve evidence: %v", err)
	}

	if len(evList) != 1 {
		t.Fatalf("Expected 1 evidence item, got %d", len(evList))
	}

	retrieved := evList[0]
	if retrieved["id"] != id {
		t.Errorf("Expected id '%s', got '%v'", id, retrieved["id"])
	}
	if retrieved["source"] != source {
		t.Errorf("Expected source '%s', got '%v'", source, retrieved["source"])
	}
	if retrieved["confidence"] != confidence {
		t.Errorf("Expected confidence '%f', got '%v'", confidence, retrieved["confidence"])
	}
	if string(retrieved["raw_data"].([]byte)) != string(rawData) {
		t.Errorf("Expected raw data '%s', got '%s'", string(rawData), string(retrieved["raw_data"].([]byte)))
	}
	if retrieved["hash"] != hash {
		t.Errorf("Expected hash '%s', got '%v'", hash, retrieved["hash"])
	}
}
