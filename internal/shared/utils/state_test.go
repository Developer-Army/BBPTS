package utils

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func TestStoreInitialization(t *testing.T) {
	store, err := NewStore(t.TempDir(), false)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestStoreSaveAndLoadLatest(t *testing.T) {
	store, err := NewStore(t.TempDir(), false)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	targets := []string{"acme-corp.io", "api.acme-corp.io"}
	events := []recon.Event{
		{Target: "https://acme-corp.io", Source: "httpx", Type: "service"},
	}

	if err := store.Save("program-a", targets, events); err != nil {
		t.Fatalf("failed to save store state: %v", err)
	}

	snap, err := store.LoadLatest("program-a")
	if err != nil {
		t.Fatalf("failed to load latest snapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("expected snapshot to exist")
	}
	if len(snap.Targets) != len(targets) {
		t.Fatalf("expected %d targets, got %d", len(targets), len(snap.Targets))
	}
}

func TestStoreComputeDiff(t *testing.T) {
	store, err := NewStore(t.TempDir(), false)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	initialTargets := []string{"api.acme-corp.io"}
	initialEvents := []recon.Event{
		{Target: "api.acme-corp.io", Source: "subfinder", Type: "discovery"},
	}
	if err := store.Save("program-b", initialTargets, initialEvents); err != nil {
		t.Fatalf("failed to save initial snapshot: %v", err)
	}

	updatedTargets := []string{"api.acme-corp.io", "dev.acme-corp.io"}
	updatedEvents := []recon.Event{
		{Target: "api.acme-corp.io", Source: "subfinder", Type: "discovery"},
		{Target: "dev.acme-corp.io", Source: "subfinder", Type: "discovery"},
	}
	if err := store.Save("program-b", updatedTargets, updatedEvents); err != nil {
		t.Fatalf("failed to save updated snapshot: %v", err)
	}

	diff, err := store.ComputeDiff("program-b", updatedTargets, updatedEvents)
	if err != nil {
		t.Fatalf("failed to compute diff: %v", err)
	}
	if diff == nil {
		t.Fatal("expected diff result")
	}
	if len(diff.NewTargets) != 1 || diff.NewTargets[0] != "dev.acme-corp.io" {
		t.Fatalf("expected dev.acme-corp.io as the only new target, got %#v", diff.NewTargets)
	}
}

func TestStorePaths(t *testing.T) {
	base := t.TempDir()
	store, err := NewStore(base, false)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	if got := store.snapshotPath("scope1"); got != filepath.Join(base, "scope1_latest.json") {
		t.Fatalf("unexpected latest snapshot path: %s", got)
	}
	if got := store.previousPath("scope1"); got != filepath.Join(base, "scope1_previous.json") {
		t.Fatalf("unexpected previous snapshot path: %s", got)
	}
	if got := store.diffPath("scope1"); got != filepath.Join(base, "scope1_diff.json") {
		t.Fatalf("unexpected diff path: %s", got)
	}
}

func TestStoreComputeDiff_RiskChangesAndNewlyExposed(t *testing.T) {
	store, err := NewStore(t.TempDir(), false)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	initialTargets := []string{"a.com", "b.com"}

	initialEvents := []recon.Event{
		{Target: "http://a.com/jenkins", Source: "httpx", Type: "service"},
		{Target: "http://b.com/", Source: "httpx", Type: "service"},
	}
	if err := store.Save("program-c", initialTargets, initialEvents); err != nil {
		t.Fatalf("failed to save initial snapshot: %v", err)
	}

	updatedTargets := []string{"a.com", "b.com"}

	updatedEvents := []recon.Event{
		{Target: "http://a.com/jenkins", Source: "httpx", Type: "service"},
		{Target: "http://b.com/", Source: "httpx", Type: "service"},
		{Target: "http://b.com/jenkins", Source: "httpx", Type: "service"},
		{Target: "http://b.com/.env", Source: "httpx", Type: "service"},
	}
	if err := store.Save("program-c", updatedTargets, updatedEvents); err != nil {
		t.Fatalf("failed to save updated snapshot: %v", err)
	}

	diff, err := store.ComputeDiff("program-c", updatedTargets, updatedEvents)
	if err != nil {
		t.Fatalf("failed to compute diff: %v", err)
	}

	if diff == nil {
		t.Fatal("expected non-nil diff")
	}

	if len(diff.RiskChanges) != 1 {
		t.Fatalf("expected exactly 1 risk change, got %d", len(diff.RiskChanges))
	}
	rc := diff.RiskChanges[0]
	if rc.Host != "b.com" {
		t.Errorf("expected risk change host to be b.com, got %s", rc.Host)
	}
	if rc.CurrentScore <= rc.PreviousScore {
		t.Errorf("expected current score (%d) to be greater than previous score (%d)", rc.CurrentScore, rc.PreviousScore)
	}

	if len(diff.NewlyExposed) != 1 {
		t.Fatalf("expected exactly 1 newly exposed asset, got %d", len(diff.NewlyExposed))
	}
	ne := diff.NewlyExposed[0]
	if ne.Host != "b.com" {
		t.Errorf("expected newly exposed host to be b.com, got %s", ne.Host)
	}
	if len(ne.Why) == 0 {
		t.Error("expected explanation reasons in Why field")
	}

	md := diff.ToMarkdown("program-c")
	if !strings.Contains(md, "Riskier Assets") {
		t.Error("expected markdown to contain 'Riskier Assets' section")
	}
	if !strings.Contains(md, "Newly Exposed Assets") {
		t.Error("expected markdown to contain 'Newly Exposed Assets' section")
	}
	if !strings.Contains(md, "b.com") {
		t.Error("expected markdown to mention b.com")
	}
}
