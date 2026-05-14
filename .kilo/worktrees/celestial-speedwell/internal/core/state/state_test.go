package state

import (
	"path/filepath"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/engine/recon"
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

	targets := []string{"example.com", "api.example.com"}
	events := []recon.Event{
		{Target: "https://example.com", Source: "httpx", Type: "service"},
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

	initialTargets := []string{"api.example.com"}
	initialEvents := []recon.Event{
		{Target: "api.example.com", Source: "subfinder", Type: "discovery"},
	}
	if err := store.Save("program-b", initialTargets, initialEvents); err != nil {
		t.Fatalf("failed to save initial snapshot: %v", err)
	}

	updatedTargets := []string{"api.example.com", "dev.example.com"}
	updatedEvents := []recon.Event{
		{Target: "api.example.com", Source: "subfinder", Type: "discovery"},
		{Target: "dev.example.com", Source: "subfinder", Type: "discovery"},
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
	if len(diff.NewTargets) != 1 || diff.NewTargets[0] != "dev.example.com" {
		t.Fatalf("expected dev.example.com as the only new target, got %#v", diff.NewTargets)
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
