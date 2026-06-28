package tools

import (
	"context"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func TestGetTechTagsForTargets(t *testing.T) {
	tempDir := t.TempDir()
	store, err := storage.NewStorage("sqlite", tempDir+"/test.db")
	if err != nil {
		t.Fatalf("failed to create test storage: %v", err)
	}
	defer store.Close()

	ctx := storage.WithStorage(context.Background(), store)

	// Save a mock event representing an httpx result with technology stack
	target := "https://example.com"
	ev := recon.Event{
		Target: target,
		Source: "httpx",
		Type:   "service",
		Properties: map[string]string{
			"technologies": "wordpress,cloudflare",
		},
	}
	err = store.SaveEvent(ev)
	if err != nil {
		t.Fatalf("failed to save mock event: %v", err)
	}

	tags := getTechTagsForTargets(ctx, []string{target})
	if len(tags) != 2 {
		t.Fatalf("expected 2 tech tags, got %d: %v", len(tags), tags)
	}

	expectedTags := map[string]bool{
		"wordpress":  true,
		"cloudflare": true,
	}

	for _, tag := range tags {
		if !expectedTags[tag] {
			t.Errorf("unexpected tag: %s", tag)
		}
	}
}
