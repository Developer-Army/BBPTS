package cluster

import (
	"testing"

	"github.com/Developer-Army/BBPTS/internal/application/services"
)

func TestDedupeEvents_MergesSameURLDifferentSources(t *testing.T) {
	events := []recon.Event{
		{Target: "https://api.example.com/v1/users?x=1", Source: "httpx", Type: "probe"},
		{Target: "https://api.example.com/v1/users?x=1", Source: "katana", Type: "crawl"},
	}
	out := DedupeEvents(events)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped event, got %d", len(out))
	}
	if out[0].Properties["bbpts_sources"] != "httpx,katana" {
		t.Fatalf("unexpected merged sources: %q", out[0].Properties["bbpts_sources"])
	}
}

func TestDedupeEvents_KeepsDistinctPaths(t *testing.T) {
	events := []recon.Event{
		{Target: "https://example.com/a", Source: "httpx"},
		{Target: "https://example.com/b", Source: "httpx"},
	}
	out := DedupeEvents(events)
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

func TestDedupeEvents_Empty(t *testing.T) {
	if DedupeEvents(nil) != nil {
		t.Fatal("expected nil")
	}
	if len(DedupeEvents([]recon.Event{})) != 0 {
		t.Fatal("expected empty slice")
	}
}
