package services

import (
	"testing"

	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
)

func TestFilterEventsInScope(t *testing.T) {
	sg := normalize.NewScopeGuard([]string{"example.com"})
	events := []Event{
		{Target: "https://example.com/login", Source: "katana"},
		{Target: "https://cdn.example.com/app.js", Source: "katana"},
		{Target: "https://youtube.com/watch?v=1", Source: "katana"},
	}

	filtered := filterEventsInScope(sg, events)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 in-scope events, got %d", len(filtered))
	}
	for _, ev := range filtered {
		if !sg.IsAllowed(ev.Target) {
			t.Fatalf("unexpected out-of-scope event kept: %s", ev.Target)
		}
	}
}
