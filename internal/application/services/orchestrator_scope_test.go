package services

import (
	"testing"

	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
)

func TestFilterEventsInScope(t *testing.T) {
	sg := normalize.NewScopeGuard([]string{"acme-corp.io"})
	events := []Event{
		{Target: "https://acme-corp.io/login", Source: "katana"},
		{Target: "https://cdn.acme-corp.io/app.js", Source: "katana"},
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
