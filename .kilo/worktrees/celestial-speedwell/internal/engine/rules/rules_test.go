package rules

import (
	"testing"

	"github.com/Developer-Army/BBPTS/internal/engine/recon"
)

func TestRuleSet_Evaluate(t *testing.T) {
	rs := DefaultRules()

	tests := []struct {
		name          string
		events        []recon.Event
		wantMatchIDs  []string
		wantToolNames []string
	}{
		{
			name: "match exposed env",
			events: []recon.Event{
				{Target: "https://example.com/.env", Source: "httpx"},
			},
			wantMatchIDs: []string{"exposed-env"},
		},
		{
			name: "match wildcard and trigger tool",
			events: []recon.Event{
				{Target: "*.example.com", Source: "crtsh"},
			},
			wantMatchIDs:  []string{"crtsh-wildcard"},
			wantToolNames: []string{"subfinder"},
		},
		{
			name: "no match",
			events: []recon.Event{
				{Target: "https://example.com/index.html", Source: "httpx"},
			},
			wantMatchIDs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, tools := rs.Evaluate(tt.events)

			if len(matches) != len(tt.wantMatchIDs) {
				t.Errorf("got %d matches, want %d", len(matches), len(tt.wantMatchIDs))
			}

			for i, id := range tt.wantMatchIDs {
				if matches[i].Rule.ID != id {
					t.Errorf("got match ID %s, want %s", matches[i].Rule.ID, id)
				}
			}

			if len(tools) != len(tt.wantToolNames) {
				t.Errorf("got %d triggered tools, want %d", len(tools), len(tt.wantToolNames))
			}
		})
	}
}
