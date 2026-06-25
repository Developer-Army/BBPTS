package services

import (
	"testing"
)

func TestConfidence(t *testing.T) {
	t.Run("Groups", TestScoreEvent_Groups)
	t.Run("Corroborate", TestCorroborateEvents)
}

func TestScoreEvent_Groups(t *testing.T) {
	tests := []struct {
		name          string
		event         Event
		expectedScore int
	}{
		{
			name: "Base Nuclei Vulnerability Confirmed",
			event: Event{
				Source: "nuclei",
				Type:   "vulnerability",
				Target: "https://example.com/api/v1/users",
				Properties: map[string]string{
					"status_code":       "200",
					"nuclei_confidence": "confirmed",
				},
			},
			expectedScore: 100,
		},
		{
			name: "GAU Info loopback 404 static",
			event: Event{
				Source: "gau",
				Type:   "info",
				Target: "http://127.0.0.1/static/main.js",
				Properties: map[string]string{
					"status_code":    "404",
					"content_length": "0",
				},
			},
			expectedScore: 0,
		},
		{
			name: "Nuclei Info Severity",
			event: Event{
				Source: "nuclei",
				Type:   "vulnerability",
				Target: "https://example.com/index.html",
				Properties: map[string]string{
					"status_code":     "200",
					"nuclei_severity": "info",
				},
			},
			expectedScore: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := ScoreEvent(tt.event)
			if score != tt.expectedScore {
				t.Errorf("expected score %d, got %d", tt.expectedScore, score)
			}
		})
	}
}

func TestCorroborateEvents(t *testing.T) {
	events := []Event{
		{Source: "nuclei", Target: "https://example.com/api/test", Type: "vulnerability"},
		{Source: "gau", Target: "https://example.com/api/test", Type: "discovery"},
	}

	corroborated := CorroborateEvents(events)

	if len(corroborated) != 2 {
		t.Fatalf("expected 2 events, got %d", len(corroborated))
	}

	if corroborated[0].Properties["corroborated_by"] != "gau" {
		t.Errorf("expected corroborated_by to be 'gau', got %q", corroborated[0].Properties["corroborated_by"])
	}

	if corroborated[1].Properties["corroborated_by"] != "nuclei" {
		t.Errorf("expected corroborated_by to be 'nuclei', got %q", corroborated[1].Properties["corroborated_by"])
	}
}
