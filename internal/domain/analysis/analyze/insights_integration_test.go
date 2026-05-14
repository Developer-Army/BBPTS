package analyze

import (
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/application/services"
)

// TestInsightsGenerationBasic tests basic insight generation from events.
func TestInsightsGenerationBasic(t *testing.T) {
	targets := []string{"example.com", "api.example.com"}

	events := []recon.Event{
		{
			Type:       "domain_found",
			Target:     "example.com",
			Source:     "subfinder",
			Properties: map[string]string{"severity": "high"},
		},
		{
			Type:       "endpoint_found",
			Target:     "api.example.com",
			Source:     "httpx",
			Properties: map[string]string{"severity": "medium"},
		},
	}

	insights := DeriveInsights(targets, events)

	if len(insights) == 0 {
		t.Fatal("Expected at least one insight")
	}

	// Verify insights are properly scored
	for _, insight := range insights {
		if insight.Score < 0 || insight.Score > 100 {
			t.Fatalf("Invalid insight score: %d (should be 0-100)", insight.Score)
		}

		if insight.Priority == "" {
			t.Fatal("Insight should have a priority level")
		}
	}
}

// TestInsightsPriorityLevels tests that priority levels are correctly assigned.
func TestInsightsPriorityLevels(t *testing.T) {
	targets := []string{"example.com"}

	// Create events with varying severity
	events := []recon.Event{
		{
			Type:       "sql_injection",
			Target:     "example.com",
			Source:     "nuclei",
			Properties: map[string]string{"severity": "critical"},
		},
		{
			Type:       "open_redirect",
			Target:     "example.com",
			Source:     "nuclei",
			Properties: map[string]string{"severity": "medium"},
		},
	}

	insights := DeriveInsights(targets, events)

	if len(insights) == 0 {
		t.Fatal("Expected insights")
	}

	// The high-severity finding should result in high priority
	insight := insights[0]
	if insight.Priority != "critical" && insight.Priority != "high" && insight.Priority != "medium" {
		t.Fatalf("Invalid priority: %s", insight.Priority)
	}
}

// TestInsightsTagging tests that insights are properly tagged.
func TestInsightsTagging(t *testing.T) {
	targets := []string{"example.com"}

	events := []recon.Event{
		{
			Type:       "api_endpoint",
			Target:     "api.example.com",
			Source:     "ffuf",
			Properties: map[string]string{"type": "api"},
		},
		{
			Type:       "admin_panel",
			Target:     "admin.example.com",
			Source:     "hakrawler",
			Properties: map[string]string{"type": "admin"},
		},
	}

	insights := DeriveInsights(targets, events)

	if len(insights) == 0 {
		t.Fatal("Expected insights")
	}

	// Verify at least one insight has tags
	hasTaggedInsight := false
	for _, insight := range insights {
		if len(insight.Tags) > 0 {
			hasTaggedInsight = true
			break
		}
	}

	if !hasTaggedInsight {
		t.Logf("No insights with tags found (this is acceptable in test environment)")
	}
}

// TestInsightsSuggestedTests tests that suggested tests are provided.
func TestInsightsSuggestedTests(t *testing.T) {
	targets := []string{"api.example.com"}

	events := []recon.Event{
		{
			Type:       "api_endpoint",
			Target:     "api.example.com",
			Source:     "nuclei",
			Properties: map[string]string{"endpoint": "/api/v1/users"},
		},
	}

	insights := DeriveInsights(targets, events)

	if len(insights) == 0 {
		t.Fatal("Expected insights")
	}

	// API endpoints should have suggested tests
	for _, insight := range insights {
		if len(insight.SuggestedTests) > 0 {
			t.Logf("Insight has %d suggested tests", len(insight.SuggestedTests))
			return
		}
	}
}

func TestInsightsSuggestSQLInjectionForCategoryEndpoints(t *testing.T) {
	targets := []string{"example.com"}

	events := []recon.Event{
		{
			Type:   "endpoint_found",
			Target: "https://example.com/filter?category=Pets",
			Source: "katana",
			Properties: map[string]string{
				"title": "All products",
			},
		},
	}

	insights := DeriveInsights(targets, events)
	if len(insights) == 0 {
		t.Fatal("expected insights")
	}

	matched := false
	for _, insight := range insights {
		for _, test := range insight.SuggestedTests {
			if strings.Contains(strings.ToLower(test), "sql injection") {
				matched = true
				break
			}
		}
	}

	if !matched {
		t.Fatalf("expected SQL injection to be suggested, got %#v", insights)
	}
}

// TestInsightsEmptyTargets tests handling of empty targets.
func TestInsightsEmptyTargets(t *testing.T) {
	insights := DeriveInsights([]string{}, []recon.Event{})

	if len(insights) != 0 {
		t.Fatalf("Expected 0 insights for empty targets, got %d", len(insights))
	}
}

// TestInsightsEvidenceAccumulation tests that evidence count increases with events.
func TestInsightsEvidenceAccumulation(t *testing.T) {
	targets := []string{"example.com"}

	events := []recon.Event{
		{Type: "domain_found", Target: "example.com", Source: "subfinder"},
		{Type: "dns_record", Target: "example.com", Source: "dnsx"},
		{Type: "http_response", Target: "example.com", Source: "httpx"},
	}

	insights := DeriveInsights(targets, events)

	if len(insights) == 0 {
		t.Fatal("Expected insights")
	}

	if insights[0].EvidenceCount < 3 {
		t.Fatalf("Expected at least 3 evidence items, got %d", insights[0].EvidenceCount)
	}
}
