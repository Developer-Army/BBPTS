package analyze

import (
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/application/services"
)

func TestDeriveInsights(t *testing.T) {
	targets := []string{"example.com"}
	events := []recon.Event{
		{
			Target: "https://example.com/api/v1/users?id=1",
			Source: "httpx",
			Properties: map[string]string{
				"server": "nginx",
			},
		},
		{
			Target: "admin.example.com",
			Source: "subfinder",
			Properties: map[string]string{
				"title": "Admin Login",
			},
		},
	}

	insights := DeriveInsights(targets, events)

	if len(insights) != 2 {
		t.Fatalf("expected 2 insights, got %d", len(insights))
	}

	var adminInsight *Insight
	var exampleInsight *Insight

	for _, i := range insights {
		// need a copy since i is value
		copy := i
		if i.Host == "admin.example.com" {
			adminInsight = &copy
		} else if i.Host == "example.com" {
			exampleInsight = &copy
		}
	}

	if adminInsight == nil {
		t.Fatalf("missing admin.example.com insight")
	}
	if exampleInsight == nil {
		t.Fatalf("missing example.com insight")
	}

	// Verify tags
	foundAuth := false
	for _, tag := range adminInsight.Tags {
		if tag == "auth" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Errorf("expected 'auth' tag on admin.example.com")
	}

	foundApi := false
	for _, tag := range exampleInsight.Tags {
		if tag == "api" {
			foundApi = true
		}
	}
	if !foundApi {
		t.Errorf("expected 'api' tag on example.com")
	}
}

func TestAnalyzers(t *testing.T) {
	tests := []struct {
		name     string
		targets  []string
		events   []recon.Event
		wantTags []string
		minScore int
	}{
		{
			name:    "Sensitive File Detection",
			targets: []string{"example.com"},
			events: []recon.Event{
				{Target: "https://example.com/.env", Source: "gobuster"},
			},
			wantTags: []string{"sensitive"},
			minScore: 35, // 10 base + 25 sensitive
		},
		{
			name:    "High Value Subdomain",
			targets: []string{"example.com"},
			events: []recon.Event{
				{Target: "dev.example.com", Source: "subfinder"},
			},
			wantTags: []string{"high-value-scope", "discovery"},
			minScore: 35, // 10 base + 20 high-value + 5 discovery
		},
		{
			name:    "LFI Candidate",
			targets: []string{"example.com"},
			events: []recon.Event{
				{Target: "https://example.com/view?file=test.txt", Source: "katana"},
			},
			wantTags: []string{"parameterized", "lfi-candidate"},
			minScore: 33, // 10 base + 8 param + 15 lfi
		},
		{
			name:    "SQLi Candidate Category Filter",
			targets: []string{"example.com"},
			events: []recon.Event{
				{Target: "https://example.com/filter?category=Gifts", Source: "katana"},
			},
			wantTags: []string{"parameterized", "sqli-candidate"},
			minScore: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insights := DeriveInsights(tt.targets, tt.events)
			if len(insights) == 0 {
				t.Fatalf("expected insights, got 0")
			}

			insight := insights[0]
			for _, want := range tt.wantTags {
				found := false
				for _, got := range insight.Tags {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing tag: %s, got: %v", want, insight.Tags)
				}
			}

			if insight.Score < tt.minScore {
				t.Errorf("score too low: %d, expected at least %d", insight.Score, tt.minScore)
			}
		})
	}
}

func TestSQLiSuggestedTestsForSelectorParameters(t *testing.T) {
	targets := []string{"example.com"}
	events := []recon.Event{
		{Target: "https://example.com/product?category=Accessories", Source: "katana"},
		{Target: "https://example.com/product?id=12", Source: "gau"},
	}

	insights := DeriveInsights(targets, events)
	if len(insights) == 0 {
		t.Fatal("expected insights")
	}

	foundSQLITest := false
	foundSQLITag := false
	for _, test := range insights[0].SuggestedTests {
		if strings.Contains(strings.ToLower(test), "sql injection") {
			foundSQLITest = true
			break
		}
	}
	for _, tag := range insights[0].Tags {
		if tag == "sqli-candidate" {
			foundSQLITag = true
			break
		}
	}

	if !foundSQLITag {
		t.Fatalf("expected sqli-candidate tag, got %v", insights[0].Tags)
	}
	if !foundSQLITest {
		t.Fatalf("expected SQL injection suggested test, got %v", insights[0].SuggestedTests)
	}
}

func TestSQLiSuggestedTestsForGenericQueryParameters(t *testing.T) {
	targets := []string{"example.com"}
	events := []recon.Event{
		{Target: "https://example.com/search?query=shoes", Source: "katana"},
	}

	insights := DeriveInsights(targets, events)
	if len(insights) == 0 {
		t.Fatal("expected insights")
	}

	foundSQLITest := false
	for _, test := range insights[0].SuggestedTests {
		if strings.Contains(strings.ToLower(test), "sql injection") {
			foundSQLITest = true
			break
		}
	}

	if !foundSQLITest {
		t.Fatalf("expected SQL injection suggested test for generic query endpoint, got %v", insights[0].SuggestedTests)
	}
}

func TestSuggestedTests_AreExpandedAndSpecific(t *testing.T) {
	targets := []string{"example.com"}
	events := []recon.Event{
		{
			Target: "https://api.example.com/v1/users?id=1&redirect=https://a.com&token=abc",
			Source: "katana",
		},
		{
			Target: "https://api.example.com/login",
			Source: "httpx",
		},
	}

	insights := DeriveInsights(targets, events)
	if len(insights) == 0 {
		t.Fatal("expected insights")
	}

	if len(insights[0].SuggestedTests) < 8 {
		t.Fatalf("expected richer suggested test set, got %d: %v", len(insights[0].SuggestedTests), insights[0].SuggestedTests)
	}

	joined := strings.ToLower(strings.Join(insights[0].SuggestedTests, " | "))
	if !strings.Contains(joined, "idor") {
		t.Fatalf("expected IDOR/BOLA-specific suggestion, got %v", insights[0].SuggestedTests)
	}
	if !strings.Contains(joined, "open redirect") {
		t.Fatalf("expected open-redirect specific suggestion, got %v", insights[0].SuggestedTests)
	}
	if !strings.Contains(joined, "token") {
		t.Fatalf("expected token-specific suggestion, got %v", insights[0].SuggestedTests)
	}
}
