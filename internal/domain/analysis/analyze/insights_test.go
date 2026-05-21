package analyze

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"strings"
	"testing"
)

func TestDeriveInsights(t *testing.T) {
	targets := []string{"acme-corp.io"}
	events := []recon.Event{
		{
			Target: "https://acme-corp.io/api/v1/users?id=1",
			Source: "httpx",
			Properties: map[string]string{
				"server": "nginx",
			},
		},
		{
			Target: "admin.acme-corp.io",
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
		if i.Host == "admin.acme-corp.io" {
			adminInsight = &copy
		} else if i.Host == "acme-corp.io" {
			exampleInsight = &copy
		}
	}

	if adminInsight == nil {
		t.Fatalf("missing admin.acme-corp.io insight")
	}
	if exampleInsight == nil {
		t.Fatalf("missing acme-corp.io insight")
	}

	// Verify tags
	foundAuth := false
	for _, tag := range adminInsight.Tags {
		if tag == "auth" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Errorf("expected 'auth' tag on admin.acme-corp.io")
	}

	foundApi := false
	for _, tag := range exampleInsight.Tags {
		if tag == "api" {
			foundApi = true
		}
	}
	if !foundApi {
		t.Errorf("expected 'api' tag on acme-corp.io")
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
			targets: []string{"acme-corp.io"},
			events: []recon.Event{
				{Target: "https://acme-corp.io/.env", Source: "gobuster"},
			},
			wantTags: []string{"sensitive"},
			minScore: 35, // 10 base + 25 sensitive
		},
		{
			name:    "High Value Subdomain",
			targets: []string{"acme-corp.io"},
			events: []recon.Event{
				{Target: "dev.acme-corp.io", Source: "subfinder"},
			},
			wantTags: []string{"high-value-scope", "discovery"},
			minScore: 35, // 10 base + 20 high-value + 5 discovery
		},
		{
			name:    "LFI Candidate",
			targets: []string{"acme-corp.io"},
			events: []recon.Event{
				{Target: "https://acme-corp.io/view?file=test.txt", Source: "katana"},
			},
			wantTags: []string{"parameterized", "lfi-candidate"},
			minScore: 33, // 10 base + 8 param + 15 lfi
		},
		{
			name:    "SQLi Candidate Category Filter",
			targets: []string{"acme-corp.io"},
			events: []recon.Event{
				{Target: "https://acme-corp.io/filter?category=Gifts", Source: "katana"},
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
	targets := []string{"acme-corp.io"}
	events := []recon.Event{
		{Target: "https://acme-corp.io/product?category=Accessories", Source: "katana"},
		{Target: "https://acme-corp.io/product?id=12", Source: "gau"},
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
	targets := []string{"acme-corp.io"}
	events := []recon.Event{
		{Target: "https://acme-corp.io/search?query=shoes", Source: "katana"},
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
	targets := []string{"acme-corp.io"}
	events := []recon.Event{
		{
			Target: "https://api.acme-corp.io/v1/users?id=1&redirect=https://a.com&token=abc",
			Source: "katana",
		},
		{
			Target: "https://api.acme-corp.io/login",
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
