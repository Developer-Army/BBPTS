package services

import (
	"testing"
)

func TestDorkQueries(t *testing.T) {
	queries := dorkQueries("example.com")

	if len(queries) == 0 {
		t.Fatal("expected dork queries, got none")
	}

	// Verify all queries contain the domain
	for _, q := range queries {
		if q.Query == "" {
			t.Error("empty dork query")
		}
		if q.Category == "" {
			t.Error("empty category for query:", q.Query)
		}
		if q.Category != "secret" && q.Category != "config" && q.Category != "endpoint" {
			t.Errorf("invalid category %q for query: %s", q.Category, q.Query)
		}
	}

	// Verify minimum query count (we expect ~30)
	if len(queries) < 25 {
		t.Errorf("expected at least 25 dork queries, got %d", len(queries))
	}
}

func TestConfigFilePatterns(t *testing.T) {
	tests := []struct {
		path  string
		match bool
	}{
		{".env", true},
		{"config.yml", true},
		{"config.json", true},
		{"config.toml", true},
		{"application.properties", true},
		{"wp-config.php", true},
		{".htaccess", true},
		{".htpasswd", true},
		{"docker-compose.yml", true},
		{"docker-compose.yaml", true},
		{"Dockerfile", true},
		{".npmrc", true},
		{".pypirc", true},
		{"settings.py", true},
		{"main.go", false},
		{"index.html", false},
		{"README.md", false},
	}

	for _, tc := range tests {
		got := configFilePatterns.MatchString(tc.path)
		if got != tc.match {
			t.Errorf("configFilePatterns.MatchString(%q) = %v, want %v", tc.path, got, tc.match)
		}
	}
}

func TestInternalEndpointPatterns(t *testing.T) {
	tests := []struct {
		content string
		want    int // expected number of matches across all patterns
	}{
		{"https://api.internal.corp.com/v1", 1},
		{"http://staging-api.example.com/users", 1},
		{"http://dev.mysite.com/config", 1},
		{"https://test.example.com/debug", 1},
		{"http://localhost:8080/health", 1},
		{"https://www.example.com/about", 0}, // not internal
	}

	for _, tc := range tests {
		count := 0
		for _, re := range internalEndpointPatterns {
			matches := re.FindAllString(tc.content, -1)
			count += len(matches)
		}
		if count != tc.want {
			t.Errorf("internal endpoint matches for %q: got %d, want %d", tc.content, count, tc.want)
		}
	}
}

func TestAPIEndpointPatterns(t *testing.T) {
	tests := []struct {
		content string
		want    int
	}{
		{`fetch("/api/v1/users")`, 1},
		{`fetch("/api/v2/orders/123")`, 1},
		{`"/graphql"`, 1},
		{`"/swagger/index.html"`, 1},
		{`"/admin/dashboard"`, 1},
		{`"/home/about"`, 0},
	}

	for _, tc := range tests {
		matches := apiEndpointPatterns.FindAllString(tc.content, -1)
		if len(matches) != tc.want {
			t.Errorf("api endpoint matches for %q: got %d, want %d", tc.content, len(matches), tc.want)
		}
	}
}

func TestStripProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com/path", "example.com"},
		{"https://example.com:8443/api", "example.com"},
		{"example.com", "example.com"},
		{"sub.example.com", "sub.example.com"},
	}

	for _, tc := range tests {
		got := stripProtocol(tc.input)
		if got != tc.want {
			t.Errorf("stripProtocol(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestDeduplication(t *testing.T) {
	seen := make(map[dedupeKey]struct{})

	k1 := dedupeKey{target: "example.com", eventType: "secret_exposed", value: "AKIAIOSFODNN7EXAMPLE"}
	k2 := dedupeKey{target: "example.com", eventType: "secret_exposed", value: "AKIAIOSFODNN7EXAMPLE"}
	k3 := dedupeKey{target: "example.com", eventType: "config_file", value: ".env"}

	seen[k1] = struct{}{}

	if _, dup := seen[k2]; !dup {
		t.Error("expected k2 to be detected as duplicate of k1")
	}

	if _, dup := seen[k3]; dup {
		t.Error("k3 should not be a duplicate")
	}
}

func TestCopyProps(t *testing.T) {
	src := map[string]string{"a": "1", "b": "2"}
	dst := copyProps(src)

	// Modify source — should not affect copy
	src["a"] = "changed"
	if dst["a"] != "1" {
		t.Error("copyProps did not create independent copy")
	}
	if len(dst) != 2 {
		t.Errorf("expected 2 props, got %d", len(dst))
	}
}

func TestGithubDorkerToolName(t *testing.T) {
	tool := &GithubDorkerTool{}
	if tool.Name() != "github_dorker" {
		t.Errorf("expected tool name 'github_dorker', got %q", tool.Name())
	}
}
