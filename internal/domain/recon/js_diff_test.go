package recon

import (
	"testing"
)

func TestRegexExtractRoutes(t *testing.T) {
	js := `const api = '/api/users'; fetch('/api/v1/posts');`
	routes := regexExtractRoutes(js)

	if len(routes) == 0 {
		t.Error("expected at least one route")
	}

	// Check that routes have expected structure
	for _, route := range routes {
		if route.Path == "" {
			t.Error("route path should not be empty")
		}
		if route.Method == "" {
			t.Error("route method should not be empty")
		}
	}
}

func TestRegexExtractRoutes_FiltersNoise(t *testing.T) {
	js := `const js = '/path/to/file.js'; const valid = '/api/users';`
	routes := regexExtractRoutes(js)

	// Should filter out .js paths
	for _, route := range routes {
		if contains(route.Path, ".js") {
			t.Errorf("should filter out .js paths, got: %s", route.Path)
		}
	}
}

func TestDiffBundles(t *testing.T) {
	oldJS := `const api = '/api/users';`
	newJS := `const api = '/api/users'; const admin = '/admin';`

	diff := DiffBundles(oldJS, newJS)

	if diff == nil {
		t.Fatal("DiffBundles should not return nil")
	}

	if diff.OldHash == "" {
		t.Error("OldHash should not be empty")
	}

	if diff.NewHash == "" {
		t.Error("NewHash should not be empty")
	}

	// Should detect added routes
	if len(diff.Added) == 0 {
		t.Error("should detect added routes")
	}
}

func TestDiffBundles_NoChanges(t *testing.T) {
	js := `const api = '/api/users';`

	diff := DiffBundles(js, js)

	if diff == nil {
		t.Fatal("DiffBundles should not return nil")
	}

	if len(diff.Added) != 0 {
		t.Errorf("expected 0 added routes, got %d", len(diff.Added))
	}

	if len(diff.Removed) != 0 {
		t.Errorf("expected 0 removed routes, got %d", len(diff.Removed))
	}
}

func TestDiffBundles_RemovedRoutes(t *testing.T) {
	oldJS := `const api = '/api/users'; const admin = '/admin';`
	newJS := `const api = '/api/users';`

	diff := DiffBundles(oldJS, newJS)

	if len(diff.Removed) == 0 {
		t.Error("should detect removed routes")
	}
}

func TestComputeRouteSignature(t *testing.T) {
	route := SemanticRoute{
		Path:       "/api/users",
		Method:     "GET",
		Variable:   "",
		SourceFile: "bundle.js",
	}

	sig := computeRouteSignature(route)

	if sig == "" {
		t.Error("signature should not be empty")
	}

	// Same route should produce same signature
	sig2 := computeRouteSignature(route)
	if sig != sig2 {
		t.Error("same route should produce same signature")
	}

	// Different route should produce different signature
	route2 := SemanticRoute{
		Path:       "/api/posts",
		Method:     "GET",
		Variable:   "",
		SourceFile: "bundle.js",
	}
	sig3 := computeRouteSignature(route2)
	if sig == sig3 {
		t.Error("different routes should produce different signatures")
	}
}

func TestComputeRouteSignature_Normalization(t *testing.T) {
	tests := []struct {
		name     string
		route1   SemanticRoute
		route2   SemanticRoute
		expected bool // true if signatures should be equal
	}{
		{
			name:     "trailing slash",
			route1:   SemanticRoute{Path: "/api/users/", Method: "GET"},
			route2:   SemanticRoute{Path: "/api/users", Method: "GET"},
			expected: true,
		},
		{
			name:     "query string",
			route1:   SemanticRoute{Path: "/api/users?id=1", Method: "GET"},
			route2:   SemanticRoute{Path: "/api/users", Method: "GET"},
			expected: true,
		},
		{
			name:     "different methods",
			route1:   SemanticRoute{Path: "/api/users", Method: "GET"},
			route2:   SemanticRoute{Path: "/api/users", Method: "POST"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig1 := computeRouteSignature(tt.route1)
			sig2 := computeRouteSignature(tt.route2)

			if (sig1 == sig2) != tt.expected {
				t.Errorf("expected signatures to be equal: %v, got %s vs %s", tt.expected, sig1, sig2)
			}
		})
	}
}

func TestHashBundle(t *testing.T) {
	js := `const api = '/api/users';`

	hash := hashBundle(js)

	if hash == "" {
		t.Error("hash should not be empty")
	}

	// Same content should produce same hash
	hash2 := hashBundle(js)
	if hash != hash2 {
		t.Error("same content should produce same hash")
	}

	// Different content should produce different hash
	js2 := `const api = '/api/posts';`
	hash3 := hashBundle(js2)
	if hash == hash3 {
		t.Error("different content should produce different hash")
	}
}

func TestJSBundleDiff_Summary(t *testing.T) {
	diff := &JSBundleDiff{
		Added:    []SemanticRoute{{Path: "/api/users"}},
		Removed:  []SemanticRoute{{Path: "/admin"}},
		Modified: []RouteModification{},
	}

	summary := diff.Summary()

	if summary == "" {
		t.Error("summary should not be empty")
	}

	if !contains(summary, "+") || !contains(summary, "-") {
		t.Error("summary should contain + and - indicators")
	}
}

func TestJSBundleDiff_Summary_NoChanges(t *testing.T) {
	diff := &JSBundleDiff{
		Added:    []SemanticRoute{},
		Removed:  []SemanticRoute{},
		Modified: []RouteModification{},
	}

	summary := diff.Summary()

	if !contains(summary, "No semantic changes") {
		t.Error("summary should indicate no changes")
	}
}

func TestJSBundleDiff_HighValueChanges(t *testing.T) {
	diff := &JSBundleDiff{
		Added: []SemanticRoute{
			{Path: "/api/users", Method: "GET"},
			{Path: "/admin", Method: "GET"},
			{Path: "/home", Method: "GET"},
		},
		Removed: []SemanticRoute{
			{Path: "/api/posts", Method: "POST"},
		},
	}

	highValue := diff.HighValueChanges()

	if len(highValue) == 0 {
		t.Error("should detect high-value changes")
	}

	// Should include /admin and /api routes
	foundAdmin := false
	foundAPI := false
	for _, r := range highValue {
		if contains(r.Path, "admin") {
			foundAdmin = true
		}
		if contains(r.Path, "api") {
			foundAPI = true
		}
	}

	if !foundAdmin {
		t.Error("should include /admin as high-value")
	}

	if !foundAPI {
		t.Error("should include /api routes as high-value")
	}
}

func TestIsHighValueRoute(t *testing.T) {
	tests := []struct {
		name     string
		route    SemanticRoute
		expected bool
	}{
		{"admin path", SemanticRoute{Path: "/admin", Method: "GET"}, true},
		{"api path", SemanticRoute{Path: "/api/users", Method: "GET"}, true},
		{"graphql", SemanticRoute{Path: "/graphql", Method: "POST", IsGraphQL: true}, true},
		{"auth flow", SemanticRoute{Path: "/login", Method: "GET", IsAuthFlow: true}, true},
		{"POST method", SemanticRoute{Path: "/submit", Method: "POST"}, true},
		{"PUT method", SemanticRoute{Path: "/update", Method: "PUT"}, true},
		{"DELETE method", SemanticRoute{Path: "/delete", Method: "DELETE"}, true},
		{"normal path", SemanticRoute{Path: "/home", Method: "GET"}, false},
		{"static asset", SemanticRoute{Path: "/style.css", Method: "GET"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHighValueRoute(tt.route)
			if result != tt.expected {
				t.Errorf("expected %v for %s, got %v", tt.expected, tt.name, result)
			}
		})
	}
}

func TestExtractAllRoutes(t *testing.T) {
	js := `const api = '/api/users'; fetch('/admin');`

	routes := extractAllRoutes(js)

	if len(routes) == 0 {
		t.Error("should extract at least one route")
	}

	// Check for duplicates
	seen := make(map[string]bool)
	for _, r := range routes {
		if seen[r.Signature] {
			t.Errorf("should not have duplicate routes, found duplicate: %s", r.Signature)
		}
		seen[r.Signature] = true
	}
}

func TestExtractRoutesFromNode(t *testing.T) {
	var routes []SemanticRoute

	// Test with nil node
	extractRoutesFromNode(nil, &routes)

	if len(routes) != 0 {
		t.Error("should not add routes for nil node")
	}
}
