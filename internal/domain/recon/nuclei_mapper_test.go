package recon

import (
	"testing"
)

func TestNucleiTagMapping(t *testing.T) {
	if len(NucleiTagMapping) == 0 {
		t.Error("NucleiTagMapping should not be empty")
	}

	// Verify each mapping has valid structure
	for bbptsTag, nucleiTags := range NucleiTagMapping {
		if bbptsTag == "" {
			t.Error("BBPTS tag should not be empty")
		}
		if len(nucleiTags) == 0 {
			t.Errorf("Nuclei tags for '%s' should not be empty", bbptsTag)
		}
	}
}

func TestNucleiSeverityForPriority(t *testing.T) {
	if len(NucleiSeverityForPriority) == 0 {
		t.Error("NucleiSeverityForPriority should not be empty")
	}

	// Verify each priority has valid severity levels
	expectedPriorities := []string{"critical", "high", "medium", "low"}
	for _, priority := range expectedPriorities {
		sevs, ok := NucleiSeverityForPriority[priority]
		if !ok {
			t.Errorf("Priority '%s' not found in NucleiSeverityForPriority", priority)
		}
		if len(sevs) == 0 {
			t.Errorf("Severity levels for priority '%s' should not be empty", priority)
		}
	}
}

func TestResolveTags(t *testing.T) {
	tests := []struct {
		name      string
		bbptsTags []string
		expected  []string
		minCount  int
	}{
		{
			name:      "exposed-secrets tag",
			bbptsTags: []string{"exposed-secrets"},
			minCount:  1,
		},
		{
			name:      "graphql tag",
			bbptsTags: []string{"graphql"},
			minCount:  1,
		},
		{
			name:      "admin-panel tag",
			bbptsTags: []string{"admin-panel"},
			minCount:  1,
		},
		{
			name:      "multiple tags",
			bbptsTags: []string{"graphql", "api-docs"},
			minCount:  2,
		},
		{
			name:      "unknown tag",
			bbptsTags: []string{"unknown-tag"},
			minCount:  0,
		},
		{
			name:      "empty tags",
			bbptsTags: []string{},
			minCount:  0,
		},
		{
			name:      "case insensitive",
			bbptsTags: []string{"GRAPHQL"},
			minCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResolveTags(tt.bbptsTags)
			if len(result) < tt.minCount {
				t.Errorf("expected at least %d tags, got %d", tt.minCount, len(result))
			}

			// Check for duplicates
			seen := make(map[string]bool)
			for _, tag := range result {
				if seen[tag] {
					t.Errorf("duplicate tag found: %s", tag)
				}
				seen[tag] = true
			}
		})
	}
}

func TestResolveTags_Deduplication(t *testing.T) {
	// Test that duplicate tags are removed
	bbptsTags := []string{"graphql", "graphql", "api-docs", "api-docs"}
	result := ResolveTags(bbptsTags)

	seen := make(map[string]bool)
	for _, tag := range result {
		if seen[tag] {
			t.Errorf("duplicate tag found: %s", tag)
		}
		seen[tag] = true
	}
}

func TestResolveTags_Overlap(t *testing.T) {
	// Test that overlapping tags from different BBPTS tags are deduplicated
	bbptsTags := []string{"graphql", "api-docs"} // both map to "swagger"
	result := ResolveTags(bbptsTags)

	seen := make(map[string]bool)
	for _, tag := range result {
		if seen[tag] {
			t.Errorf("duplicate tag found: %s", tag)
		}
		seen[tag] = true
	}
}

func TestResolveSeverity(t *testing.T) {
	tests := []struct {
		name     string
		priority string
		minCount int
	}{
		{"critical", "critical", 5},
		{"high", "high", 4},
		{"medium", "medium", 3},
		{"low", "low", 2},
		{"unknown", "unknown", 2}, // defaults to high, critical
		{"empty", "", 2},          // defaults to high, critical
		{"case insensitive", "CRITICAL", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResolveSeverity(tt.priority)
			if len(result) < tt.minCount {
				t.Errorf("expected at least %d severity levels, got %d", tt.minCount, len(result))
			}
		})
	}
}

func TestResolveSeverity_Default(t *testing.T) {
	// Test that unknown priorities return default
	result := ResolveSeverity("nonexistent-priority")

	if len(result) != 2 {
		t.Errorf("expected 2 default severity levels, got %d", len(result))
	}

	// Default should be high, critical
	expectedSeverities := map[string]bool{"high": true, "critical": true}
	for _, sev := range result {
		if !expectedSeverities[sev] {
			t.Errorf("unexpected severity in default: %s", sev)
		}
	}
}

func TestNucleiTagMapping_Coverage(t *testing.T) {
	// Test that important BBPTS tags are mapped
	importantTags := []string{
		"exposed-secrets",
		"source-disclosure",
		"backup-file",
		"graphql",
		"admin-panel",
		"ci-exposure",
		"api-docs",
		"db-exposure",
		"cloud-storage",
		"dev-environment",
		"api",
		"auth",
		"parameterized",
		"subdomain",
		"infrastructure",
	}

	for _, tag := range importantTags {
		if _, ok := NucleiTagMapping[tag]; !ok {
			t.Errorf("important tag '%s' not found in NucleiTagMapping", tag)
		}
	}
}

func TestNucleiSeverityForPriority_Coverage(t *testing.T) {
	// Test that all priority levels are defined
	expectedPriorities := []string{"critical", "high", "medium", "low"}
	for _, priority := range expectedPriorities {
		if _, ok := NucleiSeverityForPriority[priority]; !ok {
			t.Errorf("priority '%s' not found in NucleiSeverityForPriority", priority)
		}
	}
}

func TestResolveTags_Ordering(t *testing.T) {
	// Test that tags are returned in a consistent order
	bbptsTags := []string{"graphql", "api-docs"}
	result1 := ResolveTags(bbptsTags)
	result2 := ResolveTags(bbptsTags)

	if len(result1) != len(result2) {
		t.Error("results should have same length")
	}

	for i := range result1 {
		if result1[i] != result2[i] {
			t.Errorf("results should be consistent, got %s vs %s at index %d", result1[i], result2[i], i)
		}
	}
}

func TestResolveTemplateSubsets(t *testing.T) {
	tests := []struct {
		name     string
		techs    []string
		expected []string
	}{
		{
			name:     "WordPress and Laravel",
			techs:    []string{"wordpress", "laravel"},
			expected: []string{"wp-*", "php-*"},
		},
		{
			name:     "Case insensitivity and spaces",
			techs:    []string{"  WordPress ", "Django"},
			expected: []string{"wp-*", "django-*", "python-*"},
		},
		{
			name:     "Unmapped technology",
			techs:    []string{"unknown-framework"},
			expected: []string{},
		},
		{
			name:     "Deduplication",
			techs:    []string{"wordpress", "wordpress"},
			expected: []string{"wp-*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveTemplateSubsets(tt.techs)
			if len(got) != len(tt.expected) {
				t.Fatalf("ResolveTemplateSubsets() = %v, expected %v", got, tt.expected)
			}
			expectedMap := make(map[string]bool)
			for _, e := range tt.expected {
				expectedMap[e] = true
			}
			for _, g := range got {
				if !expectedMap[g] {
					t.Errorf("Unexpected subset found: %s", g)
				}
			}
		})
	}
}
