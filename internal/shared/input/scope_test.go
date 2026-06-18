package input

import (
	"strings"
	"testing"
)

func TestScopeEngine(t *testing.T) {
	scopeContent := `
# Allowed scope
*.example.com
corp.local

# Excluded scope
!*.staging.example.com
exclude:prod.staging.example.com
`
	engine, err := ParseScope(strings.NewReader(scopeContent))
	if err != nil {
		t.Fatalf("failed to parse scope: %v", err)
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"abc.example.com", true},
		{"xyz.staging.example.com", false},
		{"prod.staging.example.com", false},
		{"corp.local", true},
		{"other.com", false},
		{"https://sub.example.com/path", true},
	}

	for _, tt := range tests {
		got := engine.IsInScope(tt.target)
		if got != tt.want {
			t.Errorf("IsInScope(%q) = %v; want %v", tt.target, got, tt.want)
		}
	}
}

func TestParseJSONScope(t *testing.T) {
	// 1. HackerOne format
	h1JSON := `{
		"structured_scopes": [
			{"asset_identifier": "*.h1allow.com", "asset_type": "URL", "eligible_for_submission": true},
			{"asset_identifier": "h1block.com", "asset_type": "URL", "eligible_for_submission": false}
		]
	}`
	seH1, err := ParseScope(strings.NewReader(h1JSON))
	if err != nil {
		t.Fatalf("failed to parse HackerOne scope: %v", err)
	}
	if !seH1.IsInScope("test.h1allow.com") {
		t.Errorf("expected test.h1allow.com to be in scope")
	}
	if seH1.IsInScope("h1block.com") {
		t.Errorf("expected h1block.com to be excluded")
	}

	// 2. Bugcrowd format
	bcJSON := `{
		"target_groups": [
			{
				"name": "inscope-group",
				"in_scope": true,
				"targets": [
					{"name": "*.bcallow.com", "category": "website", "in_scope": true},
					{"name": "bcblock.com", "category": "website", "in_scope": false}
				]
			}
		]
	}`
	seBC, err := ParseScope(strings.NewReader(bcJSON))
	if err != nil {
		t.Fatalf("failed to parse Bugcrowd scope: %v", err)
	}
	if !seBC.IsInScope("test.bcallow.com") {
		t.Errorf("expected test.bcallow.com to be in scope")
	}
	if seBC.IsInScope("bcblock.com") {
		t.Errorf("expected bcblock.com to be excluded")
	}
}

