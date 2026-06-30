package input

import (
	"os"
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

func TestScopeEngineCIDR(t *testing.T) {
	scopeContent := `
# Allowed scope CIDR
192.168.1.0/24
10.0.0.5

# Excluded scope CIDR
!192.168.1.50
exclude:192.168.1.128/25
`
	engine, err := ParseScope(strings.NewReader(scopeContent))
	if err != nil {
		t.Fatalf("failed to parse scope: %v", err)
	}

	tests := []struct {
		target string
		want   bool
	}{
		{"192.168.1.10", true},
		{"192.168.1.50", false},
		{"192.168.1.200", false},
		{"10.0.0.5", true},
		{"10.0.0.6", false},
		{"192.168.2.1", false},
	}

	for _, tt := range tests {
		got := engine.IsInScope(tt.target)
		if got != tt.want {
			t.Errorf("IsInScope(%q) = %v; want %v", tt.target, got, tt.want)
		}
	}
}

func TestNewScopeEngine(t *testing.T) {
	allows := []string{"*.example.com"}
	excludes := []string{"blocked.example.com"}
	engine := NewScopeEngine(allows, excludes)
	if len(engine.Allows) != 1 || engine.Allows[0] != "*.example.com" {
		t.Errorf("expected Allows to match")
	}
	if len(engine.Excludes) != 1 || engine.Excludes[0] != "blocked.example.com" {
		t.Errorf("expected Excludes to match")
	}
}

func TestLoadScopeFile(t *testing.T) {

	tempFile, err := os.CreateTemp("", "bbpts-scope-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	content := "*.test.local\n!blocked.test.local\n"
	if _, err := tempFile.Write([]byte(content)); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tempFile.Close()

	engine, err := LoadScopeFile(tempFile.Name())
	if err != nil {
		t.Fatalf("LoadScopeFile failed: %v", err)
	}

	if !engine.IsInScope("hello.test.local") {
		t.Errorf("expected hello.test.local to be in scope")
	}
	if engine.IsInScope("blocked.test.local") {
		t.Errorf("expected blocked.test.local to be out of scope")
	}
}

func TestLoadScopeFileNotFound(t *testing.T) {
	_, err := LoadScopeFile("nonexistent-file-path-xyz.txt")
	if err == nil {
		t.Errorf("expected error for nonexistent file, got nil")
	}
}

func TestParseAlternateJSON(t *testing.T) {
	altJSON := `[
		{"asset_identifier": "alt1.com", "eligible_for_submission": true},
		{"asset_identifier": "alt2.com", "eligible_for_submission": false}
	]`
	engine, err := ParseScope(strings.NewReader(altJSON))
	if err != nil {
		t.Fatalf("failed to parse alternate JSON: %v", err)
	}
	if !engine.IsInScope("alt1.com") {
		t.Errorf("expected alt1.com to be in scope")
	}
	if engine.IsInScope("alt2.com") {
		t.Errorf("expected alt2.com to be excluded")
	}
}
