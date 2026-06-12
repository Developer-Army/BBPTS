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
