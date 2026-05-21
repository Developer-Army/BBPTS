package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	// Register the CLI flags first so that flag.Lookup can resolve them.
	if flag.Lookup("light") == nil {
		flag.Bool("light", false, "")
	}
	if flag.Lookup("input") == nil {
		flag.String("input", "", "")
	}
	if flag.Lookup("i") == nil {
		flag.String("i", "", "")
	}
	if flag.Lookup("threads") == nil {
		flag.Int("threads", 0, "")
	}

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "positional then boolean flag",
			input:    []string{"scopes.csv", "--light"},
			expected: []string{"--light", "scopes.csv"},
		},
		{
			name:     "positional then string flag with value",
			input:    []string{"scopes.csv", "-i", "other.txt"},
			expected: []string{"-i", "other.txt", "scopes.csv"},
		},
		{
			name:     "string flag, value, positional, bool flag",
			input:    []string{"-i", "targets.txt", "scopes.csv", "--light"},
			expected: []string{"-i", "targets.txt", "--light", "scopes.csv"},
		},
		{
			name:     "flag with equal sign",
			input:    []string{"scopes.csv", "--threads=10"},
			expected: []string{"--threads=10", "scopes.csv"},
		},
		{
			name:     "unknown flag",
			input:    []string{"scopes.csv", "--unknown-flag"},
			expected: []string{"--unknown-flag", "scopes.csv"},
		},
		{
			name:     "terminator --",
			input:    []string{"scopes.csv", "--", "--light", "-i", "other.txt"},
			expected: []string{"scopes.csv", "--", "--light", "-i", "other.txt"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := reorderArgs(tc.input)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("reorderArgs(%v) = %v; want %v", tc.input, got, tc.expected)
			}
		})
	}
}
