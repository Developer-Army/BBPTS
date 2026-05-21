package model

import "testing"

func TestClassifyTarget(t *testing.T) {
	tests := []struct {
		target   string
		expected string
	}{
		{"", "unknown"},
		{"192.168.1.1", "ip"},
		{"10.0.0.1", "ip"},
		{"acme-corp.io", "domain"},
		{"acme-corp.io:8080", "host:port"},
		{"sub.example.co.uk", "domain"},
	}

	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			got := ClassifyTarget(tc.target)
			if got != tc.expected {
				t.Errorf("expected %s, got %s for target %s", tc.expected, got, tc.target)
			}
		})
	}
}
