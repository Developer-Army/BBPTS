package tools

import (
	"testing"
)

func TestIsValidTarget(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"example.com", true},
		{"http://example.com", true},
		{"https://example.com/some/path", true},
		{"http://example.com:8080", true},
		{"invalid target space", false},
		{"http://", false},
		{"ftp://example.com", false},
		{"", false},
		{".example.com", false},
		{"example.com-", false},
	}

	for _, tt := range tests {
		got := isValidTarget(tt.target)
		if got != tt.want {
			t.Errorf("isValidTarget(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestIsParkedOrForSale(t *testing.T) {
	tests := []struct {
		title string
		want  bool
	}{
		{"Domain For Sale", true},
		{"This domain is for sale!", true},
		{"Buy this domain name", true},
		{"Parked Domain", true},
		{"Welcome to example.com", false},
		{"Under Construction", true},
		{"Coming Soon!", true},
		{"My Awesome Blog", false},
	}

	for _, tt := range tests {
		got := isParkedOrForSale(tt.title)
		if got != tt.want {
			t.Errorf("isParkedOrForSale(%q) = %v, want %v", tt.title, got, tt.want)
		}
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://sub.example.com:8080/path", "sub.example.com"},
		{"example.com/path", "example.com"},
	}

	for _, tt := range tests {
		got := extractHost(tt.target)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.target, got, tt.want)
		}
	}
}
