package normalize

import (
	"reflect"
	"testing"
)

func TestDeduplicateAndNormalize(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []string
		expected []string
	}{
		{
			name:     "empty inputs",
			inputs:   []string{},
			expected: []string{},
		},
		{
			name:     "basic domains with whitespace",
			inputs:   []string{" example.com ", "test.com\n", "example.com"},
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "urls to domains",
			inputs:   []string{"https://example.com/", "http://test.com/path", "https://example.com:443"},
			expected: []string{"example.com", "test.com"},
		},
		{
			name:     "IPs and CIDR",
			inputs:   []string{"192.168.1.1", "10.0.0.0/24", "192.168.1.1"},
			expected: []string{"192.168.1.1", "10.0.0.0/24"},
		},
		{
			name:     "host with port",
			inputs:   []string{"example.com:8080", "test.com:80"},
			expected: []string{"example.com:8080", "test.com:80"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DeduplicateAndNormalize(tc.inputs)
			if len(got) == 0 && len(tc.expected) == 0 {
				return // both empty
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("expected %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestDeduplicateAndPreserveURLs(t *testing.T) {
	inputs := []string{
		"https://example.com/",
		"https://example.com",
		"https://example.com:443/path#frag",
		"http://test.com:80/a",
		"http://test.com/a",
		"api.example.com",
		"api.example.com",
	}

	expected := []string{
		"https://example.com",
		"https://example.com/path",
		"http://test.com/a",
		"api.example.com",
	}

	got := DeduplicateAndPreserveURLs(inputs)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}
