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
			inputs:   []string{" acme-corp.io ", "test.com\n", "acme-corp.io"},
			expected: []string{"acme-corp.io", "test.com"},
		},
		{
			name:     "urls to domains",
			inputs:   []string{"https://acme-corp.io/", "http://test.com/path", "https://acme-corp.io:443"},
			expected: []string{"acme-corp.io", "test.com"},
		},
		{
			name:     "IPs and CIDR",
			inputs:   []string{"192.168.1.1", "10.0.0.0/24", "192.168.1.1"},
			expected: []string{"192.168.1.1", "10.0.0.0/24"},
		},
		{
			name:     "host with port",
			inputs:   []string{"acme-corp.io:8080", "test.com:80"},
			expected: []string{"acme-corp.io:8080", "test.com:80"},
		},
		{
			name:     "invalid IP addresses and invalid domains",
			inputs:   []string{"256.256.256.256", "invalid_domain", "hello...world", "123.456.789.0"},
			expected: []string{},
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
		"https://acme-corp.io/",
		"https://acme-corp.io",
		"https://acme-corp.io:443/path#frag",
		"http://test.com:80/a",
		"http://test.com/a",
		"api.acme-corp.io",
		"api.acme-corp.io",
	}

	expected := []string{
		"https://acme-corp.io",
		"https://acme-corp.io/path",
		"http://test.com/a",
		"api.acme-corp.io",
	}

	got := DeduplicateAndPreserveURLs(inputs)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
}
