package recon

import (
	"sort"
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name       string
		rawHeaders string
		title      string
		expected   []string
	}{
		{
			name:       "Laravel detect via session cookie",
			rawHeaders: "HTTP/1.1 200 OK\r\nSet-Cookie: laravel_session=xyz123; path=/; HttpOnly",
			title:      "My Application",
			expected:   []string{"laravel"},
		},
		{
			name:       "WordPress detect via header and title",
			rawHeaders: "HTTP/1.1 200 OK\r\nX-Pingback: https://blog.example.com/xmlrpc.php",
			title:      "WordPress Blog Site",
			expected:   []string{"wordpress"},
		},
		{
			name:       "Cloudflare WAF and CDN detect",
			rawHeaders: "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-RAY: 89ab1234cd",
			title:      "Protected Website",
			expected:   []string{"cloudflare"},
		},
		{
			name:       "Spring Boot and Okta auth",
			rawHeaders: "HTTP/1.1 500 Internal Error\r\nSet-Cookie: JSESSIONID=abc; Path=/\r\nX-Okta-Request-Id: okta-id-123",
			title:      "Whitelabel Error Page",
			expected:   []string{"spring boot", "okta"},
		},
		{
			name:       "No technology matched",
			rawHeaders: "HTTP/1.1 200 OK\r\nContent-Type: text/html",
			title:      "Simple Page",
			expected:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.rawHeaders, tt.title)
			sort.Strings(got)
			sort.Strings(tt.expected)

			if len(got) != len(tt.expected) {
				t.Errorf("Detect() = %v, expected %v", got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("Detect() = %v, expected %v", got, tt.expected)
					return
				}
			}
		})
	}
}
