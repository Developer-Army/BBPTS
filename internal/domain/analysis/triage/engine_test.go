package triage

import (
	"testing"
)

func TestNewTriageEngine(t *testing.T) {
	te := NewTriageEngine()

	if te == nil {
		t.Fatal("NewTriageEngine returned nil")
	}

	if len(te.noisePatternsSubdomain) == 0 {
		t.Error("Expected noise patterns for subdomains")
	}

	if len(te.noisePatternsPort) == 0 {
		t.Error("Expected noise patterns for ports")
	}

	if len(te.noisePatternsEndpoint) == 0 {
		t.Error("Expected noise patterns for endpoints")
	}

	if len(te.noisePatternsHeader) == 0 {
		t.Error("Expected noise patterns for headers")
	}

	if len(te.commonCDNs) == 0 {
		t.Error("Expected common CDNs")
	}

	if len(te.commonSaaS) == 0 {
		t.Error("Expected common SaaS")
	}
}

func TestAnalyzeFinding(t *testing.T) {
	te := NewTriageEngine()

	tests := []struct {
		name     string
		finding  *Finding
		wantInfo bool
	}{
		{
			name: "subdomain finding",
			finding: &Finding{
				Type:   "subdomain",
				Target: "api.acme-corp.io",
			},
			wantInfo: false,
		},
		{
			name: "port finding",
			finding: &Finding{
				Type:   "port",
				Target: "acme-corp.io:8080",
			},
			wantInfo: false,
		},
		{
			name: "endpoint finding",
			finding: &Finding{
				Type:   "endpoint",
				Target: "https://acme-corp.io/api/users",
			},
			wantInfo: false,
		},
		{
			name: "header finding",
			finding: &Finding{
				Type:   "header",
				Target: "x-frame-options: SAMEORIGIN",
			},
			wantInfo: false,
		},
		{
			name: "cookie finding",
			finding: &Finding{
				Type:   "cookie",
				Target: "sessionid=abc123",
			},
			wantInfo: false,
		},
		{
			name: "vulnerability finding",
			finding: &Finding{
				Type:   "vulnerability",
				Target: "CVE-2024-1234",
			},
			wantInfo: false,
		},
		{
			name: "unknown type",
			finding: &Finding{
				Type:   "unknown",
				Target: "something",
			},
			wantInfo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			te.AnalyzeFinding(tt.finding)

			if tt.finding.Severity == "" {
				t.Error("Expected severity to be set")
			}

			if tt.wantInfo && tt.finding.Severity != "info" {
				t.Errorf("Expected severity 'info', got '%s'", tt.finding.Severity)
			}
		})
	}
}

func TestAnalyzeSubdomain(t *testing.T) {
	te := NewTriageEngine()

	tests := []struct {
		name      string
		target    string
		wantNoise bool
		wantSev   string
		wantConf  float64
	}{
		{
			name:      "normal subdomain",
			target:    "api.acme-corp.io",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.8,
		},
		{
			name:      "test subdomain",
			target:    "test.acme-corp.io",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "staging subdomain",
			target:    "staging.acme-corp.io",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.8,
		},
		{
			name:      "dev subdomain",
			target:    "dev.acme-corp.io",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.8,
		},
		{
			name:      "cdn subdomain",
			target:    "cdn.acme-corp.io",
			wantNoise: true,
			wantSev:   "low",
			wantConf:  0.4,
		},
		{
			name:      "cloudflare subdomain",
			target:    "cloudflare.acme-corp.io",
			wantNoise: true,
			wantSev:   "low",
			wantConf:  0.4,
		},
		{
			name:      "static subdomain",
			target:    "static.acme-corp.io",
			wantNoise: true,
			wantSev:   "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Type:   "subdomain",
				Target: tt.target,
			}
			te.analyzeSubdomain(f)

			if f.IsNoise != tt.wantNoise {
				t.Errorf("Expected noise=%v, got %v", tt.wantNoise, f.IsNoise)
			}

			if f.Severity != tt.wantSev {
				t.Errorf("Expected severity '%s', got '%s'", tt.wantSev, f.Severity)
			}

			if tt.wantConf > 0 && f.Confidence != tt.wantConf {
				t.Errorf("Expected confidence %.2f, got %.2f", tt.wantConf, f.Confidence)
			}
		})
	}
}

func TestAnalyzePort(t *testing.T) {
	te := NewTriageEngine()

	tests := []struct {
		name      string
		target    string
		wantNoise bool
		wantSev   string
		wantConf  float64
	}{
		{
			name:      "SSH port",
			target:    "acme-corp.io:22",
			wantNoise: true,
			wantSev:   "low",
			wantConf:  0.5,
		},
		{
			name:      "SMTP port",
			target:    "acme-corp.io:25",
			wantNoise: true,
			wantSev:   "low",
			wantConf:  0.5,
		},
		{
			name:      "DNS port",
			target:    "acme-corp.io:53",
			wantNoise: true,
			wantSev:   "low",
			wantConf:  0.5,
		},
		{
			name:      "HTTP port",
			target:    "acme-corp.io:80",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.9,
		},
		{
			name:      "HTTPS port",
			target:    "acme-corp.io:443",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.9,
		},
		{
			name:      "HTTP alt port",
			target:    "acme-corp.io:8080",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.9,
		},
		{
			name:      "unknown port",
			target:    "acme-corp.io:9999",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Type:   "port",
				Target: tt.target,
			}
			te.analyzePort(f)

			if f.IsNoise != tt.wantNoise {
				t.Errorf("Expected noise=%v, got %v", tt.wantNoise, f.IsNoise)
			}

			if f.Severity != tt.wantSev {
				t.Errorf("Expected severity '%s', got '%s'", tt.wantSev, f.Severity)
			}

			if tt.wantConf > 0 && f.Confidence != tt.wantConf {
				t.Errorf("Expected confidence %.2f, got %.2f", tt.wantConf, f.Confidence)
			}
		})
	}
}

func TestAnalyzeEndpoint(t *testing.T) {
	te := NewTriageEngine()

	tests := []struct {
		name      string
		target    string
		wantNoise bool
		wantSev   string
		wantConf  float64
	}{
		{
			name:      "favicon",
			target:    "https://acme-corp.io/favicon.ico",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "robots.txt",
			target:    "https://acme-corp.io/robots.txt",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "admin endpoint",
			target:    "https://acme-corp.io/admin",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.85,
		},
		{
			name:      "api endpoint",
			target:    "https://acme-corp.io/api/users",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.85,
		},
		{
			name:      "config endpoint",
			target:    "https://acme-corp.io/config",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.85,
		},
		{
			name:      "backup endpoint",
			target:    "https://acme-corp.io/backup",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.85,
		},
		{
			name:      "endpoint with params",
			target:    "https://acme-corp.io/search?q=test",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.7,
		},
		{
			name:      "generic endpoint",
			target:    "https://acme-corp.io/page",
			wantNoise: false,
			wantSev:   "low",
			wantConf:  0.5,
		},
		{
			name:      "cdn path",
			target:    "https://acme-corp.io/cdn/static.js",
			wantNoise: true,
			wantSev:   "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Type:   "endpoint",
				Target: tt.target,
			}
			te.analyzeEndpoint(f)

			if f.IsNoise != tt.wantNoise {
				t.Errorf("Expected noise=%v, got %v", tt.wantNoise, f.IsNoise)
			}

			if f.Severity != tt.wantSev {
				t.Errorf("Expected severity '%s', got '%s'", tt.wantSev, f.Severity)
			}

			if tt.wantConf > 0 && f.Confidence != tt.wantConf {
				t.Errorf("Expected confidence %.2f, got %.2f", tt.wantConf, f.Confidence)
			}
		})
	}
}

func TestAnalyzeHeader(t *testing.T) {
	te := NewTriageEngine()

	tests := []struct {
		name      string
		target    string
		wantNoise bool
		wantSev   string
		wantConf  float64
	}{
		{
			name:      "x-aspnet-version",
			target:    "x-aspnet-version: 4.0.30319",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "server header",
			target:    "server: nginx/1.18.0",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "x-powered-by",
			target:    "x-powered-by: PHP/7.4",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "x-frame-options",
			target:    "x-frame-options: SAMEORIGIN",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.7,
		},
		{
			name:      "csp header",
			target:    "content-security-policy: default-src 'self'",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.7,
		},
		{
			name:      "hsts header",
			target:    "strict-transport-security: max-age=31536000",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.7,
		},
		{
			name:      "via header",
			target:    "via: 1.1 google",
			wantNoise: true,
			wantSev:   "low",
			wantConf:  0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Type:   "header",
				Target: tt.target,
			}
			te.analyzeHeader(f)

			if f.IsNoise != tt.wantNoise {
				t.Errorf("Expected noise=%v, got %v", tt.wantNoise, f.IsNoise)
			}

			if f.Severity != tt.wantSev {
				t.Errorf("Expected severity '%s', got '%s'", tt.wantSev, f.Severity)
			}

			if tt.wantConf > 0 && f.Confidence != tt.wantConf {
				t.Errorf("Expected confidence %.2f, got %.2f", tt.wantConf, f.Confidence)
			}
		})
	}
}

func TestAnalyzeCookie(t *testing.T) {
	te := NewTriageEngine()

	tests := []struct {
		name      string
		target    string
		wantNoise bool
		wantSev   string
		wantConf  float64
	}{
		{
			name:      "httponly false",
			target:    "session=abc; httponly=false",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.9,
		},
		{
			name:      "secure false",
			target:    "session=abc; secure=false",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.9,
		},
		{
			name:      "session cookie",
			target:    "sessionid=abc123",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.8,
		},
		{
			name:      "jsessionid",
			target:    "jsessionid=abc123",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.8,
		},
		{
			name:      "utm cookie",
			target:    "utm_source=google",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "_ga cookie",
			target:    "_ga=GA1.2.123456789.1234567890",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "generic cookie",
			target:    "pref=dark",
			wantNoise: false,
			wantSev:   "low",
			wantConf:  0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Type:   "cookie",
				Target: tt.target,
			}
			te.analyzeCookie(f)

			if f.IsNoise != tt.wantNoise {
				t.Errorf("Expected noise=%v, got %v", tt.wantNoise, f.IsNoise)
			}

			if f.Severity != tt.wantSev {
				t.Errorf("Expected severity '%s', got '%s'", tt.wantSev, f.Severity)
			}

			if tt.wantConf > 0 && f.Confidence != tt.wantConf {
				t.Errorf("Expected confidence %.2f, got %.2f", tt.wantConf, f.Confidence)
			}
		})
	}
}

func TestAnalyzeVulnerability(t *testing.T) {
	te := NewTriageEngine()

	tests := []struct {
		name      string
		target    string
		wantNoise bool
		wantSev   string
		wantConf  float64
	}{
		{
			name:      "critical CVE",
			target:    "CVE-2024-1234 critical severity 9.5",
			wantNoise: false,
			wantSev:   "critical",
			wantConf:  0.95,
		},
		{
			name:      "high CVE",
			target:    "CVE-2024-5678 high severity 8.2",
			wantNoise: false,
			wantSev:   "high",
			wantConf:  0.9,
		},
		{
			name:      "medium CVE",
			target:    "CVE-2024-9012 medium severity",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.8,
		},
		{
			name:      "wont fix",
			target:    "wont fix - not applicable",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "false positive",
			target:    "false positive - informational",
			wantNoise: true,
			wantSev:   "info",
		},
		{
			name:      "generic vulnerability",
			target:    "some vulnerability",
			wantNoise: false,
			wantSev:   "medium",
			wantConf:  0.6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				Type:   "vulnerability",
				Target: tt.target,
			}
			te.analyzeVulnerability(f)

			if f.IsNoise != tt.wantNoise {
				t.Errorf("Expected noise=%v, got %v", tt.wantNoise, f.IsNoise)
			}

			if f.Severity != tt.wantSev {
				t.Errorf("Expected severity '%s', got '%s'", tt.wantSev, f.Severity)
			}

			if tt.wantConf > 0 && f.Confidence != tt.wantConf {
				t.Errorf("Expected confidence %.2f, got %.2f", tt.wantConf, f.Confidence)
			}
		})
	}
}

func TestPrioritizeFindings(t *testing.T) {
	te := NewTriageEngine()

	findings := []*Finding{
		{Type: "subdomain", Target: "test.acme-corp.io"},
		{Type: "port", Target: "acme-corp.io:80"},
		{Type: "endpoint", Target: "https://acme-corp.io/admin"},
		{Type: "vulnerability", Target: "CVE-2024-1234 critical"},
	}

	prioritized := te.PrioritizeFindings(findings)

	if len(prioritized) != len(findings) {
		t.Errorf("Expected %d findings, got %d", len(findings), len(prioritized))
	}

	// Check that critical comes first
	if prioritized[0].Severity != "critical" {
		t.Errorf("Expected first finding to be critical, got %s", prioritized[0].Severity)
	}
}

func TestFilterNoise(t *testing.T) {
	te := NewTriageEngine()

	findings := []*Finding{
		{Type: "subdomain", Target: "test.acme-corp.io"},
		{Type: "port", Target: "acme-corp.io:80"},
		{Type: "endpoint", Target: "https://acme-corp.io/favicon.ico"},
		{Type: "endpoint", Target: "https://acme-corp.io/admin"},
	}

	actionable := te.FilterNoise(findings)

	// Should filter out test subdomain and favicon
	if len(actionable) >= len(findings) {
		t.Error("Expected some findings to be filtered as noise")
	}

	for _, f := range actionable {
		if f.IsNoise {
			t.Error("Expected all filtered findings to not be noise")
		}
	}
}

func TestGetStats(t *testing.T) {
	te := NewTriageEngine()

	findings := []*Finding{
		{Type: "subdomain", Target: "test.acme-corp.io"},
		{Type: "subdomain", Target: "api.acme-corp.io"},
		{Type: "port", Target: "acme-corp.io:80"},
		{Type: "endpoint", Target: "https://acme-corp.io/favicon.ico"},
	}

	stats := te.GetStats(findings)

	if stats["total"] != 4 {
		t.Errorf("Expected total 4, got %v", stats["total"])
	}

	bySeverity, ok := stats["by_severity"].(map[string]int)
	if !ok {
		t.Fatal("Expected by_severity to be a map")
	}

	if bySeverity["info"] == 0 {
		t.Error("Expected some info severity findings")
	}

	byType, ok := stats["by_type"].(map[string]int)
	if !ok {
		t.Fatal("Expected by_type to be a map")
	}

	if byType["subdomain"] != 2 {
		t.Errorf("Expected 2 subdomain findings, got %d", byType["subdomain"])
	}

	noiseCount, ok := stats["noise_count"].(int)
	if !ok {
		t.Fatal("Expected noise_count to be an int")
	}

	if noiseCount == 0 {
		t.Error("Expected some noise findings")
	}

	actionableCount, ok := stats["actionable_count"].(int)
	if !ok {
		t.Fatal("Expected actionable_count to be an int")
	}

	if actionableCount+noiseCount != 4 {
		t.Error("Actionable + noise should equal total")
	}
}
