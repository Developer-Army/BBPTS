package triage

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Finding represents a security finding for triage analysis.
type Finding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`         // subdomain, port, endpoint, header, cookie, etc.
	Target      string                 `json:"target"`       // The actual finding value
	Source      string                 `json:"source"`       // Tool that found it
	Severity    string                 `json:"severity"`     // critical, high, medium, low, info
	Confidence  float64                `json:"confidence"`   // 0.0-1.0
	IsNoise     bool                   `json:"is_noise"`     // Auto-detected noise
	NoiseReason string                 `json:"noise_reason"` // Why it's noise
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Timestamp   int64                  `json:"timestamp"`
}

// TriageEngine analyzes findings and auto-prioritizes them without external APIs.
type TriageEngine struct {
	noisePatternsSubdomain []string
	noisePatternsPort      []string
	noisePatternsEndpoint  []string
	noisePatternsHeader    []string

	commonCDNs []string
	commonSaaS []string
}

// NewTriageEngine creates a new AI-assisted triage engine.
func NewTriageEngine() *TriageEngine {
	te := &TriageEngine{
		// Known noise patterns for subdomains
		noisePatternsSubdomain: []string{
			// Common wildcards and placeholders
			"*.example", "*.test", "*.local", "*.internal",
			// Generated/test subdomains
			"test-", "staging-", "dev-", "tmp-", "temp-",
			"docker-", "k8s-", "lab-", "sandbox-",
			// Common CDN/3rd party
			"cdn", "static", "media", "assets", "images",
			"api-stg", "api-dev", "api-test",
		},

		// Known noise patterns for ports
		noisePatternsPort: []string{
			// These are less likely to be real findings
			":22",    // SSH (infrastructure, not security finding)
			":25",    // SMTP (mail server)
			":53",    // DNS (infrastructure)
			":631",   // CUPS printing
			":5432",  // PostgreSQL default (internal)
			":6379",  // Redis default (internal)
			":27017", // MongoDB default (internal)
		},

		// Known noise patterns for endpoints
		noisePatternsEndpoint: []string{
			// Marketing/tracking pixels
			"pixel", "beacon", "analytics", "tracker",
			// Ad networks
			"/ads/", "/banner", "/dfa/",
			// Common public endpoints
			"/favicon.ico", "/robots.txt", "/sitemap.xml",
			"/health", "/status", "/ping", "/.well-known",
			// CDN paths
			"/cdn/", "/static/", "/assets/", "/public/",
		},

		// Known noise patterns for headers
		noisePatternsHeader: []string{
			"x-aspnet-version", // Version fingerprint (common, not actionable)
			"server: nginx",    // Server info (common)
			"x-powered-by",     // Framework info (common)
		},

		// Common CDNs and SaaS platforms
		commonCDNs: []string{
			"cloudflare", "akamai", "fastly", "cloudfront",
			"edgecast", "limelight", "highwinds",
		},

		commonSaaS: []string{
			"salesforce", "zendesk", "shopify", "github",
			"twitter", "facebook", "google", "amazon",
		},
	}

	return te
}

// AnalyzeFinding analyzes a finding and returns severity/noise classification.
func (te *TriageEngine) AnalyzeFinding(f *Finding) {
	// Default confidence
	if f.Confidence == 0 {
		f.Confidence = 0.5
	}

	// Analyze based on finding type
	switch f.Type {
	case "subdomain":
		te.analyzeSubdomain(f)
	case "port", "port_open":
		te.analyzePort(f)
	case "endpoint", "js_endpoint":
		te.analyzeEndpoint(f)
	case "header", "response_header":
		te.analyzeHeader(f)
	case "cookie":
		te.analyzeCookie(f)
	case "vulnerability":
		te.analyzeVulnerability(f)
	default:
		f.Severity = "info"
	}

	slog.Debug("Finding analyzed", "id", f.ID, "severity", f.Severity, "is_noise", f.IsNoise)
}

// analyzeSubdomain checks if a subdomain is noise or actionable.
func (te *TriageEngine) analyzeSubdomain(f *Finding) {
	target := strings.ToLower(f.Target)

	// Check against noise patterns
	for _, pattern := range te.noisePatternsSubdomain {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("matches noise pattern: %s", pattern)
			f.Severity = "info"
			return
		}
	}

	// Check if it's a CDN or SaaS CNAME
	for _, cdn := range te.commonCDNs {
		if strings.Contains(target, cdn) {
			f.Severity = "low"
			f.Confidence = 0.4
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("CDN: %s", cdn)
			return
		}
	}

	// Real subdomain finding
	f.Severity = "medium"
	f.Confidence = 0.8
	f.IsNoise = false
}

// analyzePort checks if a port finding is actionable.
func (te *TriageEngine) analyzePort(f *Finding) {
	target := strings.ToLower(f.Target)

	// Check infrastructure ports (low value)
	for _, pattern := range te.noisePatternsPort {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("infrastructure port: %s", pattern)
			f.Severity = "low"
			f.Confidence = 0.5
			return
		}
	}

	// Common web ports - actionable
	commonWebPorts := []string{":80", ":443", ":8080", ":8443", ":3000", ":5000", ":9000"}
	for _, port := range commonWebPorts {
		if strings.Contains(target, port) {
			f.Severity = "high"
			f.Confidence = 0.9
			f.IsNoise = false
			return
		}
	}

	// Unknown open port - interesting
	f.Severity = "medium"
	f.Confidence = 0.7
	f.IsNoise = false
}

// analyzeEndpoint checks if an endpoint is actionable.
func (te *TriageEngine) analyzeEndpoint(f *Finding) {
	target := strings.ToLower(f.Target)

	// Check noise patterns
	for _, pattern := range te.noisePatternsEndpoint {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("matches noise pattern: %s", pattern)
			f.Severity = "info"
			return
		}
	}

	// Check for admin/sensitive paths
	sensitivePatterns := []string{
		"/admin", "/api", "/config", "/backup", "/database",
		"/debug", "/test", "/.env", "/private", "/secret",
		"/internal", "/login", "/auth", "/user",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(target, pattern) {
			f.Severity = "high"
			f.Confidence = 0.85
			f.IsNoise = false
			return
		}
	}

	// Check for parameter injection points
	if strings.Contains(target, "?") || strings.Contains(target, "&") {
		f.Severity = "medium"
		f.Confidence = 0.7
		f.IsNoise = false
		return
	}

	// Generic endpoint
	f.Severity = "low"
	f.Confidence = 0.5
	f.IsNoise = false
}

// analyzeHeader checks if a header is actionable.
func (te *TriageEngine) analyzeHeader(f *Finding) {
	target := strings.ToLower(f.Target)

	// Check noise patterns
	for _, pattern := range te.noisePatternsHeader {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("common header: %s", pattern)
			f.Severity = "info"
			return
		}
	}

	// Security-relevant headers
	securityHeaders := []string{
		"x-xss-protection", "x-frame-options", "x-content-type-options",
		"content-security-policy", "strict-transport-security",
		"access-control", "x-api-version",
	}

	for _, header := range securityHeaders {
		if strings.Contains(target, header) {
			f.Severity = "medium"
			f.Confidence = 0.7
			f.IsNoise = false
			return
		}
	}

	// Misconfiguration-related headers
	if strings.Contains(target, "server:") || strings.Contains(target, "via:") {
		f.Severity = "low"
		f.Confidence = 0.5
		f.IsNoise = true
		f.NoiseReason = "server fingerprinting header"
		return
	}

	f.Severity = "info"
	f.IsNoise = true
}

// analyzeCookie checks if a cookie is interesting.
func (te *TriageEngine) analyzeCookie(f *Finding) {
	target := strings.ToLower(f.Target)

	// Check for security-relevant cookie attributes
	if strings.Contains(target, "httponly=false") || strings.Contains(target, "secure=false") {
		f.Severity = "high"
		f.Confidence = 0.9
		f.IsNoise = false
		return
	}

	// Session cookies
	sessionPatterns := []string{"sessionid", "session", "sid", "jsessionid", "phpsessid"}
	for _, pattern := range sessionPatterns {
		if strings.Contains(target, pattern) {
			f.Severity = "medium"
			f.Confidence = 0.8
			f.IsNoise = false
			return
		}
	}

	// Tracking/analytics cookies (noise)
	if strings.Contains(target, "utm") || strings.Contains(target, "_ga") || strings.Contains(target, "_fbp") {
		f.IsNoise = true
		f.NoiseReason = "analytics/tracking cookie"
		f.Severity = "info"
		return
	}

	f.Severity = "low"
	f.Confidence = 0.5
	f.IsNoise = false
}

// analyzeVulnerability checks if a vulnerability finding is actionable.
func (te *TriageEngine) analyzeVulnerability(f *Finding) {
	target := strings.ToLower(f.Target)

	// CVE pattern matching
	cveRegex := regexp.MustCompile(`cve-\d{4}-\d{4,5}`)
	if cveRegex.MatchString(target) {
		// Real CVE finding
		if strings.Contains(target, "critical") || strings.Contains(target, "9.") {
			f.Severity = "critical"
			f.Confidence = 0.95
		} else if strings.Contains(target, "high") || strings.Contains(target, "8.") {
			f.Severity = "high"
			f.Confidence = 0.9
		} else {
			f.Severity = "medium"
			f.Confidence = 0.8
		}
		f.IsNoise = false
		return
	}

	// Common false positives
	falsePositives := []string{"wont fix", "informational", "not applicable", "false positive"}
	for _, fp := range falsePositives {
		if strings.Contains(target, fp) {
			f.IsNoise = true
			f.NoiseReason = "known false positive"
			f.Severity = "info"
			return
		}
	}

	// Default to medium
	f.Severity = "medium"
	f.Confidence = 0.6
	f.IsNoise = false
}

// PrioritizeFindings sorts findings by severity and actionability.
func (te *TriageEngine) PrioritizeFindings(findings []*Finding) []*Finding {
	// Analyze all findings first
	for _, f := range findings {
		te.AnalyzeFinding(f)
	}

	// Sort by severity (critical > high > medium > low > info)
	severityRank := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}

	// Simple bubble sort by severity (descending) then confidence
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			rank1 := severityRank[findings[i].Severity]
			rank2 := severityRank[findings[j].Severity]

			if rank2 > rank1 || (rank2 == rank1 && findings[j].Confidence > findings[i].Confidence) {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}

	return findings
}

// FilterNoise returns only actionable findings (excludes noise).
func (te *TriageEngine) FilterNoise(findings []*Finding) []*Finding {
	var actionable []*Finding
	for _, f := range findings {
		te.AnalyzeFinding(f)
		if !f.IsNoise {
			actionable = append(actionable, f)
		}
	}
	return actionable
}

// GetStats returns triage statistics.
func (te *TriageEngine) GetStats(findings []*Finding) map[string]interface{} {
	stats := map[string]interface{}{
		"total":       len(findings),
		"by_severity": make(map[string]int),
		"by_type":     make(map[string]int),
		"noise_count": 0,
	}

	severityMap := stats["by_severity"].(map[string]int)
	typeMap := stats["by_type"].(map[string]int)
	noiseCount := 0

	for _, f := range findings {
		te.AnalyzeFinding(f)
		severityMap[f.Severity]++
		typeMap[f.Type]++
		if f.IsNoise {
			noiseCount++
		}
	}

	stats["noise_count"] = noiseCount
	stats["actionable_count"] = len(findings) - noiseCount
	return stats
}
