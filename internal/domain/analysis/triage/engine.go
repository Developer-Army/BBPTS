package triage

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
)

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

type TriageEngine struct {
	noisePatternsSubdomain []string
	noisePatternsPort      []string
	noisePatternsEndpoint  []string
	noisePatternsHeader    []string

	commonCDNs []string
	commonSaaS []string
}

func NewTriageEngine() *TriageEngine {
	te := &TriageEngine{

		noisePatternsSubdomain: []string{

			"*.example", "*.test", "*.local", "*.internal",

			"test", "tmp", "temp",
			"docker", "k8s", "lab", "sandbox",

			"static", "media", "assets", "images",
		},

		noisePatternsPort: []string{

			":22",
			":25",
			":53",
			":631",
			":5432",
			":6379",
			":27017",
		},

		noisePatternsEndpoint: []string{

			"pixel", "beacon", "analytics", "tracker",

			"/ads/", "/banner", "/dfa/",

			"/favicon.ico", "/robots.txt", "/sitemap.xml",
			"/health", "/status", "/ping", "/.well-known",

			"/cdn/", "/static/", "/assets/", "/public/",
		},

		noisePatternsHeader: []string{
			"x-aspnet-version",
			"server: nginx",
			"x-powered-by",
		},

		commonCDNs: []string{
			"cdn", "cloudflare", "akamai", "fastly", "cloudfront",
			"edgecast", "limelight", "highwinds",
		},

		commonSaaS: []string{
			"salesforce", "zendesk", "shopify", "github",
			"twitter", "facebook", "google", "amazon",
		},
	}

	return te
}

func (te *TriageEngine) AnalyzeFinding(f *Finding) {

	if f.Confidence == 0 {
		f.Confidence = 0.5
	}

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

func (te *TriageEngine) analyzeSubdomain(f *Finding) {
	target := strings.ToLower(f.Target)

	for _, pattern := range te.noisePatternsSubdomain {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("matches noise pattern: %s", pattern)
			f.Severity = "info"
			return
		}
	}

	for _, cdn := range te.commonCDNs {
		if strings.Contains(target, cdn) {
			f.Severity = "low"
			f.Confidence = 0.4
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("CDN: %s", cdn)
			return
		}
	}

	f.Severity = "medium"
	f.Confidence = 0.8
	f.IsNoise = false
}

func (te *TriageEngine) analyzePort(f *Finding) {
	target := strings.ToLower(f.Target)

	for _, pattern := range te.noisePatternsPort {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("infrastructure port: %s", pattern)
			f.Severity = "low"
			f.Confidence = 0.5
			return
		}
	}

	commonWebPorts := []string{":80", ":443", ":8080", ":8443", ":3000", ":5000", ":9000"}
	for _, port := range commonWebPorts {
		if strings.Contains(target, port) {
			f.Severity = "high"
			f.Confidence = 0.9
			f.IsNoise = false
			return
		}
	}

	f.Severity = "medium"
	f.Confidence = 0.7
	f.IsNoise = false
}

func (te *TriageEngine) analyzeEndpoint(f *Finding) {
	target := strings.ToLower(f.Target)

	for _, pattern := range te.noisePatternsEndpoint {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("matches noise pattern: %s", pattern)
			f.Severity = "info"
			return
		}
	}

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

	if strings.Contains(target, "?") || strings.Contains(target, "&") {
		f.Severity = "medium"
		f.Confidence = 0.7
		f.IsNoise = false
		return
	}

	f.Severity = "low"
	f.Confidence = 0.5
	f.IsNoise = false
}

func (te *TriageEngine) analyzeHeader(f *Finding) {
	target := strings.ToLower(f.Target)

	for _, pattern := range te.noisePatternsHeader {
		if strings.Contains(target, pattern) {
			f.IsNoise = true
			f.NoiseReason = fmt.Sprintf("common header: %s", pattern)
			f.Severity = "info"
			return
		}
	}

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

func (te *TriageEngine) analyzeCookie(f *Finding) {
	target := strings.ToLower(f.Target)

	if strings.Contains(target, "httponly=false") || strings.Contains(target, "secure=false") {
		f.Severity = "high"
		f.Confidence = 0.9
		f.IsNoise = false
		return
	}

	sessionPatterns := []string{"sessionid", "session", "sid", "jsessionid", "phpsessid"}
	for _, pattern := range sessionPatterns {
		if strings.Contains(target, pattern) {
			f.Severity = "medium"
			f.Confidence = 0.8
			f.IsNoise = false
			return
		}
	}

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

func (te *TriageEngine) analyzeVulnerability(f *Finding) {
	target := strings.ToLower(f.Target)

	cveRegex := regexp.MustCompile(`cve-\d{4}-\d{4,5}`)
	if cveRegex.MatchString(target) {

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

	falsePositives := []string{"wont fix", "informational", "not applicable", "false positive"}
	for _, fp := range falsePositives {
		if strings.Contains(target, fp) {
			f.IsNoise = true
			f.NoiseReason = "known false positive"
			f.Severity = "info"
			return
		}
	}

	f.Severity = "medium"
	f.Confidence = 0.6
	f.IsNoise = false
}

func (te *TriageEngine) PrioritizeFindings(findings []*Finding) []*Finding {

	for _, f := range findings {
		te.AnalyzeFinding(f)
	}

	severityRank := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}

	sort.Slice(findings, func(i, j int) bool {
		rank1 := severityRank[findings[i].Severity]
		rank2 := severityRank[findings[j].Severity]
		if rank1 != rank2 {
			return rank1 > rank2
		}
		return findings[i].Confidence > findings[j].Confidence
	})

	return findings
}

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
