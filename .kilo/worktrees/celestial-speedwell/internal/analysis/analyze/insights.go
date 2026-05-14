// Package analyze is responsible for evaluating targets and recon events to
// generate actionable insights, risk scores, and priority levels.
package analyze

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/engine/recon"
)

// Insight encapsulates findings for a specific target host, including a computed
// risk score, priority level, relevant tags, and suggested security tests.
type Insight struct {
	Host           string   `json:"host"`
	Score          int      `json:"score"`
	Priority       string   `json:"priority"`
	Tags           []string `json:"tags"`
	Reasons        []string `json:"reasons"`
	SuggestedTests []string `json:"suggested_tests"`
	EvidenceCount  int      `json:"evidence_count"`
}

// Analyzer defines the interface for components that evaluate recon events
// to enrich an Insight with findings, scores, and tags.
type Analyzer interface {
	Analyze(ev recon.Event, insight *Insight)
}

// DeriveInsights aggregates initial targets and subsequent reconnaissance events
// to calculate risk scores and build Insight records for each discovered host.
func DeriveInsights(targets []string, events []recon.Event) []Insight {
	insights := make(map[string]*Insight)
	hostCache := make(map[string]string)

	getExtractedHost := func(raw string) string {
		if h, ok := hostCache[raw]; ok {
			return h
		}
		h := extractHost(raw)
		hostCache[raw] = h
		return h
	}

	for _, target := range targets {
		host := getExtractedHost(target)
		if host == "" {
			continue
		}
		ensureInsight(host, insights)
	}

	analyzers := []Analyzer{
		&SeverityAnalyzer{},
		&HeuristicAnalyzer{},
		&SensitivePathAnalyzer{},
		&ParameterAnalyzer{},
		&APIAuthAnalyzer{},
		&TechAnalyzer{},
		&SubdomainAnalyzer{},
		&SourceAnalyzer{},
		&FingerprintAnalyzer{},
		&ManualTestingAnalyzer{},
	}

	for _, ev := range events {
		host := getExtractedHost(ev.Target)
		if host == "" {
			continue
		}
		insight := ensureInsight(host, insights)
		insight.EvidenceCount++

		addReason(insight, "source: "+ev.Source)
		for _, a := range analyzers {
			a.Analyze(ev, insight)
		}
	}

	result := make([]Insight, 0, len(insights))
	for _, insight := range insights {
		adjustPriority(insight)
		result = append(result, *insight)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Score == result[j].Score {
			return result[i].Host < result[j].Host
		}
		return result[i].Score > result[j].Score
	})
	return result
}

func ensureInsight(host string, collection map[string]*Insight) *Insight {
	if existing, ok := collection[host]; ok {
		return existing
	}
	insight := &Insight{
		Host:     host,
		Score:    10,
		Priority: "low",
		Tags:     []string{},
		Reasons:  []string{},
		SuggestedTests: []string{
			"Audit common security headers (CSP, HSTS, XFO)",
			"Fuzz for common sensitive files and directories (SecLists)",
			"Test for SQL injection on parameterized endpoints",
		},
	}
	collection[host] = insight
	return insight
}

// --- Specific Analyzers ---

type SeverityAnalyzer struct{}

func (s *SeverityAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	severity := strings.ToLower(strings.TrimSpace(ev.Properties["severity"]))
	switch severity {
	case "critical":
		addTag(insight, "critical-finding")
		addReason(insight, "critical severity finding reported by "+ev.Source)
		insight.Score += 35
	case "high":
		addTag(insight, "high-severity")
		addReason(insight, "high severity finding reported by "+ev.Source)
		insight.Score += 25
	case "medium":
		addTag(insight, "medium-severity")
		addReason(insight, "medium severity finding reported by "+ev.Source)
		insight.Score += 15
	case "low":
		addTag(insight, "low-severity")
		addReason(insight, "low severity finding reported by "+ev.Source)
		insight.Score += 5
	}
}

type SensitivePathAnalyzer struct{}

func (s *SensitivePathAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	targetLower := strings.ToLower(ev.Target)
	sensitivePatterns := map[string]string{
		".env":       "Exposed environment file",
		".git":       "Exposed Git repository",
		".svn":       "Exposed SVN repository",
		"config.php": "Potential configuration file exposure",
		"web.config": "IIS configuration exposure",
		"backup":     "Backup file or directory found",
		"secret":     "Possible secret/credential file",
		"passwd":     "Sensitive system file path observed",
	}

	for pattern, reason := range sensitivePatterns {
		if strings.Contains(targetLower, pattern) {
			addTag(insight, "sensitive")
			addReason(insight, reason)
			addSuggestedTest(insight, "Verify file accessibility and check for credentials/secrets")
			insight.Score += 25
		}
	}
}

type ParameterAnalyzer struct{}

func (p *ParameterAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	if !strings.Contains(ev.Target, "?") {
		return
	}
	targetLower := strings.ToLower(ev.Target)
	addTag(insight, "parameterized")
	addReason(insight, "query string detected")

	// Generic SQL injection coverage for any query-bearing endpoint.
	addTag(insight, "sqli-candidate")
	addSuggestedTest(insight, "Test query parameters for SQL injection and backend query injection")
	insight.Score += 12

	// SSRF / Open Redirect indicators
	if strings.Contains(targetLower, "url=") || strings.Contains(targetLower, "dest=") || strings.Contains(targetLower, "redirect=") || strings.Contains(targetLower, "uri=") {
		addTag(insight, "ssrf-candidate")
		addSuggestedTest(insight, "Test for SSRF and Open Redirect via URL parameters")
		insight.Score += 15
	}

	// File Inclusion / Path Traversal indicators
	if strings.Contains(targetLower, "file=") || strings.Contains(targetLower, "path=") || strings.Contains(targetLower, "include=") {
		addTag(insight, "lfi-candidate")
		addSuggestedTest(insight, "Test for Local/Remote File Inclusion and Path Traversal")
		insight.Score += 15
	}

	addSuggestedTest(insight, "Parameter tampering and XSS testing on query-bearing endpoints")
	insight.Score += 8
}

type APIAuthAnalyzer struct{}

func (a *APIAuthAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	targetLower := strings.ToLower(ev.Target)
	if strings.Contains(targetLower, "/api") || strings.Contains(targetLower, "v1/") || strings.Contains(targetLower, "v2/") {
		addTag(insight, "api")
		addReason(insight, "API surface detected")
		addSuggestedTest(insight, "Fuzz for unauthenticated endpoints and test for IDOR/BOLA")
		insight.Score += 12
	}

	if strings.Contains(targetLower, "/admin") || strings.Contains(targetLower, "/dashboard") || strings.Contains(targetLower, "/login") || strings.Contains(targetLower, "/wp-login") {
		addTag(insight, "auth")
		addReason(insight, "admin/auth endpoint observed")
		addSuggestedTest(insight, "Brute-force protection check and 2FA bypass testing")
		insight.Score += 20
	}
}

type TechAnalyzer struct{}

func (t *TechAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	targetLower := strings.ToLower(ev.Target)

	techRules := []struct {
		Pattern string
		Tag     string
		Reason  string
		Score   int
	}{
		{"wp-content", "wordpress", "WordPress CMS detected", 5},
		{"wp-includes", "wordpress", "WordPress CMS detected", 5},
		{"jenkins", "jenkins", "Jenkins automation server", 15},
		{"grafana", "grafana", "Grafana dashboard", 10},
		{"prometheus", "prometheus", "Prometheus monitoring", 10},
		{"s3.amazonaws.com", "aws-s3", "AWS S3 Bucket", 10},
		{"blob.core.windows.net", "azure-blob", "Azure Blob Storage", 10},
		{"kubernetes", "k8s", "Kubernetes cluster indicator", 10},
		{"cloudflare", "cloudflare-waf", "Cloudflare WAF", 2},
	}

	for _, rule := range techRules {
		if strings.Contains(targetLower, rule.Pattern) {
			addTag(insight, rule.Tag)
			addReason(insight, rule.Reason)
			insight.Score += rule.Score
		}
	}

	if v, ok := ev.Properties["title"]; ok {
		title := strings.ToLower(v)
		if strings.Contains(title, "index of") || strings.Contains(title, "directory listing") {
			addTag(insight, "info-leak")
			addReason(insight, "directory listing enabled")
			addSuggestedTest(insight, "Audit exposed files for sensitive data")
			insight.Score += 20
		}
		if strings.Contains(title, "admin") || strings.Contains(title, "login") || strings.Contains(title, "dashboard") {
			addTag(insight, "auth")
			addReason(insight, "page title signals auth or admin panel")
			addSuggestedTest(insight, "Review access control and check for default credentials")
			insight.Score += 10
		}
	}

	if v, ok := ev.Properties["server"]; ok {
		server := strings.ToLower(v)
		if strings.Contains(server, "nginx") || strings.Contains(server, "apache") || strings.Contains(server, "iis") {
			addTag(insight, "infrastructure")
			addReason(insight, "server software: "+v)
			insight.Score += 2
		}
	}
}

type SubdomainAnalyzer struct{}

func (s *SubdomainAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	targetLower := strings.ToLower(ev.Target)
	highValueSubdomains := []string{"dev", "staging", "test", "vpn", "internal", "corp", "jenkins", "jira", "grafana", "git"}
	for _, sub := range highValueSubdomains {
		if strings.HasPrefix(targetLower, sub+".") || strings.Contains(targetLower, "."+sub+".") {
			addTag(insight, "high-value-scope")
			addReason(insight, "potential non-production or internal infrastructure")
			addSuggestedTest(insight, "Check for unauthorized access and sub-domain takeover")
			addSuggestedTest(insight, "Review for exposed internal documentation or development secrets")
			insight.Score += 20
			break
		}
	}
}

type FingerprintAnalyzer struct{}

func (f *FingerprintAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	// Detect shared infrastructure via favicon hash (commonly used to find dev/admin panels)
	if v, ok := ev.Properties["favicon_hash"]; ok {
		addTag(insight, "fingerprinted")
		addReason(insight, "favicon hash: "+v)
		// Known sensitive hashes (example: spring boot, django admin, etc.)
		insight.Score += 10
	}

	// Detect via TLS/SSL JARM fingerprint
	if v, ok := ev.Properties["jarm"]; ok {
		addTag(insight, "jarm-fingerprint")
		addReason(insight, "JARM hash: "+v)
		// JARM can identify specific software versions even if obscured
		insight.Score += 5
	}

	// Detect via common SSL subject/issuer
	if v, ok := ev.Properties["ssl_subject"]; ok {
		if strings.Contains(strings.ToLower(v), "internal") || strings.Contains(strings.ToLower(v), "localhost") {
			addTag(insight, "internal-ssl")
			addReason(insight, "internal SSL certificate observed")
			addSuggestedTest(insight, "Check for private IP exposure or unauthorized access")
			insight.Score += 15
		}
	}
}

type SourceAnalyzer struct{}

func (s *SourceAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	if ev.Source == "crtsh" || ev.Source == "subfinder" {
		addTag(insight, "discovery")
		insight.Score += 5
	}
}

type ManualTestingAnalyzer struct{}

func (m *ManualTestingAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	targetLower := strings.ToLower(ev.Target)

	// Flag 403/401 for bypass attempts
	if v, ok := ev.Properties["status"]; ok {
		if v == "403" || v == "401" {
			addTag(insight, "manual-bypass")
			addReason(insight, "Access Denied (HTTP "+v+"): Potential for 403 bypass testing")
			addSuggestedTest(insight, "Test for 403 bypass via headers (X-Forwarded-For, X-Custom-IP-Authorization) and path variations")
			insight.Score += 15
		}
	}

	// Flag complex query strings (more than 3 parameters)
	if strings.Contains(ev.Target, "?") {
		parts := strings.Split(ev.Target, "&")
		if len(parts) >= 3 {
			addTag(insight, "complex-params")
			addReason(insight, "Highly parameterized endpoint: High attack surface")
			addSuggestedTest(insight, "Perform deep parameter tampering and logic flaw testing")
			insight.Score += 10
		}
	}

	// Flag CORS misconfigurations
	if v, ok := ev.Properties["cors"]; ok {
		if v == "*" || strings.Contains(v, "null") {
			addTag(insight, "cors-risk")
			addReason(insight, "Permissive CORS policy: "+v)
			addSuggestedTest(insight, "Verify if CORS policy allows unauthorized data extraction via malicious origins")
			insight.Score += 15
		}
	}

	// Flag interesting JS patterns (already handled partially by JSAnalyzer, but we reinforce here)
	if strings.HasSuffix(targetLower, ".js") {
		interestingJS := []string{"config", "init", "auth", "api", "env", "secret"}
		for _, pattern := range interestingJS {
			if strings.Contains(targetLower, pattern) {
				addTag(insight, "interesting-js")
				addReason(insight, "JS file matches interesting pattern: "+pattern)
				addSuggestedTest(insight, "Analyze JS source for hardcoded credentials or hidden endpoints")
				insight.Score += 5
				break
			}
		}
	}
}

func adjustPriority(insight *Insight) {
	if insight.Score >= 30 {
		insight.Priority = "high"
	} else if insight.Score >= 18 {
		insight.Priority = "medium"
	} else {
		insight.Priority = "low"
	}
}

func addTag(insight *Insight, tag string) {
	for _, existing := range insight.Tags {
		if existing == tag {
			return
		}
	}
	insight.Tags = append(insight.Tags, tag)
}

func addReason(insight *Insight, reason string) {
	for _, existing := range insight.Reasons {
		if existing == reason {
			return
		}
	}
	insight.Reasons = append(insight.Reasons, reason)
}

func addSuggestedTest(insight *Insight, test string) {
	for _, existing := range insight.SuggestedTests {
		if existing == test {
			return
		}
	}
	insight.SuggestedTests = append(insight.SuggestedTests, test)
}

func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}

	// Try parsing as URL first if it has a scheme
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil && parsed.Host != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}

	// Fallback for scheme-less like example.com or example.com:8080
	if strings.Contains(raw, ":") {
		host, _, err := net.SplitHostPort(raw)
		if err == nil {
			return strings.ToLower(host)
		}
	}

	parsed, err := url.Parse("https://" + raw)
	if err == nil && parsed.Host != "" {
		return strings.ToLower(parsed.Hostname())
	}

	return strings.ToLower(raw)
}
