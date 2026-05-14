// Package analyze is responsible for evaluating targets and recon events to
// generate actionable insights, risk scores, and priority levels.
package analyze

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
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
	// Confidence is 0–100; higher values indicate stronger corroboration and evidence depth.
	Confidence int `json:"confidence"`
	// Sources lists distinct recon tools that contributed evidence for this host.
	Sources []string `json:"sources,omitempty"`
	// DedupeKey is the normalized host key used for insight grouping (same as Host when derived from DNS names).
	DedupeKey string `json:"dedupe_key,omitempty"`
	// Evidence holds a sample of the raw data (URLs, paths, etc.) that triggered the insights.
	Evidence []string `json:"evidence,omitempty"`
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
	sourcesPerHost := make(map[string]map[string]struct{})
	evidencePerHost := make(map[string]map[string]struct{})

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
	// Add cluster analyzer for post-processing
	clusterAnalyzer := NewClusterAnalyzer()
	analyzers = append(analyzers, clusterAnalyzer)

	// All events collected for cluster fitting
	var allCollectedEvents []recon.Event

	for _, ev := range events {
		host := getExtractedHost(ev.Target)
		if host == "" {
			continue
		}
		insight := ensureInsight(host, insights)
		insight.EvidenceCount++

		// Collect unique evidence samples (max 25)
		if ev.Target != "" && len(insight.Evidence) < 25 {
			if evidencePerHost[host] == nil {
				evidencePerHost[host] = make(map[string]struct{})
			}
			if _, found := evidencePerHost[host][ev.Target]; !found {
				evidencePerHost[host][ev.Target] = struct{}{}
				insight.Evidence = append(insight.Evidence, ev.Target)
			}
		}

		for _, src := range collectEventSources(ev) {
			if sourcesPerHost[host] == nil {
				sourcesPerHost[host] = make(map[string]struct{})
			}
			sourcesPerHost[host][src] = struct{}{}
		}

		addReason(insight, "source: "+ev.Source)
		for _, a := range analyzers {
			a.Analyze(ev, insight)
		}

		// Collect all events for cluster analysis
		allCollectedEvents = append(allCollectedEvents, ev)
	}

	result := make([]Insight, 0, len(insights))
	for _, insight := range insights {
		consolidateParamReasons(insight)
		enrichSuggestedTests(insight)
		insight.DedupeKey = strings.ToLower(strings.TrimSpace(insight.Host))
		insight.Sources = sortedKeys(sourcesPerHost[insight.Host])
		insight.Confidence = computeInsightConfidence(insight)
		result = append(result, *insight)
	}

	// Cluster-based scoring boost (must happen after result built, before normalization)
	clusterAnalyzer.PostProcess(result, events)

	// Normalize all raw scores to 0–100 using log-scale so that
	// scores reflect suspicion level rather than data volume.
	normalizeScores(result)

	// Priority must be set after normalization.
	for i := range result {
		adjustPriority(&result[i])
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Score == result[j].Score {
			return result[i].Host < result[j].Host
		}
		return result[i].Score > result[j].Score
	})
	return result
}

func collectEventSources(ev recon.Event) []string {
	seen := make(map[string]struct{})
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	add(ev.Source)
	if raw, ok := ev.Properties["bbpts_sources"]; ok {
		for _, part := range strings.Split(raw, ",") {
			add(part)
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func computeInsightConfidence(insight *Insight) int {
	nSources := len(insight.Sources)
	if nSources == 0 && insight.EvidenceCount > 0 {
		nSources = 1
	}
	base := 22
	corroboration := min(48, nSources*14)
	evidenceDepth := min(30, insight.EvidenceCount*6)
	scoreBoost := min(15, insight.Score/6)
	conf := base + corroboration + evidenceDepth + scoreBoost
	if conf > 100 {
		return 100
	}
	return conf
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
			"Audit security headers (CSP, HSTS, XFO)",
			"Test for SQL injection on parameters",
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
	addReason(insight, "Active parameters detected (increases attack surface)")

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

	// Parameter-aware test suggestions for higher manual testing depth.
	u, err := url.Parse(ev.Target)
	if err == nil {
		for key := range u.Query() {
			addParamSpecificTests(insight, strings.ToLower(strings.TrimSpace(key)))
		}
	}
}

type APIAuthAnalyzer struct{}

func (a *APIAuthAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	targetLower := strings.ToLower(ev.Target)
	if strings.Contains(targetLower, "/api") || strings.Contains(targetLower, "v1/") || strings.Contains(targetLower, "v2/") {
		addTag(insight, "api")
		addReason(insight, "Application API endpoints discovered")
		addSuggestedTest(insight, "Fuzz for unauthenticated endpoints and test for IDOR/BOLA")
		insight.Score += 12
	}

	if strings.Contains(targetLower, "/admin") || strings.Contains(targetLower, "/dashboard") || strings.Contains(targetLower, "/login") || strings.Contains(targetLower, "/wp-login") {
		addTag(insight, "auth")
		addReason(insight, "Administrative or Authentication interface identified")
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
		// CMS & High-Value Targets
		{"wp-content", "wordpress", "WordPress CMS detected", 8},
		{"wp-includes", "wordpress", "WordPress CMS detected", 8},
		{"/admin", "admin-panel", "Administrative interface found", 15},
		{"/dashboard", "dashboard", "Admin/user dashboard detected", 12},

		// DevOps & Monitoring (High-Value Targets)
		{"jenkins", "devops", "Jenkins automation server", 20},
		{"grafana", "monitoring", "Grafana dashboard (monitoring)", 15},
		{"prometheus", "monitoring", "Prometheus monitoring stack", 12},
		{"kibana", "elk-stack", "Kibana ELK dashboard", 15},
		{"splunk", "siem", "Splunk SIEM platform", 18},
		{"datadog", "monitoring", "Datadog monitoring/APM", 10},

		// Cloud Services
		{"s3.amazonaws.com", "aws-s3", "AWS S3 Bucket", 12},
		{"blob.core.windows.net", "azure-blob", "Azure Blob Storage", 12},
		{"storage.googleapis.com", "gcs", "Google Cloud Storage", 10},
		{"cloudfront", "aws-cdn", "AWS CloudFront CDN", 8},

		// Container & Orchestration
		{"kubernetes", "k8s", "Kubernetes cluster indicator", 18},
		{"docker", "containerization", "Docker container/registry", 10},
		{"/api/v1", "api", "Kubernetes API endpoint pattern", 15},

		// Message Queues & Databases (Exposed = Critical)
		{"rabbitmq", "message-queue", "RabbitMQ message broker", 15},
		{"kafka", "streaming", "Apache Kafka streaming platform", 15},
		{"elasticsearch", "database", "Elasticsearch exposed", 20},
		{"mongodb", "nosql", "MongoDB database", 18},
		{"redis", "cache", "Redis cache server", 15},
		{"postgres", "database", "PostgreSQL database", 18},
		{"mysql", "database", "MySQL database", 15},

		// VCS & Secrets
		{"gitlab", "git-repo", "GitLab instance", 15},
		{"gitea", "git-repo", "Gitea git service", 12},
		{".git/config", "git-leak", "Exposed Git repository", 25},
		{".env", "secrets", "Environment/config file exposed", 25},

		// Frameworks & Web Servers
		{"/phpmyadmin", "phpmyadmin", "phpMyAdmin exposed", 20},
		{"tomcat", "java-server", "Apache Tomcat", 10},
		{"jboss", "java-server", "JBoss application server", 15},
		{"asp.net", "dotnet", "ASP.NET application", 5},
	}

	for _, rule := range techRules {
		if strings.Contains(targetLower, rule.Pattern) {
			if !tagExists(insight, rule.Tag) {
				addTag(insight, rule.Tag)
				insight.Score += rule.Score
				addReason(insight, rule.Reason)
				break
			}
		}
	}

	if v, ok := ev.Properties["title"]; ok {
		title := strings.ToLower(v)
		if strings.Contains(title, "index of") || strings.Contains(title, "directory listing") {
			if !tagExists(insight, "info-leak") {
				addTag(insight, "info-leak")
				addReason(insight, "Directory listing is active (Information Leak)")
				addSuggestedTest(insight, "Audit exposed files for sensitive data")
				insight.Score += 20
			}
		}
		if strings.Contains(title, "admin") || strings.Contains(title, "login") || strings.Contains(title, "dashboard") {
			if !tagExists(insight, "auth") {
				addTag(insight, "auth")
				addReason(insight, "Page title signals an administrative login panel")
				addSuggestedTest(insight, "Review access control and check for default credentials")
				insight.Score += 10
			}
		}
	}

	if v, ok := ev.Properties["server"]; ok {
		server := strings.ToLower(v)
		if strings.Contains(server, "nginx") || strings.Contains(server, "apache") || strings.Contains(server, "iis") {
			if !tagExists(insight, "infrastructure") {
				addTag(insight, "infrastructure")
				addReason(insight, "Infrastructure detected: "+v)
				insight.Score += 2
			}
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
			addReason(insight, "Likely internal or non-production environment (High Value)")
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
	source := strings.ToLower(strings.TrimSpace(ev.Source))
	switch source {
	case "crtsh", "subfinder", "assetfinder", "amass", "puredns", "chaos", "gau", "hakrawler", "katana", "gobuster", "feroxbuster", "browser", "httpx":
		if !tagExists(insight, "discovery") {
			addTag(insight, "discovery")
			insight.Score += 5
		}
		addReason(insight, fmt.Sprintf("Discovered through %s", source))
	case "nuclei", "dalfox", "secrets":
		if !tagExists(insight, "vulnerability") {
			addTag(insight, "vulnerability")
			insight.Score += 20
		}
		addReason(insight, fmt.Sprintf("Vulnerability scan matched by %s", source))
	default:
		if source != "" {
			addReason(insight, fmt.Sprintf("Source: %s", source))
		}
	}
}

type ManualTestingAnalyzer struct{}

func (m *ManualTestingAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	targetLower := strings.ToLower(ev.Target)

	// Flag 403/401 for bypass attempts
	if v, ok := ev.Properties["status"]; ok {
		if v == "403" || v == "401" {
			addTag(insight, "manual-bypass")
			addReason(insight, "Access Restricted (HTTP "+v+"): Recommended for bypass attempts")
			addSuggestedTest(insight, "Test for 403 bypass via headers (X-Forwarded-For, X-Custom-IP-Authorization) and path variations")
			insight.Score += 15
		}
	}

	// Flag complex query strings (more than 3 parameters)
	if strings.Contains(ev.Target, "?") {
		parts := strings.Split(ev.Target, "&")
		if len(parts) >= 3 {
			addTag(insight, "complex-params")
			addReason(insight, "Complex endpoint with multiple parameters (High attack surface)")
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

// adjustPriority assigns a priority label using the normalized score (0-100)
// blended with the independently-computed confidence value.
func adjustPriority(insight *Insight) {
	// Blend: 70% normalized score + 30% confidence.
	blended := float64(insight.Score)*0.7 + float64(insight.Confidence)*0.3
	if blended >= 60 {
		insight.Priority = "high"
	} else if blended >= 35 {
		insight.Priority = "medium"
	} else {
		insight.Priority = "low"
	}
}

func tagExists(insight *Insight, tag string) bool {
	for _, existing := range insight.Tags {
		if existing == tag {
			return true
		}
	}
	return false
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

func enrichSuggestedTests(insight *Insight) {
	tagTests := map[string][]string{
		"auth": {
			"Test for 2FA bypass and brute-force protection",
			"Check password reset token predictability",
		},
		"api": {
			"Test BOLA/IDOR on object IDs",
			"Check mass assignment in JSON bodies",
		},
		"sqli-candidate": {
			"Run boolean/time/error-based SQLi probes",
			"Check UNION-based data exposure",
		},
		"ssrf-candidate": {
			"Test SSRF to internal metadata (169.254.169.254)",
			"Bypass URL allowlists via DNS rebinding",
		},
		"lfi-candidate": {
			"Test traversal variants (../, ..%2f)",
			"Try wrapper/protocol vectors (php://filter)",
		},
		"cors-risk": {
			"Validate credentialed cross-origin requests",
		},
		"manual-bypass": {
			"Attempt path normalization bypasses",
		},
		"interesting-js": {
			"Extract hidden API routes/tokens from JS",
		},
		"high-value-scope": {
			"Verify hostname/subdomain takeover risks",
		},
		"sensitive": {
			"Check for leaked keys/secrets in exposed files",
		},
	}

	for _, tag := range insight.Tags {
		tests, ok := tagTests[tag]
		if !ok {
			continue
		}
		for _, test := range tests {
			addSuggestedTest(insight, test)
		}
	}
}

func addParamSpecificTests(insight *Insight, key string) {
	switch key {
	case "id", "ids", "user", "userid", "account", "accountid", "order", "orderid", "invoice", "invoiceid":
		addSuggestedTest(insight, "Test ID-based parameter for IDOR/BOLA by sequential and cross-account object access")
	case "redirect", "redirect_url", "url", "next", "return", "returnto", "dest", "destination":
		addSuggestedTest(insight, "Validate open redirect protections (allowlist bypass, scheme-relative, encoded payloads)")
	case "file", "path", "template", "download", "folder", "include":
		addSuggestedTest(insight, "Probe file/path parameter for LFI and traversal using canonicalization bypass payloads")
	case "token", "code", "state", "otp":
		addSuggestedTest(insight, "Assess token/OTP parameter strength, replay protection, and brute-force resistance")
	case "query", "q", "search", "filter", "sort":
		addSuggestedTest(insight, "Fuzz search/filter/sort params for injection and backend query manipulation")
	case "callback", "cb", "jsonp":
		addSuggestedTest(insight, "Check callback/JSONP parameter for reflected JS execution and data leakage")
	}
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

// normalizeScores maps raw additive scores into the 0–100 range using
// log-scaling so that a target with 50,000 URLs doesn't blindly dominate
// one with genuine findings but fewer data points.
func normalizeScores(insights []Insight) {
	if len(insights) == 0 {
		return
	}

	maxRaw := 0
	for _, in := range insights {
		if in.Score > maxRaw {
			maxRaw = in.Score
		}
	}
	if maxRaw <= 0 {
		return
	}

	logMax := math.Log1p(float64(maxRaw))
	for i := range insights {
		if insights[i].Score <= 0 {
			insights[i].Score = 0
			continue
		}
		normalized := (math.Log1p(float64(insights[i].Score)) / logMax) * 100
		insights[i].Score = int(math.Round(normalized))
		if insights[i].Score > 100 {
			insights[i].Score = 100
		}
	}
}

// consolidateParamReasons merges individual "High-risk parameter detected"
// reasons into a single summary entry to prevent per-parameter score inflation.
func consolidateParamReasons(insight *Insight) {
	const prefix = "High-risk parameter detected (likely database input): "
	var paramNames []string
	cleaned := make([]string, 0, len(insight.Reasons))

	for _, r := range insight.Reasons {
		if strings.HasPrefix(r, prefix) {
			paramNames = append(paramNames, strings.TrimPrefix(r, prefix))
		} else {
			cleaned = append(cleaned, r)
		}
	}

	if len(paramNames) > 0 {
		summary := fmt.Sprintf("High-risk parameters detected (likely database inputs): %s", strings.Join(paramNames, ", "))
		cleaned = append(cleaned, summary)
	}
	insight.Reasons = cleaned
}
