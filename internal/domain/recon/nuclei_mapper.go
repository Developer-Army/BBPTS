// Package recon provides reconnaissance domain logic
package recon

import (
	"strings"
)

// NucleiTagMapping maps BBPTS rule-engine tags and insight tags to Nuclei
// template tags. This enables automatic, targeted vulnerability scanning
// based on what the recon pipeline discovered.
var NucleiTagMapping = map[string][]string{
	// Rule engine tags → nuclei template tags
	"exposed-secrets":   {"exposure", "token", "config"},
	"source-disclosure": {"git", "exposure", "config"},
	"backup-file":       {"backup", "exposure"},
	"graphql":           {"graphql", "introspection"},
	"admin-panel":       {"panel", "login", "default-login"},
	"ci-exposure":       {"jenkins", "ci", "devops"},
	"api-docs":          {"swagger", "openapi"},
	"db-exposure":       {"phpmyadmin", "mysql", "database"},
	"cloud-storage":     {"s3", "aws", "bucket"},
	"dev-environment":   {"debug", "exposure", "config"},

	// Insight tags → nuclei template tags
	"api":            {"api", "graphql", "swagger"},
	"auth":           {"login", "default-login", "brute-force", "auth-bypass"},
	"parameterized":  {"sqli", "xss", "ssti", "lfi", "rfi", "ssrf"},
	"subdomain":      {"subdomain-takeover", "cname"},
	"infrastructure": {"tech-detect", "waf-detect"},
}

// NucleiSeverityForPriority maps BBPTS priority levels to Nuclei severity
// filters. Higher-priority findings get deeper scanning.
var NucleiSeverityForPriority = map[string][]string{
	"critical": {"info", "low", "medium", "high", "critical"},
	"high":     {"low", "medium", "high", "critical"},
	"medium":   {"medium", "high", "critical"},
	"low":      {"high", "critical"},
}

// ResolveTags takes a list of BBPTS tags (from rules or insights) and returns
// the corresponding Nuclei template tags for targeted scanning.
func ResolveTags(bbptsTags []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, tag := range bbptsTags {
		nucleiTags, ok := NucleiTagMapping[strings.ToLower(tag)]
		if !ok {
			continue
		}
		for _, nt := range nucleiTags {
			if _, exists := seen[nt]; exists {
				continue
			}
			seen[nt] = struct{}{}
			result = append(result, nt)
		}
	}

	return result
}

// ResolveSeverity returns the Nuclei severity filter for a given BBPTS priority.
func ResolveSeverity(priority string) []string {
	if sevs, ok := NucleiSeverityForPriority[strings.ToLower(priority)]; ok {
		return sevs
	}
	return []string{"high", "critical"}
}
