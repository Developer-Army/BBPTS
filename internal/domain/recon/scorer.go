package recon

import (
	"fmt"
	"strings"
)

// IntelligenceScore contains the heuristic evaluation of a node.
type IntelligenceScore struct {
	Score         int
	Severity      string
	Justification []string
}

// Scorer evaluates nodes and assigns intelligence priority scores.
type Scorer struct{}

func NewScorer() *Scorer {
	return &Scorer{}
}

// ScoreEndpoint evaluates the heuristic probability of a URL being a high-value bug bounty target.
func (s *Scorer) ScoreEndpoint(url string, isAuthRequired bool, responseBody string) *IntelligenceScore {
	result := &IntelligenceScore{
		Score:         0,
		Justification: make([]string, 0),
	}

	lowerURL := strings.ToLower(url)

	// Admin / Debug Interfaces
	if strings.Contains(lowerURL, "admin") || strings.Contains(lowerURL, "debug") || strings.Contains(lowerURL, "staging") {
		result.Score += 30
		result.Justification = append(result.Justification, "Contains admin/debug/staging keywords in URL")
	}

	// API / GraphQL indicators
	if strings.Contains(lowerURL, "graphql") {
		result.Score += 40
		result.Justification = append(result.Justification, "GraphQL endpoint detected (high risk of IDOR/Information Disclosure)")
	}
	if strings.Contains(lowerURL, "/api/v1") || strings.Contains(lowerURL, "/api/v2") {
		result.Score += 15
		result.Justification = append(result.Justification, "Versioned API Endpoint")
	}

	// Authentication context
	if isAuthRequired {
		result.Score += 20
		result.Justification = append(result.Justification, "Authenticated endpoint (often undertested)")
	}

	// Basic entropy/complexity heuristics on response
	if len(responseBody) > 10000 && strings.Contains(responseBody, "{") {
		result.Score += 10
		result.Justification = append(result.Justification, "Large JSON payload detected (data leakage potential)")
	}

	// Sensitive file extensions — high value for direct access bugs
	sensitiveExts := []string{".bak", ".sql", ".env", ".log", ".conf", ".config",
		".old", ".orig", ".backup", ".dump", ".git", ".svn", ".htpasswd"}
	for _, ext := range sensitiveExts {
		if strings.HasSuffix(lowerURL, ext) || strings.Contains(lowerURL, ext+"?") {
			result.Score += 50
			result.Justification = append(result.Justification, fmt.Sprintf("Sensitive file extension detected (%s)", ext))
			break
		}
	}

	// High-value path patterns
	highValuePaths := map[string]int{
		"/internal/": 35, "/private/": 35, "/secret/": 35,
		"/upload":    30, "/file":     25, "/download":  25,
		"/config":    30, "/settings": 20, "/management": 30,
		"/swagger":   40, "/openapi":  40, "/api-docs":  40,
		"/phpinfo":   45, "/.git/":    55, "/.env":      55,
		"/actuator":  40, "/metrics":  25, "/health":    15,
		"/v3/api":    20, "/rest/":    15, "/_api/":     20,
		"/rpc":       30, "/xmlrpc":   35, "/soap":      35,
	}
	for path, pts := range highValuePaths {
		if strings.Contains(lowerURL, path) {
			result.Score += pts
			result.Justification = append(result.Justification, fmt.Sprintf("High-value path pattern (%s)", path))
			break
		}
	}

	// Query parameter count heuristic — more params = more attack surface
	paramCount := strings.Count(url, "&") + strings.Count(url, "?")
	if paramCount > 0 {
		score := paramCount * 5
		if score > 20 {
			score = 20
		}
		result.Score += score
		result.Justification = append(result.Justification, fmt.Sprintf("Parameterized URL (%d params)", paramCount))
	}

	// Sensitive parameter names
	sensitiveParams := []string{"token", "key", "secret", "password", "passwd",
		"auth", "api_key", "access_token", "redirect", "callback", "next",
		"url", "file", "path", "id", "user", "username", "email"}
	for _, param := range sensitiveParams {
		if strings.Contains(lowerURL, param+"=") || strings.Contains(lowerURL, param+"[") {
			result.Score += 15
			result.Justification = append(result.Justification, fmt.Sprintf("Sensitive parameter name (%s)", param))
			break
		}
	}

	// Calculate severity tier
	if result.Score >= 80 {
		result.Severity = "CRITICAL"
	} else if result.Score >= 50 {
		result.Severity = "HIGH"
	} else if result.Score >= 25 {
		result.Severity = "MEDIUM"
	} else {
		result.Severity = "LOW"
	}

	return result
}
