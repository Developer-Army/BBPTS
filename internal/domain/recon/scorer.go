package recon

import (
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

	// Calculate severity tier
	if result.Score >= 60 {
		result.Severity = "CRITICAL"
	} else if result.Score >= 40 {
		result.Severity = "HIGH"
	} else if result.Score >= 20 {
		result.Severity = "MEDIUM"
	} else {
		result.Severity = "LOW"
	}

	return result
}
