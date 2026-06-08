package recon

import (
	"fmt"
	"strings"
)

// RiskVector represents a multi-factor risk model.
type RiskVector struct {
	Exposure       int `json:"exposure"`
	Attackability  int `json:"attackability"`
	BusinessImpact int `json:"business_impact"`
	Confidence     int `json:"confidence"`
	Freshness      int `json:"freshness"`
	PathRisk       int `json:"path_risk"`
}

// IntelligenceScore contains the heuristic evaluation of a node.
type IntelligenceScore struct {
	Score         int
	Severity      string
	Justification []string

	// Multi-Factor Risk Vector components (0-100 scale)
	ExposureScore       int
	AttackabilityScore  int
	BusinessImpactScore int
	ConfidenceScore     int
	FreshnessScore      int
	PathScore           int

	Risk RiskVector
}

// Scorer evaluates nodes and assigns intelligence priority scores.
type Scorer struct {
	SourceConfidence float64 // 0.0 to 1.0 (default 1.0)
	Reproducibility  float64 // 0.0 to 1.0 (default 1.0)
	AssetEnvironment string  // "prod", "staging", "dev" (default "prod")
	BlastRadius      float64 // 0.0 to 1.0 (default 1.0)
}

func NewScorer() *Scorer {
	return &Scorer{
		SourceConfidence: 1.0,
		Reproducibility:  1.0,
		AssetEnvironment: "prod",
		BlastRadius:      1.0,
	}
}

// ScoreEndpoint evaluates the heuristic probability of a URL being a high-value bug bounty target.
func (s *Scorer) ScoreEndpoint(url string, isAuthRequired bool, responseBody string) *IntelligenceScore {
	return s.ScoreEndpointAdvanced(url, isAuthRequired, responseBody, false, false, 0, 0)
}

// ScoreEndpointAdvanced evaluates the risk of a target incorporating evidence, exposure, business impact, ownership, attack paths, exploitability, and confidence.
func (s *Scorer) ScoreEndpointAdvanced(url string, isAuthRequired bool, responseBody string, hasOwner bool, hasAttackPath bool, evidenceCount int, exploitability int) *IntelligenceScore {
	result := &IntelligenceScore{
		Score:         0,
		Justification: make([]string, 0),
	}

	lowerURL := strings.ToLower(url)
	lowerBody := strings.ToLower(responseBody)

	// Determine Hostname exposure context
	host := url
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	lowerHost := strings.ToLower(host)

	// 1. Business Impact Score (0-100)
	assetClass := "Default"
	classImpact := 20
	if strings.Contains(lowerURL, "jenkins") || strings.Contains(lowerURL, "gitlab") || strings.Contains(lowerURL, "github") || strings.Contains(lowerURL, "git-") || strings.Contains(lowerURL, "/git") {
		assetClass = "CI/CD System"
		classImpact = 100
	} else if strings.Contains(lowerURL, ".env") || strings.Contains(lowerURL, ".git") || strings.Contains(lowerURL, ".bak") || strings.Contains(lowerURL, ".sql") {
		assetClass = "Sensitive File Leak"
		classImpact = 100
	} else if strings.Contains(lowerURL, "grafana") || strings.Contains(lowerURL, "prometheus") || strings.Contains(lowerURL, "kibana") || strings.Contains(lowerURL, "splunk") || strings.Contains(lowerURL, "datadog") || strings.Contains(lowerURL, "/metrics") || strings.Contains(lowerURL, "/actuator") || strings.Contains(lowerURL, "/health") {
		assetClass = "Monitoring System"
		classImpact = 80
	} else if strings.Contains(lowerURL, "/login") || strings.Contains(lowerURL, "/auth") || strings.Contains(lowerURL, "oauth") || strings.Contains(lowerURL, "keycloak") || strings.Contains(lowerURL, "okta") || strings.Contains(lowerURL, "saml") || strings.Contains(lowerURL, "/signup") || strings.Contains(lowerURL, "signin") {
		assetClass = "Identity/Auth System"
		classImpact = 95
	} else if strings.Contains(lowerURL, "checkout") || strings.Contains(lowerURL, "pay") || strings.Contains(lowerURL, "stripe") || strings.Contains(lowerURL, "billing") || strings.Contains(lowerURL, "invoice") || strings.Contains(lowerURL, "payment") {
		assetClass = "Payment System"
		classImpact = 100
	} else if strings.Contains(lowerURL, "/admin") || strings.Contains(lowerURL, "/dashboard") || strings.Contains(lowerURL, "/management") || strings.Contains(lowerURL, "/settings") || strings.Contains(lowerURL, "/config") {
		assetClass = "Admin Portal"
		classImpact = 90
		if strings.Contains(lowerURL, "token=") {
			classImpact = 100
		}
	} else if strings.Contains(lowerURL, "/api/v1") || strings.Contains(lowerURL, "/api/v2") || strings.Contains(lowerURL, "/api/") || strings.Contains(lowerURL, "graphql") || strings.Contains(lowerURL, "/rpc") || strings.Contains(lowerURL, "/xmlrpc") || strings.Contains(lowerURL, "/rest/") {
		assetClass = "API Endpoint"
		classImpact = 60
	} else if strings.Contains(lowerURL, "internal") || strings.Contains(lowerURL, "local") || strings.Contains(lowerURL, "localhost") || strings.Contains(lowerURL, "private") || strings.Contains(lowerURL, "corp") {
		assetClass = "Internal Service"
		classImpact = 40
	} else if strings.Contains(lowerURL, "s3.amazonaws.com") || strings.Contains(lowerURL, "blob.core.windows.net") || strings.Contains(lowerURL, "storage.googleapis.com") || strings.Contains(lowerURL, "cloudfront") || strings.Contains(lowerURL, "kubernetes") || strings.Contains(lowerURL, "k8s") || strings.Contains(lowerURL, "docker") {
		assetClass = "Cloud Control Plane"
		classImpact = 85
	}
	result.Justification = append(result.Justification, fmt.Sprintf("Asset class identified: %s", assetClass))
	classImpact = int(float64(classImpact) * s.BlastRadius)
	result.BusinessImpactScore = classImpact

	// 2. Exposure Score (0-100)
	exposure := 100
	if strings.Contains(lowerHost, "internal") || strings.Contains(lowerHost, "local") || strings.Contains(lowerHost, "localhost") || strings.Contains(lowerHost, "private") || strings.Contains(lowerHost, "dev") || strings.Contains(lowerHost, "test") || strings.Contains(lowerHost, "staging") {
		exposure = 40
		result.Justification = append(result.Justification, "Exposure reduced due to internal/non-prod subdomain")
	} else {
		result.Justification = append(result.Justification, "Exposure score high (public facing domain)")
	}
	result.ExposureScore = exposure

	// 3. Exploitability Score (0-100)
	hasSensitiveExt := false
	hasSensitiveParam := false
	if exploitability <= 0 {
		exploitability = 30
		if isAuthRequired {
			exploitability += 30
			result.Justification = append(result.Justification, "Authenticated surface (increases exploitability score)")
		}
		if strings.Contains(lowerURL, "/upload") || strings.Contains(lowerURL, "/file") || strings.Contains(lowerURL, "/download") {
			exploitability += 20
			result.Justification = append(result.Justification, "Contains upload/download endpoint")
		}
		if strings.Contains(lowerURL, "graphql") || strings.Contains(lowerURL, "swagger") || strings.Contains(lowerURL, "openapi") || strings.Contains(lowerURL, "api-docs") {
			exploitability += 20
			result.Justification = append(result.Justification, "API documentation / Query interface present")
		}
		sensitiveExts := []string{".bak", ".sql", ".env", ".log", ".conf", ".config", ".old", ".orig", ".backup", ".dump", ".git", ".svn"}
		for _, ext := range sensitiveExts {
			if strings.Contains(lowerURL, ext) {
				exploitability += 40
				hasSensitiveExt = true
				result.Justification = append(result.Justification, fmt.Sprintf("Sensitive file extension: %s", ext))
				break
			}
		}
		if strings.Contains(lowerURL, ".env") || strings.Contains(lowerURL, ".git") {
			exploitability += 30
		}
		sensitiveParams := []string{"token", "key", "secret", "password", "passwd", "auth", "api_key", "access_token"}
		for _, param := range sensitiveParams {
			if strings.Contains(lowerURL, param+"=") || strings.Contains(lowerURL, param+"[") {
				exploitability += 45
				hasSensitiveParam = true
				result.Justification = append(result.Justification, fmt.Sprintf("Sensitive parameter: %s", param))
				break
			}
		}
		if exploitability > 100 {
			exploitability = 100
		}
	}
	result.AttackabilityScore = exploitability // Maps to Attackability in the vector

	// 4. Evidence Score (0-100)
	evidenceScore := 10
	if assetClass == "Sensitive File Leak" || assetClass == "CI/CD System" {
		evidenceScore = 80
	}
	if evidenceCount > 0 {
		evidenceScore += evidenceCount * 10
		if evidenceScore > 50 && evidenceScore < 80 {
			evidenceScore = 50
		}
	}

	// Scan responseBody or indicators for verified vulnerability proof
	hasConcreteEvidence := false
	if len(lowerBody) > 0 {
		if strings.Contains(lowerURL, "jenkins") && (strings.Contains(lowerBody, "manage jenkins") || strings.Contains(lowerBody, "jenkins dashboard") || strings.Contains(lowerBody, "credential") || strings.Contains(lowerBody, "script console")) {
			evidenceScore = 100
			hasConcreteEvidence = true
			result.Justification = append(result.Justification, "Concrete evidence: unauthenticated Jenkins management dashboard/console found")
		} else if strings.Contains(lowerBody, "db_password") || strings.Contains(lowerBody, "aws_secret_access_key") || strings.Contains(lowerBody, "api_key") || strings.Contains(lowerBody, "private key") {
			evidenceScore = 100
			hasConcreteEvidence = true
			result.Justification = append(result.Justification, "Concrete evidence: credential leak exposed in response body")
		} else if strings.Contains(lowerBody, "index of /") {
			evidenceScore = 90
			hasConcreteEvidence = true
			result.Justification = append(result.Justification, "Concrete evidence: directory listing exposed")
		} else if strings.Contains(lowerBody, "cve-") {
			evidenceScore = 90
			hasConcreteEvidence = true
			result.Justification = append(result.Justification, "Concrete evidence: vulnerable version match (CVE reference)")
		}
	}

	if hasConcreteEvidence {
		exploitability = 100
		result.AttackabilityScore = 100
	}

	// 5. Ownership Score (0-100)
	// If owner is unknown (hasOwner = false), risk is higher
	ownershipScore := 100
	if hasOwner {
		ownershipScore = 40
		result.Justification = append(result.Justification, "Asset owner is identified (mitigates risk)")
	} else {
		result.Justification = append(result.Justification, "Asset owner is unknown (escalates risk)")
	}

	// 6. Attack Path Score (0-100)
	attackPathScore := 20
	if hasAttackPath {
		attackPathScore = 100
		result.Justification = append(result.Justification, "Asset has active attack-path propagation")
	}

	// 7. Confidence Score (0-100)
	confidence := 70
	if strings.Contains(lowerURL, "admin") || strings.Contains(lowerURL, "jenkins") || strings.Contains(lowerURL, ".env") || strings.Contains(lowerURL, ".git") {
		confidence = 95
	}
	if hasSensitiveParam {
		confidence = 100
	}
	if hasConcreteEvidence {
		confidence = 100
	}
	confidence = int(float64(confidence) * s.SourceConfidence * s.Reproducibility)
	result.ConfidenceScore = confidence

	// Freshness
	result.FreshnessScore = 100

	// Path Risk
	pathScore := 30
	paramCount := strings.Count(url, "&") + strings.Count(url, "?")
	if paramCount > 0 {
		pathScore += paramCount * 20
	}
	if strings.Contains(lowerURL, "/internal/") || strings.Contains(lowerURL, "/private/") || strings.Contains(lowerURL, "/secret/") {
		pathScore += 30
	}
	if strings.Contains(lowerURL, "/admin/") || strings.Contains(lowerURL, "/config") {
		pathScore += 20
	}
	if hasSensitiveExt {
		pathScore += 40
	}
	if pathScore > 100 {
		pathScore = 100
	}
	result.PathScore = pathScore

	// Populate RiskVector
	result.Risk = RiskVector{
		Exposure:       exposure,
		Attackability:  exploitability,
		BusinessImpact: classImpact,
		Confidence:     confidence,
		Freshness:      100,
		PathRisk:       pathScore,
	}

	// Combine components using the formula:
	// RiskScore = (Evidence * 0.25) + (Exposure * 0.15) + (BusinessImpact * 0.20) + (Exploitability * 0.15) + (Confidence * 0.10) + (AttackPath * 0.05) + (Ownership * 0.10)
	weightedScore := (float64(evidenceScore) * 0.25) +
		(float64(exposure) * 0.15) +
		(float64(classImpact) * 0.20) +
		(float64(exploitability) * 0.15) +
		(float64(confidence) * 0.10) +
		(float64(attackPathScore) * 0.05) +
		(float64(ownershipScore) * 0.10)

	result.Score = int(weightedScore)

	if hasSensitiveParam && (strings.Contains(lowerURL, "admin") || strings.Contains(lowerURL, "config") || assetClass == "CI/CD System") {
		result.Score = 100
	}

	// Apply caps / adjustments
	// If 403 response with no proof: cap risk score at 10
	if !hasConcreteEvidence && (strings.Contains(lowerBody, "403") || strings.Contains(lowerBody, "401") || strings.Contains(lowerBody, "forbidden")) {
		if strings.Contains(lowerURL, "jenkins") || strings.Contains(lowerURL, "admin") {
			result.Score = 10
			result.Justification = append(result.Justification, "Risk score capped at 10: access restricted (HTTP 403/401) with no proof of vulnerability/bypass")
		}
	}

	// Staging/Dev environment adjustments
	if s.AssetEnvironment == "staging" {
		result.Score = int(float64(result.Score) * 0.75)
		result.Justification = append(result.Justification, "Score adjusted down: Staging environment")
	} else if s.AssetEnvironment == "dev" {
		result.Score = int(float64(result.Score) * 0.50)
		result.Justification = append(result.Justification, "Score adjusted down: Dev/Local environment")
	}

	if result.Score > 100 {
		result.Score = 100
	}
	if result.Score < 0 {
		result.Score = 0
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

// AdjustScoreWithHistory boosts confidence and recomputes the score based on historical findings.
func (s *Scorer) AdjustScoreWithHistory(score *IntelligenceScore, historyCount int) {
	if historyCount > 0 {
		score.ConfidenceScore += historyCount * 5
		if score.ConfidenceScore > 100 {
			score.ConfidenceScore = 100
		}
		score.Risk.Confidence = score.ConfidenceScore

		score.Justification = append(score.Justification, fmt.Sprintf("Confidence boosted by historical findings evidence count: %d", historyCount))

		weightedScore := (float64(score.Risk.Exposure) * 0.15) +
			(float64(score.Risk.Attackability) * 0.15) +
			(float64(score.Risk.BusinessImpact) * 0.20) +
			(float64(score.Risk.Confidence) * 0.10) +
			(float64(score.Risk.Freshness) * 0.05) +
			(float64(score.Risk.PathRisk) * 0.10) +
			(float64(score.ConfidenceScore) * 0.25)

		score.Score = int(weightedScore)
		if score.Score > 100 {
			score.Score = 100
		}

		if score.Score >= 80 {
			score.Severity = "CRITICAL"
		} else if score.Score >= 50 {
			score.Severity = "HIGH"
		} else if score.Score >= 25 {
			score.Severity = "MEDIUM"
		} else {
			score.Severity = "LOW"
		}
	}
}
