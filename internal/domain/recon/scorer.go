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
	result := &IntelligenceScore{
		Score:         0,
		Justification: make([]string, 0),
	}

	lowerURL := strings.ToLower(url)

	// Determine Hostname exposure context
	host := url
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	lowerHost := strings.ToLower(host)

	// Determine Asset Class and Business Impact (0-100)
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
	} else if strings.Contains(lowerURL, "internal") || strings.Contains(lowerURL, "localhost") || strings.Contains(lowerURL, "private") || strings.Contains(lowerURL, "corp") || strings.Contains(lowerURL, "local") {
		assetClass = "Internal Service"
		classImpact = 40
	} else if strings.Contains(lowerURL, "s3.amazonaws.com") || strings.Contains(lowerURL, "blob.core.windows.net") || strings.Contains(lowerURL, "storage.googleapis.com") || strings.Contains(lowerURL, "cloudfront") || strings.Contains(lowerURL, "kubernetes") || strings.Contains(lowerURL, "k8s") || strings.Contains(lowerURL, "docker") {
		assetClass = "Cloud Control Plane"
		classImpact = 85
	}

	result.Justification = append(result.Justification, fmt.Sprintf("Asset class identified: %s", assetClass))
	// Adjust business impact by blast radius
	classImpact = int(float64(classImpact) * s.BlastRadius)
	result.BusinessImpactScore = classImpact

	// 1. Exposure Score (0-100)
	exposure := 100
	if strings.Contains(lowerHost, "internal") || strings.Contains(lowerHost, "local") || strings.Contains(lowerHost, "localhost") || strings.Contains(lowerHost, "private") || strings.Contains(lowerHost, "dev") || strings.Contains(lowerHost, "test") || strings.Contains(lowerHost, "staging") {
		exposure = 40
		result.Justification = append(result.Justification, "Exposure reduced due to internal/non-prod subdomain")
	} else {
		result.Justification = append(result.Justification, "Exposure score high (public facing domain)")
	}
	result.ExposureScore = exposure

	// 2. Attackability Score (0-100)
	attackability := 30
	if isAuthRequired {
		attackability += 30
		result.Justification = append(result.Justification, "Authenticated surface (increases attackability score)")
	}
	if strings.Contains(lowerURL, "/upload") || strings.Contains(lowerURL, "/file") || strings.Contains(lowerURL, "/download") {
		attackability += 20
		result.Justification = append(result.Justification, "Contains upload/download endpoint")
	}
	if strings.Contains(lowerURL, "graphql") || strings.Contains(lowerURL, "swagger") || strings.Contains(lowerURL, "openapi") || strings.Contains(lowerURL, "api-docs") {
		attackability += 20
		result.Justification = append(result.Justification, "API documentation / Query interface present")
	}
	sensitiveExts := []string{".bak", ".sql", ".env", ".log", ".conf", ".config", ".old", ".orig", ".backup", ".dump", ".git", ".svn"}
	hasSensitiveExt := false
	for _, ext := range sensitiveExts {
		if strings.Contains(lowerURL, ext) {
			attackability += 40
			hasSensitiveExt = true
			result.Justification = append(result.Justification, fmt.Sprintf("Sensitive file extension: %s", ext))
			break
		}
	}
	if hasSensitiveExt && (strings.Contains(lowerURL, ".env") || strings.Contains(lowerURL, ".git")) {
		attackability += 30 // extra boost for credential-bearing extensions
	}

	sensitiveParams := []string{"token", "key", "secret", "password", "passwd", "auth", "api_key", "access_token"}
	hasSensitiveParam := false
	for _, param := range sensitiveParams {
		if strings.Contains(lowerURL, param+"=") || strings.Contains(lowerURL, param+"[") {
			attackability += 45
			hasSensitiveParam = true
			result.Justification = append(result.Justification, fmt.Sprintf("Sensitive parameter: %s", param))
			break
		}
	}

	if attackability > 100 {
		attackability = 100
	}
	result.AttackabilityScore = attackability

	// 3. Confidence Score (0-100)
	confidence := 80
	if strings.Contains(lowerURL, "admin") || strings.Contains(lowerURL, "jenkins") || strings.Contains(lowerURL, ".env") || strings.Contains(lowerURL, ".git") {
		confidence = 95
		result.Justification = append(result.Justification, "High confidence indicators matched")
	}
	if hasSensitiveParam {
		confidence = 100
	}
	// Adjust confidence score with source confidence and reproducibility
	confidence = int(float64(confidence) * s.SourceConfidence * s.Reproducibility)
	result.ConfidenceScore = confidence

	// 4. Freshness Score (0-100)
	result.FreshnessScore = 100

	// 5. Path Score (0-100)
	pathScore := 30
	paramCount := strings.Count(url, "&") + strings.Count(url, "?")
	if paramCount > 0 {
		pathScore += paramCount * 20
		result.Justification = append(result.Justification, fmt.Sprintf("Path contains %d query parameters", paramCount))
	}
	if strings.Contains(lowerURL, "/internal/") || strings.Contains(lowerURL, "/private/") || strings.Contains(lowerURL, "/secret/") {
		pathScore += 30
		result.Justification = append(result.Justification, "Path contains internal/private segment")
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
		Attackability:  attackability,
		BusinessImpact: classImpact,
		Confidence:     confidence,
		Freshness:      100,
		PathRisk:       pathScore,
	}

	// Calculate final score using weighted multi-factor risk model from the vector:
	// FinalScore = (Exposure * 0.20) + (Attackability * 0.25) + (BusinessImpact * 0.30) + (Confidence * 0.10) + (Freshness * 0.05) + (PathRisk * 0.10)
	weightedScore := (float64(result.Risk.Exposure) * 0.20) +
		(float64(result.Risk.Attackability) * 0.25) +
		(float64(result.Risk.BusinessImpact) * 0.30) +
		(float64(result.Risk.Confidence) * 0.10) +
		(float64(result.Risk.Freshness) * 0.05) +
		(float64(result.Risk.PathRisk) * 0.10)

	result.Score = int(weightedScore)
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
