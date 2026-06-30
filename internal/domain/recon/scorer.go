package recon

import (
	"fmt"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/risk"
)

type RiskVector struct {
	EvidenceQuality    int `json:"evidence_quality"`
	Exploitability     int `json:"exploitability"`
	Exposure           int `json:"exposure"`
	Ownership          int `json:"ownership"`
	BusinessImpact     int `json:"business_impact"`
	Freshness          int `json:"freshness"`
	AttackPathDistance int `json:"attack_path_distance"`

	// Legacy fields for backward compatibility
	Attackability int `json:"attackability"`
	Confidence    int `json:"confidence"`
	PathRisk      int `json:"path_risk"`
}

type IntelligenceScore struct {
	Score         int
	Severity      string
	Justification []string

	ExposureScore       int
	AttackabilityScore  int
	BusinessImpactScore int
	ConfidenceScore     int
	FreshnessScore      int
	PathScore           int

	Risk RiskVector
}

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

func (s *Scorer) ScoreEndpoint(url string, isAuthRequired bool, responseBody string) *IntelligenceScore {
	return s.ScoreEndpointAdvanced(url, isAuthRequired, responseBody, false, false, 0, 0)
}

func (s *Scorer) ScoreEndpointAdvanced(url string, isAuthRequired bool, responseBody string, hasOwner bool, hasAttackPath bool, evidenceCount int, exploitability int) *IntelligenceScore {
	result := &IntelligenceScore{
		Score:         0,
		Justification: make([]string, 0),
	}

	lowerURL := strings.ToLower(url)
	lowerBody := strings.ToLower(responseBody)

	host := url
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	lowerHost := strings.ToLower(host)

	evidenceQuality := 10
	if evidenceCount > 0 {
		evidenceQuality = 50 + (evidenceCount * 10)
		if evidenceQuality > 90 {
			evidenceQuality = 90
		}
		result.Justification = append(result.Justification, fmt.Sprintf("Evidence count: %d", evidenceCount))
	}

	if len(lowerBody) > 0 {
		if strings.Contains(lowerBody, "db_password") || strings.Contains(lowerBody, "aws_secret_access_key") || strings.Contains(lowerBody, "api_key") || strings.Contains(lowerBody, "private key") {
			evidenceQuality = 100
			result.Justification = append(result.Justification, "Concrete evidence: credential leak exposed in response body")
		} else if strings.Contains(lowerBody, "index of /") {
			evidenceQuality = 95
			result.Justification = append(result.Justification, "Concrete evidence: directory listing exposed")
		} else if strings.Contains(lowerBody, "cve-") {
			evidenceQuality = 90
			result.Justification = append(result.Justification, "Concrete evidence: vulnerable version match (CVE reference)")
		}
	}

	expScore := exploitability
	if expScore <= 0 {
		if isAuthRequired {
			expScore = 30
			result.Justification = append(result.Justification, "Authenticated surface (decreases exploitability)")
		} else {
			expScore = 70
			result.Justification = append(result.Justification, "Unauthenticated surface (increases exploitability)")
		}
	}

	exposure := 100
	labels := strings.Split(lowerHost, ".")
	isInternal := false
	for _, label := range labels {
		if label == "internal" || label == "local" || label == "localhost" || label == "private" || label == "dev" || label == "test" || label == "staging" {
			isInternal = true
			break
		}
	}
	if isInternal {
		exposure = 40
		result.Justification = append(result.Justification, "Exposure reduced due to internal/non-prod subdomain")
	} else {
		result.Justification = append(result.Justification, "Exposure score high (public facing domain)")
	}

	ownershipScore := 100
	if hasOwner {
		ownershipScore = 30
		result.Justification = append(result.Justification, "Asset owner is identified (mitigates risk)")
	} else {
		result.Justification = append(result.Justification, "Asset owner is unknown (unmanaged risk)")
	}

	businessImpact := 50
	if strings.Contains(lowerURL, "api") {
		businessImpact = 70
	}
	businessImpact = int(float64(businessImpact) * s.BlastRadius)

	freshness := 100

	attackPathDistance := 20
	if hasAttackPath {
		attackPathDistance = 100
		result.Justification = append(result.Justification, "Asset has active attack path to crown jewels")
	}

	factors := risk.EvidenceRiskFactors{
		EvidenceQuality:    evidenceQuality,
		Exploitability:     expScore,
		Exposure:           exposure,
		Ownership:          ownershipScore,
		BusinessImpact:     businessImpact,
		Freshness:          freshness,
		AttackPathDistance: attackPathDistance,
	}

	weightedScore := risk.CalculateEvidenceRisk(factors)
	result.Score = weightedScore

	switch s.AssetEnvironment {
	case "staging":
		result.Score = int(float64(result.Score) * 0.75)
		result.Justification = append(result.Justification, "Score adjusted down: Staging environment")
	case "dev":
		result.Score = int(float64(result.Score) * 0.50)
		result.Justification = append(result.Justification, "Score adjusted down: Dev/Local environment")
	}

	if result.Score > 100 {
		result.Score = 100
	}
	if result.Score < 0 {
		result.Score = 0
	}

	confidence := int(float64(evidenceQuality) * s.SourceConfidence * s.Reproducibility)
	result.Risk = RiskVector{
		EvidenceQuality:    evidenceQuality,
		Exploitability:     expScore,
		Exposure:           exposure,
		Ownership:          ownershipScore,
		BusinessImpact:     businessImpact,
		Freshness:          freshness,
		AttackPathDistance: attackPathDistance,

		Attackability: expScore,
		Confidence:    confidence,
		PathRisk:      attackPathDistance,
	}

	result.ExposureScore = exposure
	result.AttackabilityScore = expScore
	result.BusinessImpactScore = businessImpact
	result.FreshnessScore = freshness
	result.PathScore = attackPathDistance

	result.ConfidenceScore = confidence

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

func (s *Scorer) AdjustScoreWithHistory(score *IntelligenceScore, historyCount int) {
	if historyCount > 0 {
		score.ConfidenceScore += historyCount * 5
		if score.ConfidenceScore > 100 {
			score.ConfidenceScore = 100
		}
		score.Risk.EvidenceQuality += historyCount * 5
		if score.Risk.EvidenceQuality > 100 {
			score.Risk.EvidenceQuality = 100
		}

		score.Justification = append(score.Justification, fmt.Sprintf("Confidence boosted by historical findings evidence count: %d", historyCount))

		weightedScore := risk.CalculateEvidenceRisk(risk.EvidenceRiskFactors{
			EvidenceQuality:    score.Risk.EvidenceQuality,
			Exploitability:     score.Risk.Exploitability,
			Exposure:           score.Risk.Exposure,
			Ownership:          score.Risk.Ownership,
			BusinessImpact:     score.Risk.BusinessImpact,
			Freshness:          score.Risk.Freshness,
			AttackPathDistance: score.Risk.AttackPathDistance,
		})

		score.Score = weightedScore
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
