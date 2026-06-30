package risk

type RiskFactors struct {
	Exposure       int `json:"exposure"`
	Exploitability int `json:"exploitability"`
	BusinessImpact int `json:"business_impact"`
	Confidence     int `json:"confidence"`
	AttackPath     int `json:"attack_path"`
}

type EvidenceRiskFactors struct {
	EvidenceQuality    int `json:"evidence_quality"`
	Exploitability     int `json:"exploitability"`
	Exposure           int `json:"exposure"`
	Ownership          int `json:"ownership"` // higher means unmanaged/unowned risk
	BusinessImpact     int `json:"business_impact"`
	Freshness          int `json:"freshness"`            // higher means newer/fresh
	AttackPathDistance int `json:"attack_path_distance"` // higher means closer/more dangerous
}

func CalculateRisk(f RiskFactors) int {
	score := (float64(f.Exposure) * 0.20) +
		(float64(f.Exploitability) * 0.25) +
		(float64(f.BusinessImpact) * 0.30) +
		(float64(f.Confidence) * 0.15) +
		(float64(f.AttackPath) * 0.10)
	return int(score)
}

func CalculateEvidenceRisk(f EvidenceRiskFactors) int {
	score := (float64(f.EvidenceQuality) * 0.25) +
		(float64(f.Exploitability) * 0.20) +
		(float64(f.Exposure) * 0.15) +
		(float64(f.Ownership) * 0.10) +
		(float64(f.BusinessImpact) * 0.15) +
		(float64(f.Freshness) * 0.05) +
		(float64(f.AttackPathDistance) * 0.10)
	return int(score)
}
