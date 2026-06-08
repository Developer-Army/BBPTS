package risk

// RiskFactors represents multi-factor metrics for calculating asset and finding risk.
type RiskFactors struct {
	Exposure       int `json:"exposure"`
	Exploitability int `json:"exploitability"`
	BusinessImpact int `json:"business_impact"`
	Confidence     int `json:"confidence"`
	AttackPath     int `json:"attack_path"`
}

// CalculateRisk implements the advanced risk scoring engine logic.
func CalculateRisk(f RiskFactors) int {
	score := (float64(f.Exposure) * 0.20) +
		(float64(f.Exploitability) * 0.25) +
		(float64(f.BusinessImpact) * 0.30) +
		(float64(f.Confidence) * 0.15) +
		(float64(f.AttackPath) * 0.10)
	return int(score)
}
