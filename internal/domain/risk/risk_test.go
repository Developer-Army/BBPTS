package risk

import "testing"

func TestCalculateRisk(t *testing.T) {
	tests := []struct {
		name     string
		factors  RiskFactors
		expected int
	}{
		{
			name: "All zero factors",
			factors: RiskFactors{
				Exposure:       0,
				Exploitability: 0,
				BusinessImpact: 0,
				Confidence:     0,
				AttackPath:     0,
			},
			expected: 0,
		},
		{
			name: "All max factors",
			factors: RiskFactors{
				Exposure:       100,
				Exploitability: 100,
				BusinessImpact: 100,
				Confidence:     100,
				AttackPath:     100,
			},
			expected: 100,
		},
		{
			name: "Weighted calculation test",
			factors: RiskFactors{
				Exposure:       50,  // 50 * 0.20 = 10
				Exploitability: 60,  // 60 * 0.25 = 15
				BusinessImpact: 80,  // 80 * 0.30 = 24
				Confidence:     70,  // 70 * 0.15 = 10.5
				AttackPath:     40,  // 40 * 0.10 = 4
			},
			expected: 63, // 10 + 15 + 24 + 10.5 + 4 = 63.5 -> cast to int is 63
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateRisk(tt.factors)
			if got != tt.expected {
				t.Errorf("CalculateRisk() = %d, expected %d", got, tt.expected)
			}
		})
	}
}
