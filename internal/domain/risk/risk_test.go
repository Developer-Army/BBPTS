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
				Exposure:       50,
				Exploitability: 60,
				BusinessImpact: 80,
				Confidence:     70,
				AttackPath:     40,
			},
			expected: 63,
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
