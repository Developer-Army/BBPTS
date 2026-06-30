package recon

import (
	"testing"
)

func TestNewScorer(t *testing.T) {
	scorer := NewScorer()
	if scorer == nil {
		t.Fatal("NewScorer returned nil")
	}
}

func TestScorer_ScoreEndpoint_EvidenceBased(t *testing.T) {
	scorer := NewScorer()

	res1 := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)
	if res1.Score == 0 {
		t.Error("expected non-zero score for public endpoint")
	}

	resUnowned := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)
	resOwned := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", true, false, 0, 0)
	if resUnowned.Score <= resOwned.Score {
		t.Errorf("expected unowned target risk (%d) to be higher than owned target risk (%d)", resUnowned.Score, resOwned.Score)
	}

	resUnauth := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)
	resAuth := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", true, "", false, false, 0, 0)
	if resUnauth.Score <= resAuth.Score {
		t.Errorf("expected unauthenticated target risk (%d) to be higher than authenticated target risk (%d)", resUnauth.Score, resAuth.Score)
	}

	resPublic := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)
	resInternal := scorer.ScoreEndpointAdvanced("https://internal.acme-corp.io/api", false, "", false, false, 0, 0)
	if resPublic.Score <= resInternal.Score {
		t.Errorf("expected public target risk (%d) to be higher than internal target risk (%d)", resPublic.Score, resInternal.Score)
	}

	resNoPath := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)
	resWithPath := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, true, 0, 0)
	if resWithPath.Score <= resNoPath.Score {
		t.Errorf("expected target risk with attack path (%d) to be higher than without (%d)", resWithPath.Score, resNoPath.Score)
	}

	resNoEv := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)
	resWithEv := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "db_password=secret", false, false, 0, 0)
	if resWithEv.Score <= resNoEv.Score {
		t.Errorf("expected target risk with concrete evidence (%d) to be higher than without (%d)", resWithEv.Score, resNoEv.Score)
	}
}

func TestScorer_ScoreEndpoint_SeverityCalculation(t *testing.T) {
	scorer := NewScorer()

	res1 := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "db_password=secret", false, true, 5, 90)
	if res1.Severity != "CRITICAL" && res1.Severity != "HIGH" {
		t.Errorf("expected CRITICAL or HIGH severity for high risk target, got %s", res1.Severity)
	}

	res2 := scorer.ScoreEndpointAdvanced("https://internal.acme-corp.io/api", true, "", true, false, 0, 10)
	if res2.Severity == "" {
		t.Error("expected severity to be set")
	}
}

func TestScorer_ScoreEndpoint_JustificationTracking(t *testing.T) {
	scorer := NewScorer()

	result := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", true, "", false, true, 3, 0)

	if len(result.Justification) == 0 {
		t.Error("expected at least one justification")
	}

	seen := make(map[string]bool)
	for _, j := range result.Justification {
		if seen[j] {
			t.Errorf("duplicate justification: %s", j)
		}
		seen[j] = true
	}
}

func TestScorer_Phase4Adjustments(t *testing.T) {

	sStaging := NewScorer()
	sStaging.AssetEnvironment = "staging"
	resStaging := sStaging.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)

	sProd := NewScorer()
	resProd := sProd.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)

	expectedStagingScore := int(float64(resProd.Score) * 0.75)
	if resStaging.Score != expectedStagingScore {
		t.Errorf("expected staging score %d, got %d", expectedStagingScore, resStaging.Score)
	}

	sDev := NewScorer()
	sDev.AssetEnvironment = "dev"
	resDev := sDev.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)

	expectedDevScore := int(float64(resProd.Score) * 0.50)
	if resDev.Score != expectedDevScore {
		t.Errorf("expected dev score %d, got %d", expectedDevScore, resDev.Score)
	}

	sBlast := NewScorer()
	sBlast.BlastRadius = 0.5
	resBlast := sBlast.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)

	expectedImpact := int(70.0 * 0.5)
	if resBlast.BusinessImpactScore != expectedImpact {
		t.Errorf("expected business impact %d, got %d", expectedImpact, resBlast.BusinessImpactScore)
	}

	sConf := NewScorer()
	sConf.SourceConfidence = 0.8
	sConf.Reproducibility = 0.5
	resConf := sConf.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 1, 0)

	if resConf.ConfidenceScore == 0 {
		t.Errorf("expected confidence score to be non-zero, got %d", resConf.ConfidenceScore)
	}
}

func TestScorer_AdjustScoreWithHistory(t *testing.T) {
	scorer := NewScorer()
	result := scorer.ScoreEndpointAdvanced("https://acme-corp.io/api", false, "", false, false, 0, 0)
	initialScore := result.Score
	initialConf := result.ConfidenceScore

	scorer.AdjustScoreWithHistory(result, 5)

	if result.ConfidenceScore <= initialConf {
		t.Errorf("expected confidence score to increase from %d, got %d", initialConf, result.ConfidenceScore)
	}
	if result.Score <= initialScore {
		t.Errorf("expected final score to increase from %d, got %d", initialScore, result.Score)
	}
}
