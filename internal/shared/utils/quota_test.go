package utils

import (
	"os"
	"testing"
)

func TestQuotaGuard(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "quota-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	qg := NewQuotaGuard(tmpDir)
	if qg.Increment("shodan") != 1 {
		t.Errorf("expected shodan count to be 1")
	}
	if qg.Increment("shodan") != 2 {
		t.Errorf("expected shodan count to be 2")
	}
	if qg.Increment("chaos") != 1 {
		t.Errorf("expected chaos count to be 1")
	}
	if qg.Increment("github") != 1 {
		t.Errorf("expected github count to be 1")
	}

	// Load in a new instance and check persistence
	qg2 := NewQuotaGuard(tmpDir)
	usage := qg2.GetUsage()
	if usage.ShodanCalls != 2 {
		t.Errorf("expected persisted shodan calls to be 2, got %d", usage.ShodanCalls)
	}
	if usage.ChaosCalls != 1 {
		t.Errorf("expected persisted chaos calls to be 1, got %d", usage.ChaosCalls)
	}
	if usage.GitHubCalls != 1 {
		t.Errorf("expected persisted github calls to be 1, got %d", usage.GitHubCalls)
	}
}
