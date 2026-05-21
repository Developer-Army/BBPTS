package tui

import "testing"

func TestCalculateProgress_UsesToolLevelCompletion(t *testing.T) {
	m := NewModel()
	m.stageToolPlan[1] = 4
	m.stageCompletions[1] = map[string]struct{}{
		"subfinder": {},
		"httpx":     {},
	}

	got := m.calculateProgress()
	if got != 0.5 {
		t.Fatalf("expected 0.5 progress, got %f", got)
	}
}

func TestCalculateProgress_FallsBackToStageCompletion(t *testing.T) {
	m := NewModel()
	m.stages[0] = stageInfo{complete: true}
	m.stages[1] = stageInfo{complete: true}

	got := m.calculateProgress()
	if got != 2.0/7.0 {
		t.Fatalf("expected stage fallback progress, got %f", got)
	}
}
