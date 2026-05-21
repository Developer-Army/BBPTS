package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

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

func TestTabToggleMode(t *testing.T) {
	m := NewModel()
	m.awaitingInput = true
	m.targetMode = "normal"

	// Simulate tab keypress
	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyTab, Runes: []rune{}})
	m = res.(Model)
	if m.targetMode != "light" {
		t.Errorf("expected mode to toggle to light, got %s", m.targetMode)
	}
	if cmd != nil {
		t.Errorf("expected cmd to be nil, got %v", cmd)
	}

	// Tab again
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab, Runes: []rune{}})
	m = res.(Model)
	if m.targetMode != "normal" {
		t.Errorf("expected mode to toggle back to normal, got %s", m.targetMode)
	}
}

func TestTargetValidationResultMsg_HandlesInvalid(t *testing.T) {
	m := NewModel()
	m.awaitingInput = true

	msg := TargetValidationResultMsg{
		Target:   "invalid-target",
		IsValid:  false,
		ErrorMsg: "Host does not resolve",
	}

	res, cmd := m.Update(msg)
	m = res.(Model)

	if !m.awaitingInput {
		t.Errorf("expected to stay in awaitingInput state on invalid target validation")
	}
	hasError := false
	for _, line := range m.cliHistory {
		if strings.Contains(line, "Error") {
			hasError = true
			break
		}
	}
	if !hasError {
		t.Errorf("expected error message in cliHistory, got %v", m.cliHistory)
	}
	if cmd != nil {
		t.Errorf("expected cmd to be nil, got %v", cmd)
	}
}
