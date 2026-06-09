package workflows

import (
	"testing"
	"time"
)

func TestGetSLADuration(t *testing.T) {
	tests := []struct {
		severity string
		expected time.Duration
	}{
		{"critical", 7 * 24 * time.Hour},
		{"high", 14 * 24 * time.Hour},
		{"medium", 30 * 24 * time.Hour},
		{"low", 90 * 24 * time.Hour},
		{"unknown", 90 * 24 * time.Hour},
	}

	for _, tt := range tests {
		got := GetSLADuration(tt.severity)
		if got != tt.expected {
			t.Errorf("GetSLADuration(%q) = %v, expected %v", tt.severity, got, tt.expected)
		}
	}
}

func TestIsValidTransition(t *testing.T) {
	tests := []struct {
		from     WorkflowState
		to       WorkflowState
		expected bool
	}{
		{StateDiscovered, StateTriaged, true},
		{StateDiscovered, StateClosed, true},
		{StateDiscovered, StateResolved, false},
		{StateClosed, StateReopened, true},
		{StateClosed, StateDiscovered, true},
		{StateClosed, StateResolved, false},
		{StateReopened, StateTriaged, true},
		{StateReopened, StateClosed, true},
		{StateReopened, StateResolved, false},
		{StateVerified, StateClosed, true},
		{StateVerified, StateResolved, false},
		{StateResolved, StateVerified, true},
		{StateResolved, StateClosed, true},
		{StateResolved, StateDiscovered, false},
	}

	for _, tt := range tests {
		got := IsValidTransition(tt.from, tt.to)
		if got != tt.expected {
			t.Errorf("IsValidTransition(%q, %q) = %v, expected %v", tt.from, tt.to, got, tt.expected)
		}
	}
}
