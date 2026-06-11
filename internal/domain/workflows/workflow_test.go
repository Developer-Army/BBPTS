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
		{StateDiscovered, StateVerified, false},
		{StateClosed, StateReopened, true},
		{StateClosed, StateDiscovered, true},
		{StateReopened, StateTriaged, true},
		{StateReopened, StateClosed, true},
		{StateVerified, StateClosed, true},
		{StateRemediating, StateVerified, true},
		{StateRemediating, StateResolved, true},
		{StateRemediating, StateException, true},
		{StateException, StateRemediating, true},
		{StateException, StateClosed, true},
		{StateExpired, StateEscalated, true},
		{StateEscalated, StateRemediating, true},
	}

	for _, tt := range tests {
		got := IsValidTransition(tt.from, tt.to)
		if got != tt.expected {
			t.Errorf("IsValidTransition(%q, %q) = %v, expected %v", tt.from, tt.to, got, tt.expected)
		}
	}
}

func TestWorkflowEngine_TransitionFlow(t *testing.T) {
	now := time.Now()
	engine := NewWorkflowEngine(StateDiscovered, "high", now)

	if engine.State != StateDiscovered {
		t.Errorf("expected initial state Discovered, got %s", engine.State)
	}

	// Discovered -> Triaged
	if err := engine.Transition(StateTriaged, "analyst-1", "verified finding exists"); err != nil {
		t.Fatalf("failed transition: %v", err)
	}

	// Triaged -> Assigned
	if err := engine.Transition(StateAssigned, "analyst-1", "assigning to backend team"); err != nil {
		t.Fatalf("failed transition: %v", err)
	}

	// Invalid: Assigned -> Verified
	if err := engine.Transition(StateVerified, "analyst-1", "force verify"); err == nil {
		t.Error("expected error for invalid transition Assigned -> Verified")
	}

	// Assigned -> Acknowledged
	if err := engine.Transition(StateAcknowledged, "dev-lead", "ack'd finding"); err != nil {
		t.Fatalf("failed transition: %v", err)
	}

	// Acknowledged -> Remediating
	if err := engine.Transition(StateRemediating, "dev-lead", "remediation patch in progress"); err != nil {
		t.Fatalf("failed transition: %v", err)
	}

	// Remediating -> Verified
	if err := engine.Transition(StateVerified, "security-qa", "patch verified"); err != nil {
		t.Fatalf("failed transition: %v", err)
	}

	// Verified -> Closed
	if err := engine.Transition(StateClosed, "security-qa", "closed finding"); err != nil {
		t.Fatalf("failed transition: %v", err)
	}

	if len(engine.AuditHistory) != 6 {
		t.Errorf("expected 6 audit logs, got %d", len(engine.AuditHistory))
	}
}

func TestWorkflowEngine_SLAException(t *testing.T) {
	now := time.Now()
	engine := NewWorkflowEngine(StateRemediating, "critical", now)

	future := now.Add(48 * time.Hour)
	err := engine.RequestException(future, "manager-1", "waiting for next sprint release cycle")
	if err != nil {
		t.Fatalf("failed to request exception: %v", err)
	}

	if engine.State != StateException {
		t.Errorf("expected state Exception, got %s", engine.State)
	}

	if !engine.Deadline.Equal(future) {
		t.Errorf("expected deadline updated to %v, got %v", future, engine.Deadline)
	}

	// Check SLA before exception expires
	engine.CheckSLAExpiry(now.Add(24*time.Hour), "system")
	if engine.State != StateException {
		t.Errorf("expected state Exception to remain, got %s", engine.State)
	}

	// Check SLA after exception expires
	engine.CheckSLAExpiry(now.Add(50*time.Hour), "system")
	if engine.State != StateExpired {
		t.Errorf("expected state Expired after exception expiry, got %s", engine.State)
	}
}

func TestWorkflowEngine_SLAExpiryAndEscalation(t *testing.T) {
	now := time.Now()
	engine := NewWorkflowEngine(StateAssigned, "critical", now)

	// Critical SLA is 7 days. Check expiry at 8 days.
	engine.CheckSLAExpiry(now.Add(8*24*time.Hour), "system")
	if engine.State != StateExpired {
		t.Errorf("expected state to transition to Expired, got %s", engine.State)
	}

	// Second check should escalate it
	engine.CheckSLAExpiry(now.Add(9*24*time.Hour), "system")
	if engine.State != StateEscalated {
		t.Errorf("expected state to escalate, got %s", engine.State)
	}

	// Manual escalation
	engine2 := NewWorkflowEngine(StateRemediating, "high", now)
	err := engine2.TriggerEscalation("admin", "executive request")
	if err != nil {
		t.Fatalf("failed manual escalation: %v", err)
	}
	if engine2.State != StateEscalated {
		t.Errorf("expected Escalated, got %s", engine2.State)
	}
}
