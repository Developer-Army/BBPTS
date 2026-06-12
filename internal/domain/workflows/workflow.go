package workflows

import (
	"errors"
	"fmt"
	"time"
)

// WorkflowState represents the state of a CTEM finding.
type WorkflowState string

const (
	StateDiscovered   WorkflowState = "Discovered"
	StateTriaged      WorkflowState = "Triaged"
	StateAssigned     WorkflowState = "Assigned"
	StateAcknowledged WorkflowState = "Acknowledged"
	StateRemediating  WorkflowState = "Remediating"
	StateResolved     WorkflowState = "Resolved" // Legacy compatibility
	StateVerified     WorkflowState = "Verified"
	StateClosed       WorkflowState = "Closed"
	StateReopened     WorkflowState = "Reopened"
	StateException    WorkflowState = "Exception"
	StateExpired      WorkflowState = "Expired"
	StateEscalated    WorkflowState = "Escalated"
)

// IsValidTransition validates if a state change is allowed under the CTEM specification.
func IsValidTransition(from, to WorkflowState) bool {
	if from == to {
		return true
	}
	// Expired and Escalated transitions are allowed from any active/non-final states
	if to == StateExpired || to == StateEscalated {
		return from != StateClosed && from != StateVerified
	}

	switch from {
	case StateDiscovered:
		return to == StateTriaged || to == StateClosed
	case StateTriaged:
		return to == StateAssigned || to == StateClosed || to == StateException
	case StateAssigned:
		return to == StateAcknowledged || to == StateClosed || to == StateException
	case StateAcknowledged:
		return to == StateRemediating || to == StateClosed || to == StateException
	case StateRemediating:
		return to == StateVerified || to == StateResolved || to == StateClosed || to == StateException
	case StateResolved:
		// Legacy compatibility
		return to == StateVerified || to == StateClosed
	case StateVerified:
		return to == StateClosed || to == StateReopened || to == StateDiscovered
	case StateClosed:
		return to == StateReopened || to == StateDiscovered
	case StateReopened:
		return to == StateTriaged || to == StateClosed
	case StateException:
		// Can return to active states, close, or transition to expired
		return to == StateRemediating || to == StateClosed || to == StateTriaged || to == StateExpired
	case StateExpired:
		// Can be escalated or resolved/closed
		return to == StateEscalated || to == StateRemediating || to == StateClosed
	case StateEscalated:
		// Must be remediating, verified, or closed
		return to == StateRemediating || to == StateClosed
	default:
		return false
	}
}

// GetSLADuration returns the SLA timeframe by severity.
func GetSLADuration(severity string) time.Duration {
	switch severity {
	case "critical":
		return 7 * 24 * time.Hour
	case "high":
		return 14 * 24 * time.Hour
	case "medium":
		return 30 * 24 * time.Hour
	default:
		return 90 * 24 * time.Hour
	}
}

// AuditLog represents an action taken on a finding workflow.
type AuditLog struct {
	Timestamp time.Time
	FromState WorkflowState
	ToState   WorkflowState
	Actor     string
	Reason    string
}

// WorkflowEngine encapsulates workflow state machine rules, SLAs, and exceptions.
type WorkflowEngine struct {
	SLADuration    time.Duration
	CreatedAt      time.Time
	Deadline       time.Time
	ExceptionUntil time.Time
	State          WorkflowState
	AuditHistory   []AuditLog
}

func NewWorkflowEngine(initialState WorkflowState, severity string, createdAt time.Time) *WorkflowEngine {
	sla := GetSLADuration(severity)
	return &WorkflowEngine{
		SLADuration:  sla,
		CreatedAt:    createdAt,
		Deadline:     createdAt.Add(sla),
		State:        initialState,
		AuditHistory: make([]AuditLog, 0),
	}
}

// Transition attempts to change the state with safety validations and audit recording.
func (we *WorkflowEngine) Transition(to WorkflowState, actor string, reason string) error {
	if !IsValidTransition(we.State, to) {
		return fmt.Errorf("invalid transition from %s to %s", we.State, to)
	}

	log := AuditLog{
		Timestamp: time.Now(),
		FromState: we.State,
		ToState:   to,
		Actor:     actor,
		Reason:    reason,
	}

	we.State = to
	we.AuditHistory = append(we.AuditHistory, log)
	return nil
}

// RequestException grants a temporary SLA extension.
func (we *WorkflowEngine) RequestException(until time.Time, actor string, reason string) error {
	if we.State == StateClosed {
		return errors.New("cannot request exception for closed finding")
	}
	if until.Before(time.Now()) {
		return errors.New("exception date must be in the future")
	}

	err := we.Transition(StateException, actor, fmt.Sprintf("Exception granted until %s: %s", until.Format(time.RFC3339), reason))
	if err != nil {
		return err
	}

	we.ExceptionUntil = until
	we.Deadline = until
	return nil
}

// CheckSLAExpiry evaluates if the SLA deadline has passed.
// If past deadline, transitions the state to Expired or Escalated.
func (we *WorkflowEngine) CheckSLAExpiry(now time.Time, actor string) {
	if we.State == StateClosed || we.State == StateVerified {
		return
	}

	// If exception is active, we are safe until exception expires
	if we.State == StateException {
		if now.After(we.ExceptionUntil) {
			_ = we.Transition(StateExpired, actor, "Exception period expired")
		}
		return
	}

	if now.After(we.Deadline) {
		if we.State == StateExpired {
			// Double escalation path
			_ = we.Transition(StateEscalated, actor, "SLA expired and overdue - escalated")
		} else if we.State != StateEscalated {
			_ = we.Transition(StateExpired, actor, "SLA deadline exceeded")
		}
	}
}

// TriggerEscalation escalates an overdue/stalled finding.
func (we *WorkflowEngine) TriggerEscalation(actor string, reason string) error {
	return we.Transition(StateEscalated, actor, reason)
}
