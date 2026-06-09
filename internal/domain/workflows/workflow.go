package workflows

import "time"

// WorkflowState represents the state of a CTEM finding.
type WorkflowState string

const (
	StateDiscovered  WorkflowState = "Discovered"
	StateTriaged     WorkflowState = "Triaged"
	StateAssigned    WorkflowState = "Assigned"
	StateAcknowledged WorkflowState = "Acknowledged"
	StateRemediating WorkflowState = "Remediating"
	StateResolved    WorkflowState = "Resolved"
	StateVerified    WorkflowState = "Verified"
	StateClosed      WorkflowState = "Closed"
	StateReopened    WorkflowState = "Reopened"
)

// IsValidTransition validates if a state change is allowed under the CTEM specification.
func IsValidTransition(from, to WorkflowState) bool {
	if from == to {
		return true
	}
	switch from {
	case StateDiscovered:
		return to == StateTriaged || to == StateClosed
	case StateTriaged:
		return to == StateAssigned || to == StateClosed
	case StateAssigned:
		return to == StateAcknowledged || to == StateClosed
	case StateAcknowledged:
		return to == StateRemediating || to == StateClosed
	case StateRemediating:
		return to == StateResolved || to == StateClosed
	case StateResolved:
		return to == StateVerified || to == StateClosed
	case StateVerified:
		return to == StateClosed
	case StateClosed:
		return to == StateReopened || to == StateDiscovered
	case StateReopened:
		return to == StateTriaged || to == StateClosed
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
