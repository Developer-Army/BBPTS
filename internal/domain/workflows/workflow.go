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
)

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
