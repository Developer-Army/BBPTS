package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

// Escalator manages periodic SLA and escalation checks for active findings.
type Escalator struct {
	store    *storage.Storage
	interval time.Duration
	done     chan struct{}
}

// NewEscalator creates a new Escalator daemon.
func NewEscalator(store *storage.Storage, checkInterval time.Duration) *Escalator {
	if checkInterval <= 0 {
		checkInterval = 1 * time.Hour
	}
	return &Escalator{
		store:    store,
		interval: checkInterval,
		done:     make(chan struct{}),
	}
}

// Start runs the escalator ticker in a background goroutine.
func (e *Escalator) Start(ctx context.Context) {
	slog.Info("Starting CTEM Escalator Engine", "interval", e.interval)
	ticker := time.NewTicker(e.interval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-e.done:
				return
			case <-ticker.C:
				e.CheckAndEscalate(ctx)
			}
		}
	}()
}

// Stop stops the background escalator ticker.
func (e *Escalator) Stop() {
	close(e.done)
}

// CheckAndEscalate queries overdue assignments, flags their statuses, and triggers matched escalation rules.
func (e *Escalator) CheckAndEscalate(ctx context.Context) {
	slog.Debug("Running CTEM Escalation evaluation")
	overdue, err := e.store.GetOverdueAssignments()
	if err != nil {
		slog.Error("Failed to fetch overdue assignments", "error", err)
		return
	}

	for _, oa := range overdue {
		// 1. Mark status as overdue in db if not already marked/escalated
		if oa.Status != "overdue" && !isEscalatedStatus(oa.Status) {
			if err := e.store.UpdateAssignmentStatus(oa.AssignmentID, "overdue"); err != nil {
				slog.Error("Failed to update status to overdue", "assignment_id", oa.AssignmentID, "error", err)
			}
		}

		// 2. Fetch escalation rules for this policy severity
		rules, err := e.store.GetEscalationRulesForSeverity(oa.Severity)
		if err != nil {
			slog.Error("Failed to fetch escalation rules", "severity", oa.Severity, "error", err)
			continue
		}

		now := time.Now().UTC()
		overdueDuration := now.Sub(oa.DueAt)

		for _, rule := range rules {
			requiredDelay := time.Duration(rule.DelayDays) * 24 * time.Hour
			if overdueDuration >= requiredDelay {
				// Check if we already ran this or a higher level of escalation
				alreadyRun := false
				var lastLvl int
				if n, err := fmt.Sscanf(oa.Status, "escalated_lvl_%d", &lastLvl); err == nil && n == 1 {
					if lastLvl >= rule.DelayDays {
						alreadyRun = true
					}
				}

				if alreadyRun {
					continue
				}

				// Trigger the rule!
				e.dispatchEscalation(oa, rule)

				// Update status to record that this escalation level ran
				newStatus := fmt.Sprintf("escalated_lvl_%d", rule.DelayDays)
				if err := e.store.UpdateAssignmentStatus(oa.AssignmentID, newStatus); err != nil {
					slog.Error("Failed to update escalation status", "assignment_id", oa.AssignmentID, "status", newStatus, "error", err)
				}
			}
		}
	}
}

func isEscalatedStatus(status string) bool {
	var lastLvl int
	n, err := fmt.Sscanf(status, "escalated_lvl_%d", &lastLvl)
	return err == nil && n == 1
}

func (e *Escalator) dispatchEscalation(oa storage.OverdueAssignment, rule storage.EscalationRule) {
	slog.Warn("CTEM ESCALATION TRIGGERED",
		"assignment_id", oa.AssignmentID,
		"finding", oa.Title,
		"target", oa.Target,
		"delay_days", rule.DelayDays,
		"action_type", rule.ActionType,
	)

	// Build the notification payload
	message := fmt.Sprintf("⚠️ *SLA Breach Escalation (Level %d)*\n"+
		"*Finding:* %s\n"+
		"*Severity:* %s\n"+
		"*Target:* %s\n"+
		"*Due Date:* %s\n"+
		"*Status:* Overdue\n",
		rule.DelayDays, oa.Title, oa.Severity, oa.Target, oa.DueAt.Format(time.RFC3339))

	switch rule.ActionType {
	case "slack", "webhook":
		urlVal, ok := rule.Properties["url"]
		if !ok {
			slog.Error("Webhook/Slack URL missing in escalation properties")
			return
		}
		url, ok := urlVal.(string)
		if !ok || url == "" {
			slog.Error("Invalid Webhook/Slack URL format")
			return
		}

		payload := map[string]string{
			"text": message,
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}

		resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
		if err != nil {
			slog.Error("Failed to dispatch escalation webhook", "url", url, "error", err)
			return
		}
		defer resp.Body.Close()
		slog.Info("Escalation webhook dispatched successfully", "status_code", resp.StatusCode)
	default:
		slog.Warn("Unsupported escalation action type", "type", rule.ActionType)
	}
}
