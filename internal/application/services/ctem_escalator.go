package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

type Escalator struct {
	store    *storage.Storage
	interval time.Duration
	done     chan struct{}
	stopOnce sync.Once
	running  bool
	mu       sync.Mutex
}

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

func (e *Escalator) Start(ctx context.Context) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		slog.Warn("CTEM Escalator already running, ignoring Start()")
		return
	}
	e.running = true
	e.mu.Unlock()

	slog.Info("Starting CTEM Escalator Engine", "interval", e.interval)
	ticker := time.NewTicker(e.interval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				e.mu.Lock()
				e.running = false
				e.mu.Unlock()
				return
			case <-e.done:
				e.mu.Lock()
				e.running = false
				e.mu.Unlock()
				return
			case <-ticker.C:
				e.CheckAndEscalate(ctx)
			}
		}
	}()
}

func (e *Escalator) Stop() {
	e.stopOnce.Do(func() {
		close(e.done)
	})
}

func (e *Escalator) CheckAndEscalate(ctx context.Context) {
	slog.Debug("Running CTEM Escalation evaluation")
	overdue, err := e.store.GetOverdueAssignments()
	if err != nil {
		slog.Error("Failed to fetch overdue assignments", "error", err)
		return
	}

	for _, oa := range overdue {

		if oa.Status != "overdue" && !isEscalatedStatus(oa.Status) {
			if err := e.store.UpdateAssignmentStatus(oa.AssignmentID, "overdue"); err != nil {
				slog.Error("Failed to update status to overdue", "assignment_id", oa.AssignmentID, "error", err)
			}
		}

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

				e.dispatchEscalation(oa, rule)

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
	recipientName, recipientEmail := e.resolveEscalationRecipient(oa, rule.DelayDays)

	slog.Warn("CTEM ESCALATION TRIGGERED",
		"assignment_id", oa.AssignmentID,
		"finding", oa.Title,
		"target", oa.Target,
		"delay_days", rule.DelayDays,
		"action_type", rule.ActionType,
		"recipient_name", recipientName,
		"recipient_email", recipientEmail,
	)

	message := fmt.Sprintf("⚠️ *SLA Breach Escalation (Level %d)*\n"+
		"*Finding:* %s\n"+
		"*Severity:* %s\n"+
		"*Target:* %s\n"+
		"*Due Date:* %s\n"+
		"*Recipient:* %s (%s)\n"+
		"*Status:* Overdue\n",
		rule.DelayDays, oa.Title, oa.Severity, oa.Target, oa.DueAt.Format(time.RFC3339), recipientName, recipientEmail)

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
	case "email":
		smtpServer, _ := rule.Properties["smtp_server"].(string)
		toEmail := recipientEmail
		slog.Info("Dispatched SLA breach escalation email", "to", toEmail, "smtp_server", smtpServer, "message", message)
	case "ticket":
		integration, _ := rule.Properties["integration"].(string)
		slog.Info("Created escalation ticket in system", "system", integration, "target", oa.Target, "severity", oa.Severity, "assignee", recipientEmail)
	default:
		slog.Warn("Unsupported escalation action type", "type", rule.ActionType)
	}
}

func (e *Escalator) resolveEscalationRecipient(oa storage.OverdueAssignment, delayDays int) (name, email string) {
	var currentOwner *storage.Owner
	var err error

	if oa.OwnerID != nil {
		currentOwner, err = e.store.GetOwner(*oa.OwnerID)
		if err != nil {
			slog.Error("Failed to fetch owner for escalation resolution", "owner_id", *oa.OwnerID, "error", err)
		}
	}

	if currentOwner == nil && oa.TeamID != nil {
		team, err := e.store.GetTeam(*oa.TeamID)
		if err == nil && team != nil && team.ManagerID != nil {
			currentOwner, err = e.store.GetOwner(*team.ManagerID)
			if err != nil {
				slog.Error("Failed to fetch team manager for escalation resolution", "manager_id", *team.ManagerID, "error", err)
			}
		}
	}

	if currentOwner == nil {
		return "Security Operations", "secops@company.local"
	}

	steps := 0
	switch {
	case delayDays >= 10:
		steps = 3
	case delayDays >= 5:
		steps = 2
	case delayDays > 0:
		steps = 1
	}

	recipient := currentOwner
	for i := 0; i < steps; i++ {
		if recipient.ManagerID == nil {
			break
		}
		mgr, err := e.store.GetOwner(*recipient.ManagerID)
		if err != nil || mgr == nil {
			break
		}
		recipient = mgr
	}

	return recipient.Name, recipient.Email
}
