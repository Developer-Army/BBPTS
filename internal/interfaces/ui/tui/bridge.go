// Package ui provides user interface components
package tui

import (
	"context"
	"fmt"
	"log/slog"

	tea "github.com/charmbracelet/bubbletea"
)

// Bridge acts as a connector between the CLI logic and the TUI.
type Bridge struct {
	Program *tea.Program
}

// NewBridge creates a new TUI bridge.
func NewBridge(p *tea.Program) *Bridge {
	return &Bridge{Program: p}
}

// ReportStage implements recon.ProgressReporter.
func (b *Bridge) ReportStage(stage int, tools int, targets int, complete bool) {
	b.SendStageUpdate(stage, tools, targets, complete)
}

// SendStageUpdate sends a pipeline stage update to the TUI.
func (b *Bridge) SendStageUpdate(stage int, tools int, targets int, complete bool) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(StageUpdateMsg{
		Stage:    stage,
		Tools:    tools,
		Targets:  targets,
		Complete: complete,
	})
}

// SendEvent sends a discovery event to the TUI.
func (b *Bridge) SendEvent(source, target string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(EventFoundMsg{
		Source: source,
		Target: target,
	})
}

// ReportEvent streams a live discovery into the TUI.
func (b *Bridge) ReportEvent(source, target string) {
	b.SendEvent(source, target)
}

// SendInsight sends a prioritized insight to the TUI.
func (b *Bridge) SendInsight(host string, priority string, score int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(InsightMsg{
		Host:     host,
		Priority: priority,
		Score:    score,
	})
}

// SendRuleMatch sends a rule engine match to the TUI.
func (b *Bridge) SendRuleMatch(ruleID, priority, target string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(RuleMatchMsg{
		RuleID:   ruleID,
		Priority: priority,
		Target:   target,
	})
}

// ReportToolStatus streams tool lifecycle updates into the TUI.
func (b *Bridge) ReportToolStatus(tool, status, detail string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(ToolStatusMsg{
		Tool:   tool,
		Status: status,
		Detail: detail,
	})
}

// ReportFailure streams tool failures into the TUI.
func (b *Bridge) ReportFailure(tool, detail string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(FailureMsg{
		Tool:   tool,
		Detail: detail,
	})
}

// CompleteSession requests a graceful shutdown of the TUI once scan is done.
func (b *Bridge) CompleteSession() {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(SessionCompleteMsg{})
}

// LogHandler is a custom slog.Handler that redirects logs to the TUI.
type LogHandler struct {
	slog.Handler
	Program *tea.Program
}

func (h *LogHandler) Handle(ctx context.Context, r slog.Record) error {
	// Only forward logs when the TUI program is active
	if h.Program != nil {
		msg := r.Message
		r.Attrs(func(a slog.Attr) bool {
			msg = fmt.Sprintf("%s %s=%v", msg, a.Key, a.Value)
			return true
		})
		h.Program.Send(LogMsg(msg))
		return nil // suppress default output
	}
	// Fallback to original handler when TUI is not running
	return h.Handler.Handle(ctx, r)
}
