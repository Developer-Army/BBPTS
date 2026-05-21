// Package ui provides user interface components
package tui

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// TargetInputChan is used to send targets from TUI to the orchestrator.
var TargetInputChan = make(chan []string, 1)

// TargetModeChan is used to send selected scan mode from TUI to the orchestrator.
var TargetModeChan = make(chan string, 1)

// ScanAbortChan is used to signal scan interruption from TUI.
var ScanAbortChan = make(chan struct{}, 1)

// PromptForTargetMsg triggers target entry prompt in the TUI.
type PromptForTargetMsg struct{}

// InitialTargetsMsg notifies the TUI of the target list to scan.
type InitialTargetsMsg []string

// StageToolsMsg lists the tools for the current stage.
type StageToolsMsg struct {
	Stage int
	Tools []string
}

// ThreadCountMsg notifies the TUI of the thread configuration.
type ThreadCountMsg struct {
	Active int
	Max    int
}

// RateLimitMsg notifies the TUI of the requests per second rate limit.
type RateLimitMsg struct {
	RateLimit int
}

// Bridge acts as a connector between the CLI logic and the TUI.
type Bridge struct {
	Program *tea.Program
}

// NewBridge creates a new TUI bridge.
func NewBridge(p *tea.Program) *Bridge {
	return &Bridge{Program: p}
}

// PromptForTarget requests the TUI to prompt the user for target entry.
func (b *Bridge) PromptForTarget() {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(PromptForTargetMsg{})
}

// SendInitialTargets sends the initial target list to the TUI.
func (b *Bridge) SendInitialTargets(targets []string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(InitialTargetsMsg(targets))
}

// ReportStageTools reports the tool list for the stage.
func (b *Bridge) ReportStageTools(stage int, tools []string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(StageToolsMsg{
		Stage: stage,
		Tools: tools,
	})
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
func (b *Bridge) SendEvent(source, target, eventType string, properties map[string]string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(EventFoundMsg{
		Source:     source,
		Target:     target,
		Type:       eventType,
		Properties: properties,
	})
}

// ReportEvent streams a live discovery into the TUI.
func (b *Bridge) ReportEvent(source, target, eventType string, properties map[string]string) {
	b.SendEvent(source, target, eventType, properties)
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

// SendThreadCount sends the actual active and max threads to the TUI.
func (b *Bridge) SendThreadCount(active, max int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(ThreadCountMsg{
		Active: active,
		Max:    max,
	})
}

// SendRateLimit sends the configured rate limit to the TUI.
func (b *Bridge) SendRateLimit(rateLimit int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(RateLimitMsg{
		RateLimit: rateLimit,
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
		var errVal string
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "error" || a.Key == "err" {
				errVal = fmt.Sprintf("%v", a.Value)
			}
			return true
		})
		if errVal != "" {
			msg = fmt.Sprintf("%s (error: %s)", msg, errVal)
		}
		
		component := "Scanner"
		var threadID string
		var toolName string
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "thread" || a.Key == "thread_id" {
				threadID = fmt.Sprintf("Thread-%v", a.Value)
			} else if a.Key == "tool" || a.Key == "tool_name" {
				toolName = fmt.Sprintf("%v", a.Value)
			}
			return true
		})

		if threadID != "" {
			component = threadID
		} else if toolName != "" {
			component = formatComponent(toolName)
		}

		levelStr := r.Level.String()
		if levelStr == "ERROR" {
			levelStr = "WARN"
		}
		if strings.Contains(strings.ToLower(msg), "vuln") || strings.Contains(strings.ToLower(msg), "cve-") {
			levelStr = "VULN"
		}

		h.Program.Send(LogMsg{
			Timestamp: r.Time.Format("15:04:05"),
			Level:     levelStr,
			Component: component,
			Message:   msg,
		})
		return nil // suppress default output
	}
	// Fallback to original handler when TUI is not running
	return h.Handler.Handle(ctx, r)
}

func formatComponent(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return "Scanner"
	}
	switch strings.ToLower(toolName) {
	case "naabu", "nmap":
		return "PortScan"
	case "httpx":
		return "HTTPX"
	case "dnsx":
		return "DNS"
	case "nuclei":
		return "Scanner"
	default:
		// Capitalize first letter
		runes := []rune(toolName)
		runes[0] = rune(strings.ToUpper(string(runes[0]))[0])
		return string(runes)
	}
}
