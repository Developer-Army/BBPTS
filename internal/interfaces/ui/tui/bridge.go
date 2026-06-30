// Package ui provides user interface components
package tui

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

var TargetInputChan = make(chan []string, 1)

var TargetModeChan = make(chan string, 1)

var ScanAbortChan = make(chan struct{}, 1)

type PromptForTargetMsg struct{}

type InitialTargetsMsg []string

type StageToolsMsg struct {
	Stage int
	Tools []string
}

type ThreadCountMsg struct {
	Active int
	Max    int
}

type RateLimitMsg struct {
	RateLimit int
}

type PortScannedMsg struct{ Count int }

type RequestRateMsg struct{ Rate int }

type ToolProgressMsg struct {
	Tool  string
	Done  int
	Total int
}

type Bridge struct {
	Program *tea.Program
}

func NewBridge(p *tea.Program) *Bridge {
	return &Bridge{Program: p}
}

func (b *Bridge) PromptForTarget() {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(PromptForTargetMsg{})
}

func (b *Bridge) SendInitialTargets(targets []string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(InitialTargetsMsg(targets))
}

func (b *Bridge) ReportStageTools(stage int, tools []string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(StageToolsMsg{
		Stage: stage,
		Tools: tools,
	})
}

func (b *Bridge) ReportStage(stage int, tools int, targets int, complete bool) {
	b.SendStageUpdate(stage, tools, targets, complete)
}

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

func (b *Bridge) ReportEvent(source, target, eventType string, properties map[string]string) {
	b.SendEvent(source, target, eventType, properties)
}

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

func (b *Bridge) ReportFailure(tool, detail string) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(FailureMsg{
		Tool:   tool,
		Detail: detail,
	})
}

func (b *Bridge) SendThreadCount(active, max int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(ThreadCountMsg{
		Active: active,
		Max:    max,
	})
}

func (b *Bridge) SendRateLimit(rateLimit int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(RateLimitMsg{
		RateLimit: rateLimit,
	})
}

func (b *Bridge) SendPortsScanned(count int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(PortScannedMsg{Count: count})
}

func (b *Bridge) SendRequestRate(rate int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(RequestRateMsg{Rate: rate})
}

func (b *Bridge) ReportToolProgress(tool string, done, total int) {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(ToolProgressMsg{Tool: tool, Done: done, Total: total})
}

func (b *Bridge) CompleteSession() {
	if b == nil || b.Program == nil {
		return
	}
	b.Program.Send(SessionCompleteMsg{})
}

type LogHandler struct {
	slog.Handler
	Program *tea.Program
}

func (h *LogHandler) Handle(ctx context.Context, r slog.Record) error {

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
			switch a.Key {
			case "thread", "thread_id":
				threadID = fmt.Sprintf("Thread-%v", a.Value)
			case "tool", "tool_name":
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
		return nil
	}

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

		runes := []rune(toolName)
		runes[0] = rune(strings.ToUpper(string(runes[0]))[0])
		return string(runes)
	}
}
