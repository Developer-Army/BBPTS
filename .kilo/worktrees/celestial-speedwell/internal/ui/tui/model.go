// Package tui — model.go implements the main state machine for the BBPTS
// elite dashboard using the Bubble Tea framework.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Messages ---

type StageUpdateMsg struct {
	Stage    int
	Tools    int
	Targets  int
	Complete bool
}

type EventFoundMsg struct {
	Source string
	Target string
}

type InsightMsg struct {
	Host     string
	Priority string
	Score    int
}

type RuleMatchMsg struct {
	RuleID   string
	Priority string
	Target   string
}

type LogMsg string

type ToolStatusMsg struct {
	Tool   string
	Status string
	Detail string
}

type FailureMsg struct {
	Tool   string
	Detail string
}

// --- Model Definition ---

type Model struct {
	// State
	currentStage int
	stages       [7]stageInfo
	eventsFound  int
	insights     []InsightMsg
	ruleMatches  []RuleMatchMsg
	lastEvent    EventFoundMsg
	lastTool     ToolStatusMsg
	failures     []FailureMsg
	logs         []string

	// Components
	spinner      spinner.Model
	progress     progress.Model
	insightTable table.Model

	// UI State
	width    int
	height   int
	quitting bool
}

type stageInfo struct {
	active   bool
	tools    int
	targets  int
	complete bool
}

const totalStages = 7

func NewModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(ColorPink)

	p := progress.New(progress.WithDefaultGradient())

	columns := []table.Column{
		{Title: "Host", Width: 30},
		{Title: "Priority", Width: 10},
		{Title: "Score", Width: 5},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(7),
	)

	return Model{
		spinner:      s,
		progress:     p,
		insightTable: t,
		failures:     make([]FailureMsg, 0, 4),
		logs:         make([]string, 0),
		width:        80, // Default width
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = m.width - 20
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case StageUpdateMsg:
		m.currentStage = msg.Stage
		m.stages[msg.Stage] = stageInfo{
			active:   !msg.Complete,
			tools:    msg.Tools,
			targets:  msg.Targets,
			complete: msg.Complete,
		}
		return m, nil

	case EventFoundMsg:
		m.eventsFound++
		m.lastEvent = msg
		return m, nil

	case InsightMsg:
		m.insights = append(m.insights, msg)
		// Update table rows
		rows := make([]table.Row, len(m.insights))
		for i, insight := range m.insights {
			rows[i] = table.Row{insight.Host, insight.Priority, fmt.Sprintf("%d", insight.Score)}
		}
		m.insightTable.SetRows(rows)
		return m, nil

	case RuleMatchMsg:
		m.ruleMatches = append(m.ruleMatches, msg)
		return m, nil

	case LogMsg:
		m.logs = append(m.logs, string(msg))
		if len(m.logs) > 8 {
			m.logs = m.logs[1:]
		}
		return m, nil

	case ToolStatusMsg:
		m.lastTool = msg
		return m, nil

	case FailureMsg:
		m.failures = append(m.failures, msg)
		if len(m.failures) > 3 {
			m.failures = m.failures[1:]
		}
		return m, nil
	}

	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return StyleMain.Render("\n  " + StyleHigh.Render("BBPTS") + " Scan Session Terminated.\n\n")
	}

	var b strings.Builder

	// --- Header (Premium Branding) ---
	b.WriteString(StylePurple.Render(LogoBBPTS) + "\n")

	// --- Progress Calculations ---
	completedStages := 0
	for _, stage := range m.stages {
		if stage.complete {
			completedStages++
		}
	}
	progressValue := float64(completedStages) / float64(totalStages)
	s := m.stages[m.currentStage]
	stageNumber := m.currentStage + 1
	if stageNumber < 1 {
		stageNumber = 1
	}
	if stageNumber > totalStages {
		stageNumber = totalStages
	}

	// --- Primary Status Box ---
	statusLine := fmt.Sprintf(" %s Stage %d/%d | Tools: %d | Targets: %d",
		m.spinner.View(), stageNumber, totalStages, s.tools, s.targets)

	b.WriteString(StyleBorder.Width(m.width-4).Render(
		StyleStatusLine.Width(m.width-8).Render(statusLine)+"\n"+
			m.progress.ViewAs(progressValue),
	) + "\n\n")

	// --- Live Tool Activity ---
	if m.lastTool.Tool != "" {
		toolName := strings.ToUpper(formatToolName(m.lastTool.Tool))
		if m.lastTool.Status == "running" {
			b.WriteString(" " + StylePulse.Render("»") + " " + StyleKey.Render(toolName) + " is active\n")
			target := truncateTarget(m.lastEvent.Target, m.width-10)
			if target == "" {
				target = "awaiting data stream..."
			}
			b.WriteString("   " + StyleComment.Render("→ "+target) + "\n")
		} else if m.lastTool.Status == "done" {
			b.WriteString(" " + StyleGreen.Render("✓") + " " + StyleKey.Render(toolName) + " completed: " + StyleValue.Render(m.lastTool.Detail) + "\n")
		}
	} else {
		b.WriteString(" " + StyleComment.Render("• System idle...") + "\n")
	}

	// --- Real-time Metrics ---
	metrics := fmt.Sprintf("\n %s %d  %s %d  %s %d",
		StyleKey.Render("EVENTS:"), m.eventsFound,
		StyleKey.Render("INSIGHTS:"), len(m.insights),
		StyleKey.Render("CRITICAL:"), countCritical(m.ruleMatches))
	b.WriteString(metrics + "\n")

	// --- Activity Feed ---
	if len(m.logs) > 0 {
		b.WriteString("\n" + StyleTitle.Render(" ACTIVITY LOG") + "\n")
		for _, l := range m.logs {
			b.WriteString(" " + StyleComment.Render("• "+truncateTarget(l, m.width-10)) + "\n")
		}
	}

	// --- Error Notification ---
	if len(m.failures) > 0 {
		lastFailure := m.failures[len(m.failures)-1]
		b.WriteString("\n" + StyleFailure.Render(" ERROR ") + " " + StyleValue.Render(formatToolName(lastFailure.Tool)+": "+truncateTarget(lastFailure.Detail, m.width-20)) + "\n")
	}

	// --- Footer ---
	footer := fmt.Sprintf("\n %s | %s | press 'q' to quit",
		time.Now().Format("15:04:05 MST"),
		StylePurple.Render("v2.0-ELITE"))
	b.WriteString(StyleComment.Render(footer))

	return StyleMain.Render(b.String())
}

func countCritical(matches []RuleMatchMsg) int {
	count := 0
	for _, m := range matches {
		if m.Priority == "critical" {
			count++
		}
	}
	return count
}

func formatToolName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "waiting"
	}
	return name
}

func truncateTarget(value string, width int) string {
	if width < 8 || len(value) <= width {
		return value
	}
	return value[:width-3] + "..."
}
