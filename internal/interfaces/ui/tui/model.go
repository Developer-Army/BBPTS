// Package ui provides user interface components
package tui

import (
	"fmt"
	"strings"

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

type SessionCompleteMsg struct{}

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

	// Scroll state for history
	scrollOffset int

	// Progress tracking for more accurate estimation.
	stageToolPlan    map[int]int
	stageCompletions map[int]map[string]struct{}
	lastToolStage    int
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
		spinner:          s,
		progress:         p,
		insightTable:     t,
		failures:         make([]FailureMsg, 0, 4),
		logs:             make([]string, 0),
		width:            80, // Default width
		height:           24, // Default height
		stageToolPlan:    make(map[int]int),
		stageCompletions: make(map[int]map[string]struct{}),
		lastToolStage:    -1,
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
		m.lastToolStage = msg.Stage
		if msg.Tools > 0 {
			m.stageToolPlan[msg.Stage] = msg.Tools
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
		// Keep more log entries for scrollable history
		if len(m.logs) > 50 {
			m.logs = m.logs[len(m.logs)-50:]
		}
		return m, nil

	case ToolStatusMsg:
		m.lastTool = msg
		if msg.Status == "done" {
			stage := m.lastToolStage
			if stage < 0 {
				stage = m.currentStage
			}
			if m.stageCompletions[stage] == nil {
				m.stageCompletions[stage] = make(map[string]struct{})
			}
			toolKey := strings.ToLower(strings.TrimSpace(msg.Tool))
			m.stageCompletions[stage][toolKey] = struct{}{}
		}
		return m, nil

	case FailureMsg:
		m.failures = append(m.failures, msg)
		if len(m.failures) > 3 {
			m.failures = m.failures[1:]
		}
		return m, nil

	case SessionCompleteMsg:
		m.quitting = true
		return m, tea.Quit
	}

	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return StyleMain.Render("\n  " + StyleHigh.Render("BBPTS") + " Scan Session Terminated.\n\n")
	}

	// Calculate dimensions
	headerHeight := 3
	inputHeight := 3
	statusHeight := 1
	minChatHeight := 5
	availableHeight := m.height - headerHeight - inputHeight - statusHeight

	// Ensure minimum chat height
	chatHeight := availableHeight
	if chatHeight < minChatHeight {
		chatHeight = minChatHeight
	}

	// Build all content lines
	contentLines := m.buildContentLines()

	// Calculate scroll bounds
	maxScroll := len(contentLines) - chatHeight
	if maxScroll < 0 {
		maxScroll = 0
	}

	// Adjust scroll offset if needed
	if m.scrollOffset > maxScroll {
		m.scrollOffset = maxScroll
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}

	// Determine visible lines
	start := m.scrollOffset
	end := start + chatHeight
	if end > len(contentLines) {
		end = len(contentLines)
	}

	visibleLines := contentLines
	if len(contentLines) > chatHeight {
		visibleLines = contentLines[start:end]
	}

	var b strings.Builder

	// --- Header ---
	b.WriteString(StyleHeader.Width(m.width-2).Render("🤖 BBPTS - Bug Bounty Program Tool Set v2.0") + "\n")

	// Display current stage info
	completedStages := 0
	for _, stage := range m.stages {
		if stage.complete {
			completedStages++
		}
	}
	s := m.stages[m.currentStage]
	stageNumber := m.currentStage + 1
	if stageNumber < 1 {
		stageNumber = 1
	}
	if stageNumber > totalStages {
		stageNumber = totalStages
	}

	stageInfo := fmt.Sprintf("Stage %d/%d | Tools: %d | Targets: %d", stageNumber, totalStages, s.tools, s.targets)
	b.WriteString(StyleStatusLine.Width(m.width-2).Render(stageInfo) + "\n")
	b.WriteString(strings.Repeat("─", m.width-2) + "\n")

	// --- Main Content Area ---
	for _, line := range visibleLines {
		b.WriteString(" " + line + "\n")
	}

	// Add padding if needed
	for i := len(visibleLines); i < chatHeight; i++ {
		b.WriteString(" \n")
	}

	// --- Scroll Indicators ---
	if m.scrollOffset > 0 {
		b.WriteString(fmt.Sprintf("\033[1;33m↑ %d more\033[0m\n", m.scrollOffset))
	} else {
		b.WriteString("\n")
	}

	if len(contentLines) > m.scrollOffset+chatHeight {
		b.WriteString(fmt.Sprintf("\033[1;33m↓ %d more\033[0m\n", len(contentLines)-(m.scrollOffset+chatHeight)))
	} else {
		b.WriteString("\n")
	}

	// --- Input Row ---
	b.WriteString(strings.Repeat("─", m.width-2) + "\n")
	b.WriteString(StyleKey.Render("> ") + m.spinner.View() + " " + StyleComment.Render("Scanning in progress...") + "\n")
	b.WriteString(strings.Repeat("─", m.width-2) + "\n")

	// --- Status Bar ---
	statusText := fmt.Sprintf(" EVENTS: %d  INSIGHTS: %d  CRITICAL: %d",
		m.eventsFound, len(m.insights), countCritical(m.ruleMatches))
	b.WriteString(StyleStatusLine.Width(m.width - 2).Render(statusText))

	return StyleMain.Render(b.String())
}

// buildContentLines creates all content lines for the chat area
func (m Model) buildContentLines() []string {
	var lines []string

	// Add progress bar with tool-level completion when available.
	progressValue := m.calculateProgress()

	// Create a simple progress bar visualization
	progressWidth := 50
	if progressWidth > m.width-10 {
		progressWidth = m.width - 10
	}
	filled := int(progressValue * float64(progressWidth))
	progressBar := strings.Repeat("█", filled) + strings.Repeat("░", progressWidth-filled)
	lines = append(lines, fmt.Sprintf("Progress: [%s] %.0f%%", progressBar, progressValue*100))
	lines = append(lines, "")

	// Add current tool activity
	if m.lastTool.Tool != "" {
		toolName := strings.ToUpper(formatToolName(m.lastTool.Tool))
		if m.lastTool.Status == "running" {
			lines = append(lines, StylePulse.Render("»")+" "+StyleKey.Render(toolName)+" is active")
			target := truncateTarget(m.lastEvent.Target, m.width-15)
			if target == "" {
				target = "awaiting data stream..."
			}
			lines = append(lines, "  "+StyleComment.Render("→ "+target))
		} else if m.lastTool.Status == "done" {
			lines = append(lines, StyleGreen.Render("✓")+" "+StyleKey.Render(toolName)+" completed: "+StyleValue.Render(m.lastTool.Detail))
		}
	} else {
		lines = append(lines, StyleComment.Render("• System idle..."))
	}

	lines = append(lines, "")

	// Add recent logs
	if len(m.logs) > 0 {
		lines = append(lines, StyleTitle.Render("ACTIVITY LOG"))
		// Show last 10 logs
		startIdx := 0
		if len(m.logs) > 10 {
			startIdx = len(m.logs) - 10
		}
		for i := startIdx; i < len(m.logs); i++ {
			lines = append(lines, " "+StyleComment.Render("• "+truncateTarget(m.logs[i], m.width-15)))
		}
	}

	// Add failures if any
	if len(m.failures) > 0 {
		lines = append(lines, "")
		lastFailure := m.failures[len(m.failures)-1]
		lines = append(lines, StyleFailure.Render("ERROR")+" "+StyleValue.Render(formatToolName(lastFailure.Tool)+": "+truncateTarget(lastFailure.Detail, m.width-25)))
	}

	return lines
}

func (m Model) calculateProgress() float64 {
	totalPlannedTools := 0
	totalCompletedTools := 0

	for stage, planned := range m.stageToolPlan {
		if planned < 0 {
			continue
		}
		totalPlannedTools += planned
		if completed, ok := m.stageCompletions[stage]; ok {
			totalCompletedTools += len(completed)
		}
	}

	if totalPlannedTools > 0 {
		progress := float64(totalCompletedTools) / float64(totalPlannedTools)
		if progress < 0 {
			return 0
		}
		if progress > 1 {
			return 1
		}
		return progress
	}

	// Fallback for very early startup before tool plan is known.
	completedStages := 0
	for _, stage := range m.stages {
		if stage.complete {
			completedStages++
		}
	}
	return float64(completedStages) / float64(totalStages)
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
