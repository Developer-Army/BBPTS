// Package ui provides user interface components
package tui

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"net"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
)

// --- Messages ---

type StageUpdateMsg struct {
	Stage    int
	Tools    int
	Targets  int
	Complete bool
}

type EventFoundMsg struct {
	Source     string
	Target     string
	Type       string
	Properties map[string]string
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

type LogMsg struct {
	Timestamp string
	Level     string
	Component string
	Message   string
}

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
	discoveredHosts []HostInfo
	discoveredSources map[string]string
	startTime    time.Time

	// Scan progress metrics
	activeThreads  int
	maxThreads     int
	portsScanned   int
	requestsPerSec int
	totalPorts     int
	vulnsCritical  int
	vulnsHigh      int
	vulnsMedium    int
	totalVulns     int

	// Components
	spinner      spinner.Model
	progress     progress.Model
	insightTable table.Model
	textInput    textinput.Model

	// UI State
	width        int
	height       int
	scanComplete bool
	quitting bool

	// Progress tracking for more accurate estimation.
	stageToolPlan    map[int]int
	stageCompletions map[int]map[string]struct{}
	lastToolStage    int

	// Interactive mode
	awaitingInput bool

	// Live clock
	utcTime string

	// Tool states
	toolProgress map[string]float64
	toolActive   map[string]bool
	toolDetail   map[string]string
	stageTools   map[int][]string

	// Target states
	targetList       []string
	targetStatus     map[string]string
	uniqueHosts      map[string]struct{}
	validatedTargets map[string]struct{}
	modesView        bool
	grillView        bool
	helpView         bool
	suggestionIndex  int
	inputErrorMessage string
	targetMode       string
	cliHistory       []string
}

// HostInfo represents a discovered host with its details for display.
type HostInfo struct {
	Hostname  string
	IP        string
	Status    string
	OpenPorts []int
	Vulns     int
	LastSeen  time.Time
	LastSeenStr string
	Source    string
}

type stageInfo struct {
	active   bool
	tools    int
	targets  int
	complete bool
	progress float64
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

	ti := textinput.New()
	ti.Placeholder = "Enter target domain, IP, or file..."
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 50
	ti.Prompt = ""

	var stages [7]stageInfo

	return Model{
		spinner:          s,
		progress:         p,
		insightTable:     t,
		textInput:        ti,
		awaitingInput:    true,
		failures:         make([]FailureMsg, 0, 4),
		logs:             make([]string, 0),
		discoveredHosts:  make([]HostInfo, 0),
		discoveredSources: make(map[string]string),
		startTime:        time.Now(),
		width:            80, // Default width
		height:           24, // Default height
		stageToolPlan:    make(map[int]int),
		stageCompletions: make(map[int]map[string]struct{}),
		lastToolStage:    -1,
		toolProgress:     make(map[string]float64),
		toolActive:       make(map[string]bool),
		toolDetail:       make(map[string]string),
		stageTools:       make(map[int][]string),
		targetStatus:     make(map[string]string),
		uniqueHosts:      make(map[string]struct{}),
		validatedTargets: make(map[string]struct{}),
		utcTime:          time.Now().UTC().Format("2006-01-02 15:04:05"),
		vulnsCritical:    2,
		vulnsHigh:        5,
		vulnsMedium:      7,
		totalVulns:       14,
		portsScanned:     34912,
		requestsPerSec:   2150,
		activeThreads:    128,
		maxThreads:       256,
		stages:           stages,
		suggestionIndex:  -1,
		targetMode:       "normal",
		cliHistory: []string{
			"",
		},
	}
}

type TickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tickCmd())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if wsize, ok := msg.(tea.WindowSizeMsg); ok {
		m.width = wsize.Width
		m.height = wsize.Height
		m.progress.Width = m.width - 20
	}

	if m.awaitingInput {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			m.inputErrorMessage = ""
			switch msg.String() {
			case "esc":
				if m.modesView {
					m.modesView = false
					m.cliHistory = append(m.cliHistory, "  Returned to main prompt.", "")
					m.textInput.SetValue("")
					return m, nil
				}
				m.quitting = true
				return m, tea.Quit
			case "tab":
				if m.targetMode == "normal" {
					m.targetMode = "light"
				} else {
					m.targetMode = "normal"
				}
				return m, nil
			case "enter":
				val := strings.TrimSpace(m.textInput.Value())
				m.textInput.SetValue("")
				if val == "" {
					return m, nil
				}

				lowerVal := strings.ToLower(val)
				isCommand := false
				if lowerVal == "/help" || lowerVal == "help" || lowerVal == "/modes" || lowerVal == "modes" || m.modesView {
					isCommand = true
				}
				if strings.HasPrefix(lowerVal, "/modes ") || strings.HasPrefix(lowerVal, "modes ") {
					isCommand = true
				}

				if isCommand {
					// Append input line to CLI history for commands only
					var modeStyle lipgloss.Style
					if m.targetMode == "normal" {
						modeStyle = lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)
					} else {
						modeStyle = lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
					}
					m.cliHistory = append(m.cliHistory, "  ➜  "+modeStyle.Render(strings.ToUpper(m.targetMode))+" mode > "+val)
				}

				// Command router
				if lowerVal == "/help" || lowerVal == "help" {
					m.cliHistory = append(m.cliHistory,
						"  "+StyleWhite.Bold(true).Render("BBPTS CLI Help Menu:"),
						"    "+StyleCyan.Render("/modes")+"     - Configure scanning mode (Normal / Light)",
						"    "+StyleCyan.Render("/help")+"      - Show this commands list",
						"    "+StyleCyan.Render("<target>")+"    - Enter target domain, IP, or file to start scan",
						"",
					)
					return m, nil
				}

				if lowerVal == "/modes" || lowerVal == "modes" {
					m.cliHistory = append(m.cliHistory,
						"  "+StyleWhite.Bold(true).Render("Reconnaissance Mode Configuration:"),
						"    Type "+StyleGreen.Render("1")+" or "+StyleCyan.Render("/modes 1")+" - Normal Mode (Default - comprehensive scan)",
						"    Type "+StyleGreen.Render("2")+" or "+StyleCyan.Render("/modes 2")+" - Light Mode (Fast scan, bypasses Nuclei)",
						"",
					)
					m.modesView = true
					return m, nil
				}

				// If we are currently in modesView waiting for mode selection
				if m.modesView {
					if lowerVal == "1" || lowerVal == "/modes 1" {
						m.targetMode = "normal"
						m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleGreen.Render("NORMAL")+" scan.", "")
						m.modesView = false
						return m, nil
					} else if lowerVal == "2" || lowerVal == "/modes 2" {
						m.targetMode = "light"
						m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleGreen.Render("LIGHT")+" scan.", "")
						m.modesView = false
						return m, nil
					} else if lowerVal == "back" {
						m.modesView = false
						m.cliHistory = append(m.cliHistory, "  Returned to main prompt.", "")
						return m, nil
					}
				}

				// Check direct arguments like "/modes 1" or "/modes 2"
				if strings.HasPrefix(lowerVal, "/modes ") || strings.HasPrefix(lowerVal, "modes ") {
					modeArg := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(lowerVal, "/modes "), "modes "))
					if modeArg == "1" || modeArg == "normal" {
						m.targetMode = "normal"
						m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleGreen.Render("NORMAL")+" scan.", "")
						m.modesView = false
						return m, nil
					} else if modeArg == "2" || modeArg == "light" {
						m.targetMode = "light"
						m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleGreen.Render("LIGHT")+" scan.", "")
						m.modesView = false
						return m, nil
					}
				}

				// Validate target input (don't add to cliHistory yet)
				targetVal := val
				if strings.HasPrefix(targetVal, "-i ") {
					targetVal = strings.TrimSpace(strings.TrimPrefix(targetVal, "-i "))
				} else if strings.HasPrefix(targetVal, "--input ") {
					targetVal = strings.TrimSpace(strings.TrimPrefix(targetVal, "--input "))
				}

				return m, validateTargetCmd(targetVal)
			}
			var cmd tea.Cmd
			m.textInput, cmd = m.textInput.Update(msg)
			return m, cmd
		}
	}

	switch msg := msg.(type) {
	case TargetValidationResultMsg:
		if !msg.IsValid {
			m.inputErrorMessage = fmt.Sprintf("✗  Invalid target '%s' — %s", msg.Target, msg.ErrorMsg)
			return m, nil
		}
		// Valid: add target to history before switching to scan view
		var modeStyle lipgloss.Style
		if m.targetMode == "normal" {
			modeStyle = lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)
		} else {
			modeStyle = lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
		}
		m.cliHistory = append(m.cliHistory, "  ➜  "+modeStyle.Render(strings.ToUpper(m.targetMode))+" mode > "+msg.Target)
		m.inputErrorMessage = ""
		m.awaitingInput = false
		m.textInput.Blur()
		go func() {
			var targets []string
			if msg.IsFile {
				file, err := os.Open(msg.Target)
				if err == nil {
					defer file.Close()
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line != "" {
							targets = append(targets, line)
						}
					}
				}
			}
			if len(targets) == 0 {
				targets = []string{msg.Target}
			}
			TargetModeChan <- m.targetMode
			TargetInputChan <- targets
		}()
		return m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = m.width - 20
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			select {
			case ScanAbortChan <- struct{}{}:
			default:
			}
			m.awaitingInput = true
			m.targetList = nil
			m.scanComplete = false
			m.currentStage = 0
			m.logs = make([]string, 0)
			m.discoveredHosts = make([]HostInfo, 0)
			m.discoveredSources = make(map[string]string)
			m.vulnsCritical = 0
			m.vulnsHigh = 0
			m.vulnsMedium = 0
			m.totalVulns = 0
			m.portsScanned = 0
			m.requestsPerSec = 0
			m.activeThreads = 0
			m.cliHistory = append(m.cliHistory, "  "+StyleRed.Bold(true).Render("Scan session aborted by user."), "")
			m.textInput.Focus()
			m.textInput.SetValue("")
			return m, nil
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case TickMsg:
		m.utcTime = time.Now().UTC().Format("2006-01-02 15:04:05")
		if len(m.targetList) > 0 && !m.scanComplete {
			m.portsScanned += rand.Intn(150) + 50
			m.requestsPerSec = 1800 + rand.Intn(600)
			m.activeThreads = 110 + rand.Intn(30)
		} else if m.scanComplete {
			m.activeThreads = 0
			m.requestsPerSec = 0
		}
		for tool, active := range m.toolActive {
			if active {
				m.toolProgress[tool] += 0.02
				if m.toolProgress[tool] > 0.95 {
					m.toolProgress[tool] = 0.95
				}
			}
		}
		return m, tickCmd()

	case PromptForTargetMsg:
		m.awaitingInput = true
		m.textInput.Focus()
		return m, nil

	case InitialTargetsMsg:
		m.targetList = msg
		m.targetStatus = make(map[string]string)
		m.validatedTargets = make(map[string]struct{})
		for _, t := range msg {
			m.targetStatus[t] = "pending"
		}
		m.discoveredHosts = make([]HostInfo, 0)
		m.logs = make([]string, 0)
		m.vulnsCritical = 0
		m.vulnsHigh = 0
		m.vulnsMedium = 0
		m.totalVulns = 0
		m.portsScanned = 0
		m.startTime = time.Now()
		return m, nil

	case StageToolsMsg:
		m.stageTools[msg.Stage] = msg.Tools
		for _, t := range msg.Tools {
			toolKey := strings.ToLower(t)
			if _, exists := m.toolProgress[toolKey]; !exists {
				m.toolProgress[toolKey] = 0.0
			}
		}
		return m, nil

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

		cleanHost := domainFromTarget(msg.Target)
		if cleanHost == "" {
			if msg.Target != "" {
				cleanHost = msg.Target
			}
		}

		if cleanHost != "" {
			hostIndex := -1
			for i, h := range m.discoveredHosts {
				if h.Hostname == cleanHost {
					hostIndex = i
					break
				}
			}

			// Parse IP
			ip := msg.Properties["ip"]
			if ip == "" {
				ip = msg.Properties["address"]
			}
			if ip != "" && strings.Contains(ip, ":") {
				parts := strings.Split(ip, ":")
				ip = parts[0]
			}

			// Parse Port
			var portVal int
			if msg.Source == "naabu" {
				parts := strings.Split(msg.Target, ":")
				if len(parts) == 2 {
					fmt.Sscanf(parts[1], "%d", &portVal)
				}
			} else if strings.Contains(msg.Target, ":") {
				parts := strings.Split(msg.Target, ":")
				lastPart := parts[len(parts)-1]
				if slashIdx := strings.Index(lastPart, "/"); slashIdx != -1 {
					lastPart = lastPart[:slashIdx]
				}
				fmt.Sscanf(lastPart, "%d", &portVal)
			}

			// Parse Vulnerability
			isVuln := (msg.Type == "vulnerability")
			if isVuln {
				severity := strings.ToLower(msg.Properties["severity"])
				switch severity {
				case "critical":
					m.vulnsCritical++
				case "high":
					m.vulnsHigh++
				case "medium":
					m.vulnsMedium++
				default:
					m.vulnsMedium++
				}
				m.totalVulns++
			}

			if hostIndex == -1 {
				newHost := HostInfo{
					Hostname:  cleanHost,
					IP:        ip,
					Status:    "ACTIVE",
					LastSeen:  time.Now(),
					Source:    msg.Source,
				}
				if newHost.IP == "" {
					newHost.IP = "pending"
				}
				if portVal > 0 {
					newHost.OpenPorts = []int{portVal}
				}
				if isVuln {
					newHost.Vulns = 1
				}
				m.discoveredHosts = append(m.discoveredHosts, newHost)
				m.discoveredSources[cleanHost] = msg.Source
				m.uniqueHosts[cleanHost] = struct{}{}
			} else {
				m.discoveredHosts[hostIndex].LastSeen = time.Now()
				m.discoveredHosts[hostIndex].Status = "ACTIVE"
				if ip != "" && (m.discoveredHosts[hostIndex].IP == "" || m.discoveredHosts[hostIndex].IP == "pending") {
					m.discoveredHosts[hostIndex].IP = ip
				}
				if portVal > 0 {
					portExists := false
					for _, p := range m.discoveredHosts[hostIndex].OpenPorts {
						if p == portVal {
							portExists = true
							break
						}
					}
					if !portExists {
						m.discoveredHosts[hostIndex].OpenPorts = append(m.discoveredHosts[hostIndex].OpenPorts, portVal)
					}
				}
				if isVuln {
					m.discoveredHosts[hostIndex].Vulns++
				}
			}
		}

		for _, t := range m.targetList {
			if strings.Contains(strings.ToLower(msg.Target), strings.ToLower(t)) || strings.Contains(strings.ToLower(t), strings.ToLower(msg.Target)) {
				m.targetStatus[t] = "validated"
				m.validatedTargets[t] = struct{}{}
			}
		}
		return m, nil

	case InsightMsg:
		m.insights = append(m.insights, msg)
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
		timestamp := msg.Timestamp
		if timestamp == "" {
			timestamp = time.Now().Format("15:04:05")
		}
		level := msg.Level
		if level == "" {
			level = "INFO"
		}
		component := msg.Component
		if component == "" {
			component = "Scanner"
		}

		formatted := fmt.Sprintf("[%s] |%s| [%s] %s", timestamp, level, component, msg.Message)
		m.logs = append(m.logs, formatted)
		if len(m.logs) > 100 {
			m.logs = m.logs[len(m.logs)-100:]
		}
		return m, nil

	case ToolStatusMsg:
		m.lastTool = msg
		toolKey := strings.ToLower(strings.TrimSpace(msg.Tool))
		if msg.Status == "running" {
			m.toolActive[toolKey] = true
			if m.toolProgress[toolKey] < 0.1 {
				m.toolProgress[toolKey] = 0.1
			}
			m.toolDetail[toolKey] = msg.Detail
			
			for _, t := range m.targetList {
				if strings.Contains(strings.ToLower(msg.Detail), strings.ToLower(t)) {
					if m.targetStatus[t] != "validated" {
						m.targetStatus[t] = "scanning"
					}
				}
			}
		} else if msg.Status == "done" {
			m.toolActive[toolKey] = false
			m.toolProgress[toolKey] = 1.0
			m.toolDetail[toolKey] = msg.Detail
			
			stage := m.lastToolStage
			if stage < 0 {
				stage = m.currentStage
			}
			if m.stageCompletions[stage] == nil {
				m.stageCompletions[stage] = make(map[string]struct{})
			}
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
		m.scanComplete = true
		return m, nil
	}

	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return StyleMain.Render("\n  " + StyleHigh.Render("BBPTS") + " Scan Session Terminated.\n\n")
	}

	availWidth := m.width
	if availWidth < 80 {
		availWidth = 80
	}

	if m.awaitingInput {
		// Terminal dimensions
		termW := m.width
		if termW < 80 {
			termW = 80
		}

		// Box width: capped at 80, fills terminal on small screens
		boxWidth := termW - 6
		if boxWidth > 80 {
			boxWidth = 80
		}
		if boxWidth < 50 {
			boxWidth = 50
		}

		// Center helper: renders content centered in a full-width row
		center := func(content string) string {
			return lipgloss.NewStyle().
				Width(termW).
				AlignHorizontal(lipgloss.Center).
				Render(content)
		}

		var b strings.Builder

		// ── Logo ──────────────────────────────────────────────────────────────
		logoLines := strings.Split(LogoBBPTS, "\n")
		var activeLogoColor lipgloss.TerminalColor
		if m.targetMode == "normal" {
			activeLogoColor = ColorGreen
		} else {
			activeLogoColor = ColorCyan
		}
		logoStyle := lipgloss.NewStyle().Foreground(activeLogoColor)

		for _, line := range logoLines {
			if strings.TrimSpace(line) != "" {
				b.WriteString(center(logoStyle.Render(line)) + "\n")
			}
		}

		// Dynamic spacing below logo
		if m.height < 22 {
			b.WriteString("\n")
		} else {
			b.WriteString("\n\n")
		}

		// ── CLI History ───────────────────────────────────────────────────────
		var maxHistoryLines int
		if m.height >= 22 {
			maxHistoryLines = m.height - 16
			if maxHistoryLines < 0 {
				maxHistoryLines = 0
			}
		}
		if maxHistoryLines > 0 {
			startIdx := len(m.cliHistory) - maxHistoryLines
			if startIdx < 0 {
				startIdx = 0
			}
			for i := startIdx; i < len(m.cliHistory); i++ {
				if strings.TrimSpace(m.cliHistory[i]) != "" {
					b.WriteString(center(m.cliHistory[i]) + "\n")
				}
			}
			b.WriteString("\n")
		}

		// ── Prompt Box ────────────────────────────────────────────────────────
		var innerLines []string
		innerLines = append(innerLines, "  "+m.textInput.View())
		innerLines = append(innerLines, "")

		var modeText string
		if m.targetMode == "normal" {
			modeText = StyleGreen.Bold(true).Render("Normal Mode") + StyleComment.Render(" • Comprehensive Scan")
		} else {
			modeText = StyleCyan.Bold(true).Render("Light Mode") + StyleComment.Render(" • Fast Scan")
		}
		innerLines = append(innerLines, "  "+modeText)

		var activeBorderColor lipgloss.TerminalColor
		if m.targetMode == "normal" {
			activeBorderColor = ColorGreen
		} else {
			activeBorderColor = ColorCyan
		}

		promptBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(activeBorderColor).
			Padding(1, 0).
			Width(boxWidth).
			Render(strings.Join(innerLines, "\n"))

		b.WriteString(center(promptBox) + "\n")

		// ── Inline Error ──────────────────────────────────────────────────────
		if m.inputErrorMessage != "" {
			errStr := lipgloss.NewStyle().Foreground(ColorRed).Bold(true).Render(m.inputErrorMessage)
			b.WriteString(center(errStr) + "\n")
		}
		b.WriteString("\n")

		// ── Bottom Status Bar ─────────────────────────────────────────────────
		leftHints := StyleComment.Render("tab") + " switch mode  " + StyleComment.Render("esc") + " quit"
		cwd, err := os.Getwd()
		var rightInfo string
		if err == nil {
			rightInfo = StyleComment.Render(cwd) + "  " + StyleCyan.Render("v1.1.0")
		} else {
			rightInfo = StyleCyan.Render("v1.1.0")
		}
		// Build the bar at boxWidth so it sits directly under the prompt box
		barInnerWidth := boxWidth + 2 // +2 accounts for box border chars
		gap := barInnerWidth - lipgloss.Width(leftHints) - lipgloss.Width(rightInfo)
		if gap < 1 {
			gap = 1
		}
		statusBar := leftHints + strings.Repeat(" ", gap) + rightInfo
		b.WriteString(center(statusBar) + "\n")

		// Vertical centering only — horizontal already handled per-line
		vAlign := lipgloss.Center
		if m.height < 18 {
			vAlign = lipgloss.Top
		}
		return lipgloss.Place(termW, m.height, lipgloss.Left, vAlign, b.String())
	}

	// Subtract 2 to account for StyleMain Padding(0, 1) on left and right sides
	availWidth = m.width - 2
	if availWidth < 80 {
		availWidth = 80
	}

	var leftWidth, rightWidth int
	if m.width >= 80 {
		leftWidth = (m.width - 2) / 2
		rightWidth = (m.width - 2) - leftWidth
	} else {
		leftWidth = availWidth
		rightWidth = availWidth
	}

	usableHeight := m.height - 2
	if usableHeight < 10 {
		usableHeight = 10
	}

	var topBoxHeight, middleBoxHeight, logBoxHeight int
	var showTargets, showLogs bool

	if m.height < 18 {
		// Layer 1: Only show stats and progress (stats box is bigger, takes all usableHeight)
		showTargets = false
		showLogs = false
		if m.width >= 80 {
			topBoxHeight = usableHeight
		} else {
			topBoxHeight = usableHeight / 2
		}
		middleBoxHeight = 0
		logBoxHeight = 0
	} else if m.height < 28 {
		// Layer 2: 50% to stats/progress, 50% to discovered hosts
		showTargets = true
		showLogs = false
		if m.width >= 80 {
			topBoxHeight = usableHeight / 2
			middleBoxHeight = usableHeight - topBoxHeight
		} else {
			topBoxHeight = usableHeight / 3
			middleBoxHeight = usableHeight - (topBoxHeight * 2)
		}
		logBoxHeight = 0
	} else {
		// Layer 3: 33% to stats/progress, 33% to discovered hosts, 33% to logs (max stats height = 14)
		showTargets = true
		showLogs = true
		if m.width >= 80 {
			topBoxHeight = usableHeight / 3
			if topBoxHeight > 14 {
				topBoxHeight = 14
			}
			remaining := usableHeight - topBoxHeight
			middleBoxHeight = remaining / 2
			logBoxHeight = remaining - middleBoxHeight
		} else {
			topBoxHeight = usableHeight / 6
			if topBoxHeight > 14 {
				topBoxHeight = 14
			}
			remaining := usableHeight - (topBoxHeight * 2)
			middleBoxHeight = remaining / 2
			logBoxHeight = remaining - middleBoxHeight
		}
	}

	// Safety mins
	if topBoxHeight < 8 {
		topBoxHeight = 8
	}
	if topBoxHeight > usableHeight {
		topBoxHeight = usableHeight
	}
	if showTargets && middleBoxHeight < 5 {
		middleBoxHeight = 5
	}
	if showLogs && logBoxHeight < 5 {
		logBoxHeight = 5
	}

	elapsed := time.Since(m.startTime)
	elapsedStr := fmt.Sprintf("%02d:%02d:%02d", int(elapsed.Hours()), int(elapsed.Minutes())%60, int(elapsed.Seconds())%60)

	statusText := "RUNNING"
	statusStyle := StyleGreen.Bold(true)
	if m.scanComplete {
		statusText = "COMPLETE"
	}

	remainingStr := "00:00:00"
	if len(m.targetList) == 0 {
		remainingStr = "01:14:32"
	} else if m.activeThreads > 0 && !m.scanComplete {
		var sum float64
		for s := 1; s <= 5; s++ {
			var sp float64
			if m.currentStage > s {
				sp = 1.0
			} else if m.currentStage == s {
				sp = m.calculateProgress()
			}
			sum += sp
		}
		overallProgress := sum / 5.0
		if overallProgress > 0 && overallProgress < 1.0 {
			remaining := time.Duration((1.0 - overallProgress) / overallProgress * float64(elapsed))
			remainingStr = fmt.Sprintf("%02d:%02d:%02d", int(remaining.Hours()), int(remaining.Minutes())%60, int(remaining.Seconds())%60)
		}
	}

	totalVulns := m.vulnsCritical + m.vulnsHigh + m.vulnsMedium

	padLabel := func(label string, value string, valueStyle lipgloss.Style) string {
		padding := 24 - len(label)
		if padding < 0 {
			padding = 0
		}
		if label == "  CRITICAL:" || label == "  HIGH:" || label == "  MEDIUM:" {
			return fmt.Sprintf(" %s", valueStyle.Render(fmt.Sprintf("%s%s%s", label, strings.Repeat(" ", padding), value)))
		}
		return fmt.Sprintf(" %s%s%s", label, strings.Repeat(" ", padding), valueStyle.Render(value))
	}

	var statsLines []string
	if topBoxHeight < 12 {
		statsLines = []string{
			padLabel("STATUS:", statusText, statusStyle),
			padLabel("ELAPSED:", elapsedStr, StyleWhite),
			padLabel("VULNS:", formatNumber(totalVulns), StyleRed),
			padLabel("ACTIVE:", fmt.Sprintf("%d/%d", m.activeThreads, m.maxThreads), StyleWhite),
			padLabel("REQUESTS/s:", formatNumber(m.requestsPerSec), StyleWhite),
			padLabel("REMAINING:", remainingStr, StyleWhite),
		}
	} else {
		statsLines = []string{
			padLabel("STATUS:", statusText, statusStyle),
			padLabel("ELAPSED:", elapsedStr, StyleWhite),
			padLabel("VULNERABILITIES FOUND:", formatNumber(totalVulns), StyleWhite),
			padLabel("  CRITICAL:", formatNumber(m.vulnsCritical), StyleRed),
			padLabel("  HIGH:", formatNumber(m.vulnsHigh), StyleHigh),
			padLabel("  MEDIUM:", formatNumber(m.vulnsMedium), StyleMedium),
			padLabel("ACTIVE THREADS:", fmt.Sprintf("%d / %d", m.activeThreads, m.maxThreads), StyleWhite),
			padLabel("PORTS SCANNED:", formatNumber(m.portsScanned), StyleWhite),
			padLabel("REQUESTS/s:", formatNumber(m.requestsPerSec), StyleWhite),
			padLabel("REMAINING:", remainingStr, StyleWhite),
		}
	}

	statsContent := strings.Join(statsLines, "\n")
	statsBox := renderBox("SCAN STATISTICS", statsContent, leftWidth, topBoxHeight, ColorBorder, ColorCyan, true)

	stagesInfo := []struct {
		num  int
		name string
	}{
		{1, "HOST DISCOVERY"},
		{2, "PORT SCANNING"},
		{3, "SERVICE ENUM"},
		{4, "VULN ASSESSMENT"},
		{5, "REPORT GEN"},
	}

	var stageProgressLines []string
	for _, s := range stagesInfo {
		var prog float64
		var statusStr string

		if len(m.targetList) == 0 {
			prog = m.stages[s.num].progress
			statusStr = fmt.Sprintf("%3d%%", int(prog*100))
		} else {
			if m.scanComplete {
				prog = 1.0
				statusStr = "100%"
			} else if m.currentStage > s.num {
				prog = 1.0
				statusStr = "100%"
			} else if m.currentStage == s.num {
				prog = m.calculateProgress()
				if prog > 0.99 {
					prog = 0.99
				}
				statusStr = fmt.Sprintf("%3d%%", int(prog*100))
			} else {
				prog = 0.0
				statusStr = "  0%"
			}
		}

		if topBoxHeight < 12 {
			barWidth := rightWidth - 26
			if barWidth < 5 {
				barWidth = 5
			}
			barStr := renderProgressBar(barWidth, prog, ColorCyan, ColorSelection)
			line := fmt.Sprintf(" %d. %-15s %s %s", s.num, s.name, barStr, statusStr)
			stageProgressLines = append(stageProgressLines, line)
		} else {
			textPad := rightWidth - 2 - len(fmt.Sprintf("%d. %s", s.num, s.name)) - len(statusStr) - 2
			if textPad < 0 {
				textPad = 0
			}
			var textColor lipgloss.Color
			var filledColor lipgloss.Color

			switch s.num {
			case 1:
				textColor = ColorCyan
				filledColor = ColorCyan
			case 2:
				textColor = ColorGreen
				filledColor = ColorGreen
			case 3:
				textColor = lipgloss.Color("#81a1c1")
				filledColor = lipgloss.Color("#81a1c1")
			case 4:
				textColor = ColorForeground
				filledColor = ColorForeground
			default:
				textColor = ColorComment
				filledColor = ColorSelection
			}

			textLine := fmt.Sprintf(" %d. %s%s%s", s.num, s.name, strings.Repeat(" ", textPad), statusStr)
			stageProgressLines = append(stageProgressLines, lipgloss.NewStyle().Foreground(textColor).Render(textLine))

			barWidth := rightWidth - 4
			if barWidth < 5 {
				barWidth = 5
			}
			barLine := " " + renderProgressBar(barWidth, prog, filledColor, ColorSelection)
			stageProgressLines = append(stageProgressLines, barLine)
		}
	}

	var overallProg float64
	if len(m.targetList) == 0 {
		overallProg = 0.54
	} else {
		var sum float64
		for s := 1; s <= 5; s++ {
			var sp float64
			if m.scanComplete {
				sp = 1.0
			} else if m.currentStage > s {
				sp = 1.0
			} else if m.currentStage == s {
				sp = m.calculateProgress()
			}
			sum += sp
		}
		overallProg = sum / 5.0
	}

	if topBoxHeight >= 12 {
		stageProgressLines = append(stageProgressLines, lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", rightWidth-2)))
		overallText := fmt.Sprintf(" TOTAL PROGRESS%s%3d%%", strings.Repeat(" ", rightWidth-2-len("TOTAL PROGRESS")-4-2), int(overallProg*100))
		stageProgressLines = append(stageProgressLines, StyleWhite.Render(overallText))
	}

	progressContent := strings.Join(stageProgressLines, "\n")
	progressBox := renderBox("STAGE PROGRESS", progressContent, rightWidth, topBoxHeight, ColorBorder, ColorCyan, true)

	var topSection string
	if m.width >= 80 {
		topSection = lipgloss.JoinHorizontal(lipgloss.Top, statsBox, progressBox)
	} else {
		topSection = statsBox + "\n" + progressBox
	}

	var finalView strings.Builder
	finalView.WriteString(topSection)

	if showTargets {
		var targetLines []string
		pHeader := fmt.Sprintf(" %-20s  %-15s  %-10s  %-15s  %-8s  %-10s",
			"HOSTNAME", "IP ADDRESS", "STATUS", "OPEN PORTS", "VULNS", "LAST SEEN")
		targetLines = append(targetLines, StyleCyan.Bold(true).Render(pHeader))

		if len(m.discoveredHosts) == 0 {
			targetLines = append(targetLines, "  "+StyleComment.Render("Awaiting discovery events..."))
		} else {
			visibleCount := middleBoxHeight - 3
			if visibleCount < 1 {
				visibleCount = 1
			}
			start := len(m.discoveredHosts) - visibleCount
			if start < 0 {
				start = 0
			}

			padRight := func(s string, width int) string {
				if len(s) >= width {
					return s[:width]
				}
				return s + strings.Repeat(" ", width-len(s))
			}

			for i := start; i < len(m.discoveredHosts); i++ {
				host := m.discoveredHosts[i]
				hostname := host.Hostname
				ip := host.IP
				if ip == "" || ip == "pending" {
					ip = "10.0.1.15"
				}
				status := host.Status
				if status == "" {
					status = "ACTIVE"
				}

				var portsStr string
				if len(host.OpenPorts) > 0 {
					var ports []string
					for _, p := range host.OpenPorts {
						ports = append(ports, fmt.Sprintf("%d", p))
					}
					portsStr = strings.Join(ports, ",")
				} else {
					portsStr = "80,443"
				}

				vulnsStr := fmt.Sprintf("%d", host.Vulns)

				lastSeenStr := host.LastSeen.Format("15:04:05")
				if host.LastSeen.IsZero() {
					lastSeenStr = host.LastSeenStr
					if lastSeenStr == "" {
						lastSeenStr = time.Now().Format("15:04:05")
					}
				}

				var vulnsColored string
				if host.Vulns > 0 {
					vulnsColored = StyleRed.Bold(true).Render(padRight(vulnsStr, 8))
				} else {
					vulnsColored = StyleWhite.Render(padRight(vulnsStr, 8))
				}

				pHostname := padRight(truncateString(hostname, 20), 20)
				pIP := padRight(ip, 15)
				pStatus := padRight(status, 10)
				pPorts := padRight(portsStr, 15)
				pLastSeen := padRight(lastSeenStr, 10)

				line := fmt.Sprintf(" %s  %s  %s  %s  %s  %s",
					StyleWhite.Render(pHostname),
					StyleWhite.Render(pIP),
					StyleGreen.Render(pStatus),
					StyleWhite.Render(pPorts),
					vulnsColored,
					StyleWhite.Render(pLastSeen),
				)
				targetLines = append(targetLines, line)
			}
		}

		targetsContent := strings.Join(targetLines, "\n")
		targetsBox := renderBox("DISCOVERED SUBDOMAINS/IPs", targetsContent, availWidth, middleBoxHeight, ColorBorder, ColorCyan, true)
		finalView.WriteString("\n" + targetsBox)
	}

	if showLogs {
		var visibleLogs []string
		maxLogLines := logBoxHeight - 2
		if maxLogLines < 1 {
			maxLogLines = 1
		}

		if len(m.logs) > 0 {
			start := len(m.logs) - maxLogLines
			if start < 0 {
				start = 0
			}
			for i := start; i < len(m.logs); i++ {
				visibleLogs = append(visibleLogs, colorizeLog(m.logs[i]))
			}
		} else {
			visibleLogs = append(visibleLogs, " "+StyleComment.Render("Awaiting system events..."))
		}

		logContent := strings.Join(visibleLogs, "\n")
		logBox := renderBox("LIVE EVENT LOG", logContent, availWidth, logBoxHeight, ColorBorder, ColorCyan, true)
		finalView.WriteString("\n" + logBox)
	}

	return StyleMain.Render(finalView.String())
}

// --- Helpers ---

func formatNumber(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var res []string
	for len(s) > 3 {
		res = append([]string{s[len(s)-3:]}, res...)
		s = s[:len(s)-3]
	}
	if len(s) > 0 {
		res = append([]string{s}, res...)
	}
	return strings.Join(res, ",")
}

func renderProgressBar(width int, prog float64, filledColor, unfilledColor lipgloss.Color) string {
	filledWidth := int(prog * float64(width))
	if filledWidth > width {
		filledWidth = width
	}
	if filledWidth < 0 {
		filledWidth = 0
	}
	unfilledWidth := width - filledWidth

	filledStr := strings.Repeat("█", filledWidth)
	unfilledStr := strings.Repeat("░", unfilledWidth)

	filledStyled := lipgloss.NewStyle().Foreground(filledColor).Render(filledStr)
	unfilledStyled := lipgloss.NewStyle().Foreground(unfilledColor).Render(unfilledStr)

	return filledStyled + unfilledStyled
}

func truncateStyledString(s string, maxLen int) string {
	width := lipgloss.Width(s)
	if width <= maxLen {
		return s
	}
	
	targetLen := maxLen - 3
	if targetLen < 1 {
		targetLen = 1
	}
	
	var result strings.Builder
	visibleLen := 0
	inEscape := false

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\x1b' {
			inEscape = true
			result.WriteRune(r)
			continue
		}
		if inEscape {
			result.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}

		if visibleLen < targetLen {
			result.WriteRune(r)
			visibleLen++
		}
	}
	result.WriteString("\x1b[0m...")
	return result.String()
}

func renderBox(title string, content string, width int, height int, borderColor lipgloss.Color, titleColor lipgloss.Color, centerTitle bool) string {
	lines := strings.Split(content, "\n")
	
	borderStyle := lipgloss.NewStyle().Foreground(borderColor)
	titleStyle := lipgloss.NewStyle().Foreground(titleColor).Bold(true)
	
	var topBorder string
	if centerTitle {
		titleLen := len(title)
		totalDashes := width - 2 - titleLen - 2
		if totalDashes < 0 {
			totalDashes = 0
		}
		leftDashes := totalDashes / 2
		rightDashes := totalDashes - leftDashes
		
		topBorder = borderStyle.Render("╭"+strings.Repeat("─", leftDashes)+" ") +
					titleStyle.Render(title) +
					borderStyle.Render(" "+strings.Repeat("─", rightDashes)+"╮")
	} else {
		topBorder = borderStyle.Render("╭── ") +
					titleStyle.Render(title) +
					borderStyle.Render(" "+strings.Repeat("─", width-len(title)-6)+"╮")
	}
	
	var b strings.Builder
	b.WriteString(topBorder + "\n")
	
	innerWidth := width - 2
	
	for i := 0; i < height-2; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		
		// 1. Truncate styled line to innerWidth
		truncated := truncateStyledString(line, innerWidth)
		
		// 2. Pad to innerWidth
		visibleWidth := lipgloss.Width(truncated)
		padded := truncated
		if visibleWidth < innerWidth {
			padded += strings.Repeat(" ", innerWidth - visibleWidth)
		}
		
		b.WriteString(borderStyle.Render("│") + padded + borderStyle.Render("│") + "\n")
	}
	
	bottomBorder := borderStyle.Render("╰" + strings.Repeat("─", innerWidth) + "╯")
	b.WriteString(bottomBorder)
	return b.String()
}

func colorizeLog(logLine string) string {
	if !strings.Contains(logLine, "|") {
		return logLine
	}
	
	parts := strings.SplitN(logLine, "|", 3)
	if len(parts) < 3 {
		return logLine
	}
	
	timestampPart := strings.TrimSpace(parts[0])
	levelPart := strings.TrimSpace(parts[1])
	rest := strings.TrimSpace(parts[2])
	
	componentEnd := strings.Index(rest, "]")
	if componentEnd == -1 {
		return logLine
	}
	componentPart := rest[:componentEnd+1]
	messagePart := strings.TrimSpace(rest[componentEnd+1:])
	
	timestampColored := StyleComment.Render(timestampPart)
	
	var levelColored string
	switch levelPart {
	case "INFO":
		levelColored = StyleCyan.Render("INFO")
	case "WARN":
		levelColored = StyleYellow.Render("WARN")
	case "VULN":
		levelColored = StyleRed.Bold(true).Render("VULN")
	default:
		levelColored = StyleWhite.Render(levelPart)
	}
	
	componentColored := StyleWhite.Render(componentPart)
	
	var messageColored string
	if levelPart == "VULN" {
		messageColored = StyleRed.Render(messagePart)
	} else {
		words := strings.Split(messagePart, " ")
		for i, w := range words {
			if isNumeric(w) {
				words[i] = StyleGreen.Render(w)
			} else if w == "OPEN" {
				words[i] = StyleGreen.Bold(true).Render(w)
			}
		}
		messageColored = strings.Join(words, " ")
	}
	
	return fmt.Sprintf("%s %s %s %s", timestampColored, levelColored, componentColored, messageColored)
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	clean := strings.ReplaceAll(strings.ReplaceAll(s, ",", ""), ".", "")
	for _, r := range clean {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func domainFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		parts := strings.Split(target, "://")
		if len(parts) > 1 {
			target = parts[1]
		}
	}
	target = strings.Split(target, "/")[0]
	target = strings.Split(target, ":")[0]
	return strings.ToLower(target)
}

func (m Model) calculateProgress() float64 {
	stage := m.currentStage
	if plan, exists := m.stageToolPlan[stage]; !exists || plan == 0 {
		for s, p := range m.stageToolPlan {
			if p > 0 {
				stage = s
				break
			}
		}
	}

	if plan, exists := m.stageToolPlan[stage]; exists && plan > 0 {
		if completions, ok := m.stageCompletions[stage]; ok {
			return float64(len(completions)) / float64(plan)
		}
	}

	completedStages := 0
	for _, stageInfo := range m.stages {
		if stageInfo.complete {
			completedStages++
		}
	}
	return float64(completedStages) / float64(totalStages)
}

func truncateString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	if limit <= 3 {
		return s[:limit]
	}
	return s[:limit-3] + "..."
}

type TargetValidationResultMsg struct {
	Target   string
	IsValid  bool
	IsFile   bool
	ErrorMsg string
}

func validateTargetCmd(targetVal string) tea.Cmd {
	return func() tea.Msg {
		// Verify if it is a local file path
		if _, err := os.Stat(targetVal); err == nil {
			return TargetValidationResultMsg{Target: targetVal, IsValid: true, IsFile: true}
		}

		cleanHost := targetVal
		if strings.HasPrefix(cleanHost, "http://") || strings.HasPrefix(cleanHost, "https://") {
			cleanHost = strings.TrimPrefix(cleanHost, "http://")
			cleanHost = strings.TrimPrefix(cleanHost, "https://")
		}
		if idx := strings.Index(cleanHost, "/"); idx != -1 {
			cleanHost = cleanHost[:idx]
		}
		if idx := strings.LastIndex(cleanHost, ":"); idx != -1 {
			if !(strings.Count(cleanHost, ":") > 1 && !strings.Contains(cleanHost, "]")) {
				cleanHost = cleanHost[:idx]
				cleanHost = strings.TrimPrefix(cleanHost, "[")
				cleanHost = strings.TrimSuffix(cleanHost, "]")
			}
		}

		isIP := (net.ParseIP(cleanHost) != nil)
		var isCIDR bool
		if _, _, err := net.ParseCIDR(targetVal); err == nil {
			isCIDR = true
		}

		if !isIP && !isCIDR && !normalize.IsValidDomain(cleanHost) {
			return TargetValidationResultMsg{Target: targetVal, IsValid: false, ErrorMsg: "Invalid syntax."}
		}

		// DNS lookup
		if !isIP && !isCIDR {
			ips, err := net.LookupIP(cleanHost)
			if err != nil || len(ips) == 0 {
				return TargetValidationResultMsg{Target: targetVal, IsValid: false, ErrorMsg: "Host does not resolve."}
			}
		}

		return TargetValidationResultMsg{Target: targetVal, IsValid: true, IsFile: false}
	}
}
