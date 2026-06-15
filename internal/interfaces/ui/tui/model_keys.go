package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func handleAwaitingInputKey(m Model, msg tea.KeyMsg) (Model, tea.Cmd) {
	m.inputErrorMessage = ""
	switch msg.String() {
	case "esc":
		if m.modesView {
			m.modesView = false
			m.cliHistory = append(m.cliHistory, "  Returned to main prompt.", "")
			m.textInput.SetValue("")
			return m, nil
		}
		if m.configView {
			if m.configEditKey != "" {
				m.configEditKey = ""
				m.textInput.SetValue("")
				m.textInput.Placeholder = "Type number to edit, 'save' to save, 'back' to exit..."
				return m, nil
			}
			m.configView = false
			m.cliHistory = append(m.cliHistory, "  [System] Exited configuration view. Changes discarded.", "")
			m.textInput.SetValue("")
			m.textInput.Placeholder = "Enter target domain, IP, or file..."
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
	case "/":
		if m.textInput.Value() == "" && !m.configView {
			m.cliHistory = append(m.cliHistory,
				"  "+StyleWhite.Bold(true).Render("Available Commands:"),
				"    "+StyleCyan.Render("/configure")+"  - Edit API Keys and notification webhooks",
				"    "+StyleCyan.Render("/modes")+"     - Configure scanning mode (Normal / Light)",
				"    "+StyleCyan.Render("/history")+"   - Show target entry history",
				"    "+StyleCyan.Render("/clear")+"     - Clear command line screen history",
				"    "+StyleCyan.Render("/info")+"      - Show system version & configuration info",
				"    "+StyleCyan.Render("/help")+"      - Show help details",
				"",
			)
		}
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd
	case "enter":
		val := strings.TrimSpace(m.textInput.Value())
		m.textInput.SetValue("")
		if val == "" {
			return m, nil
		}

		lowerVal := strings.ToLower(val)
		isCommand := false
		if lowerVal == "/help" || lowerVal == "help" || lowerVal == "/modes" || lowerVal == "modes" || m.modesView ||
			lowerVal == "/configure" || lowerVal == "configure" || lowerVal == "/setup" || lowerVal == "setup" || lowerVal == "/keys" || lowerVal == "keys" || m.configView {
			isCommand = true
		}
		if strings.HasPrefix(lowerVal, "/modes ") || strings.HasPrefix(lowerVal, "modes ") {
			isCommand = true
		}

		if isCommand {
			var modeStyle lipgloss.Style
			if m.targetMode == "light" {
				modeStyle = lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)
			} else {
				modeStyle = lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
			}
			displayVal := val
			if m.configView && m.configEditKey != "" {
				displayVal = "********"
			}
			m.cliHistory = append(m.cliHistory, "  ➜  "+modeStyle.Render(strings.ToUpper(m.targetMode))+" mode > "+displayVal)
		}

		if m.configView {
			if m.configEditKey != "" {
				switch m.configEditKey {
				case "telegram_bot_token":
					m.cfg.Notify.TelegramBotToken = val
				case "telegram_chat_id":
					m.cfg.Notify.TelegramChatID = val
				case "discord_webhook":
					m.cfg.Notify.DiscordWebhook = val
				case "slack_webhook":
					m.cfg.Notify.SlackWebhook = val
				default:
					if m.cfg.APIKeys == nil {
						m.cfg.APIKeys = make(map[string]string)
					}
					m.cfg.APIKeys[m.configEditKey] = val
				}
				m.cliHistory = append(m.cliHistory, "  [System] Updated "+m.configEditKey+" in-memory.", "")
				m.configEditKey = ""
				m.textInput.Placeholder = "Type number to edit, 'save' to save, 'back' to exit..."
				return m, nil
			} else {
				if lowerVal == "back" || lowerVal == "exit" {
					m.configView = false
					m.cliHistory = append(m.cliHistory, "  [System] Exited configuration view. Changes discarded.", "")
					m.textInput.Placeholder = "Enter target domain, IP, or file..."
					return m, nil
				}
				if lowerVal == "save" {
					err := saveConfig(m.configPath, m.cfg)
					if err != nil {
						m.cliHistory = append(m.cliHistory, "  "+StyleRed.Bold(true).Render("✗ Failed to save config: "+err.Error()), "")
					} else {
						m.cliHistory = append(m.cliHistory, "  "+StyleGreen.Bold(true).Render("✓ Configuration saved to "+m.configPath), "")
					}
					m.configView = false
					m.textInput.Placeholder = "Enter target domain, IP, or file..."
					return m, nil
				}
				var num int
				if _, err := fmt.Sscanf(lowerVal, "%d", &num); err == nil && num >= 1 && num <= 10 {
					field := configFields[num-1]
					m.configEditKey = field.Key
					m.textInput.Placeholder = "Enter new value for " + field.Label + "..."
					return m, nil
				}
				m.cliHistory = append(m.cliHistory, "  "+StyleRed.Render("Invalid config command. Enter 1-10, 'save', or 'back'."), "")
				return m, nil
			}
		}

		if lowerVal == "/configure" || lowerVal == "configure" || lowerVal == "/setup" || lowerVal == "setup" || lowerVal == "/keys" || lowerVal == "keys" {
			m.configView = true
			m.configEditKey = ""
			m.textInput.Placeholder = "Type number to edit, 'save' to save, 'back' to exit..."
			m.cliHistory = append(m.cliHistory,
				"  "+StyleWhite.Bold(true).Render("BBPTS Configuration Editor Loaded:"),
				"    Enter 1-10 to edit a value, or 'save' / 'back'.",
				"",
			)
			return m, nil
		}

		if lowerVal == "/help" || lowerVal == "help" {
			m.cliHistory = append(m.cliHistory,
				"  "+StyleWhite.Bold(true).Render("BBPTS CLI Help Menu:"),
				"    "+StyleCyan.Render("/configure")+"  - Edit API Keys and notification webhooks",
				"    "+StyleCyan.Render("/modes")+"     - Configure scanning mode (Normal / Light)",
				"    "+StyleCyan.Render("/history")+"   - Show target entry history",
				"    "+StyleCyan.Render("/clear")+"     - Clear command line screen history",
				"    "+StyleCyan.Render("/info")+"      - Show system version & configuration info",
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

		if lowerVal == "/history" || lowerVal == "history" {
			var targets []string
			for _, h := range m.cliHistory {
				if strings.Contains(h, " > ") {
					targets = append(targets, h)
				}
			}
			m.cliHistory = append(m.cliHistory, "  "+StyleWhite.Bold(true).Render("Command History:"))
			if len(targets) == 0 {
				m.cliHistory = append(m.cliHistory, "    No commands recorded yet.")
			} else {
				for _, t := range targets {
					m.cliHistory = append(m.cliHistory, "    "+t)
				}
			}
			m.cliHistory = append(m.cliHistory, "")
			return m, nil
		}

		if lowerVal == "/clear" || lowerVal == "clear" {
			m.cliHistory = []string{""}
			return m, nil
		}

		if lowerVal == "/info" || lowerVal == "info" {
			m.cliHistory = append(m.cliHistory,
				"  "+StyleWhite.Bold(true).Render("BBPTS Engine Info:"),
				"    Version:    v1.3.0",
				"    Status:     Ready to scan",
				"    Database:   SQLite (active)",
				"",
			)
			return m, nil
		}

		if m.modesView {
			switch lowerVal {
			case "1", "/modes 1":
				m.targetMode = "normal"
				m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleCyan.Render("NORMAL")+" scan.", "")
				m.modesView = false
				return m, nil
			case "2", "/modes 2":
				m.targetMode = "light"
				m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleGreen.Render("LIGHT")+" scan.", "")
				m.modesView = false
				return m, nil
			case "back":
				m.modesView = false
				m.cliHistory = append(m.cliHistory, "  Returned to main prompt.", "")
				return m, nil
			}
		}

		if strings.HasPrefix(lowerVal, "/modes ") || strings.HasPrefix(lowerVal, "modes ") {
			modeArg := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(lowerVal, "/modes "), "modes "))
			switch modeArg {
			case "1", "normal":
				m.targetMode = "normal"
				m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleCyan.Render("NORMAL")+" scan.", "")
				m.modesView = false
				return m, nil
			case "2", "light":
				m.targetMode = "light"
				m.cliHistory = append(m.cliHistory, "  [System] Mode set to "+StyleGreen.Render("LIGHT")+" scan.", "")
				m.modesView = false
				return m, nil
			}
		}

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

func handleScanActiveKey(m Model, msg tea.KeyMsg) (Model, tea.Cmd) {
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
	return m, nil
}
