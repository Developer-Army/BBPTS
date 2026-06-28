package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func handleAwaitingInputKey(m Model, msg tea.KeyMsg) (Model, tea.Cmd) {
	m.inputErrorMessage = ""
	switch msg.String() {
	case "esc":
		if m.modesView || m.helpView || m.infoView || m.configView {
			m.modesView = false
			m.helpView = false
			m.infoView = false
			m.configView = false
			m.configEditKey = ""
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
	case "enter":
		val := strings.TrimSpace(m.textInput.Value())
		m.textInput.SetValue("")
		if val == "" {
			return m, nil
		}

		lowerVal := strings.ToLower(val)

		// 1. If currently in infoView or helpView, check for exit command
		if m.infoView || m.helpView {
			if lowerVal == "back" || lowerVal == "exit" {
				m.infoView = false
				m.helpView = false
				return m, nil
			}
			return m, nil
		}

		// 2. If in modesView, check selection or exit
		if m.modesView {
			switch lowerVal {
			case "1", "normal":
				m.targetMode = "normal"
				m.modesView = false
				return m, nil
			case "2", "light":
				m.targetMode = "light"
				m.modesView = false
				return m, nil
			case "back", "exit":
				m.modesView = false
				return m, nil
			}
			return m, nil
		}

		// 3. If in configView, check fields, save, or back
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
				m.configEditKey = ""
				m.textInput.Placeholder = "Type number to edit, 'save' to save, 'back' to exit..."
				return m, nil
			} else {
				if lowerVal == "back" || lowerVal == "exit" {
					m.configView = false
					m.textInput.Placeholder = "Enter target domain, IP, or file..."
					return m, nil
				}
				if lowerVal == "save" {
					err := saveConfig(m.configPath, m.cfg)
					m.configView = false
					m.textInput.Placeholder = "Enter target domain, IP, or file..."
					if err != nil {
						m.inputErrorMessage = "Failed to save config: " + err.Error()
					}
					return m, nil
				}
				var num int
				if _, err := fmt.Sscanf(lowerVal, "%d", &num); err == nil && num >= 1 && num <= len(configFields) {
					field := configFields[num-1]
					m.configEditKey = field.Key
					m.textInput.Placeholder = "Enter new value for " + field.Label + "..."
					return m, nil
				}
				return m, nil
			}
		}

		// 4. Check for commands typed at the main prompt
		if lowerVal == "/configure" || lowerVal == "configure" || lowerVal == "/setup" || lowerVal == "setup" || lowerVal == "/keys" || lowerVal == "keys" {
			m.configView = true
			m.configEditKey = ""
			m.textInput.Placeholder = "Type number to edit, 'save' to save, 'back' to exit..."
			return m, nil
		}

		if lowerVal == "/help" || lowerVal == "help" {
			m.helpView = true
			return m, nil
		}

		if lowerVal == "/modes" || lowerVal == "modes" {
			m.modesView = true
			return m, nil
		}

		if lowerVal == "/info" || lowerVal == "info" {
			m.infoView = true
			return m, nil
		}

		if lowerVal == "/clear" || lowerVal == "clear" {
			m.cliHistory = []string{""}
			return m, nil
		}

		// Handle modes commands with direct argument
		if strings.HasPrefix(lowerVal, "/modes ") || strings.HasPrefix(lowerVal, "modes ") {
			modeArg := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(lowerVal, "/modes "), "modes "))
			switch modeArg {
			case "1", "normal":
				m.targetMode = "normal"
				return m, nil
			case "2", "light":
				m.targetMode = "light"
				return m, nil
			}
		}

		// 5. It's a target domain/IP to start scan!
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
