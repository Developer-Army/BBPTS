// Package ui provides user interface components
package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// --- Colors (Modern Palette inspired by Antigravity Code) ---
	ColorBackground = lipgloss.Color("#0f0f0f")
	ColorForeground = lipgloss.Color("#f0f0f0")
	ColorSelection  = lipgloss.Color("#2a2a2a")
	ColorComment    = lipgloss.Color("#6c7086")
	ColorCyan       = lipgloss.Color("#89dceb")
	ColorGreen      = lipgloss.Color("#a6e3a1")
	ColorOrange     = lipgloss.Color("#fab387")
	ColorPink       = lipgloss.Color("#f5c2e7")
	ColorPurple     = lipgloss.Color("#cba6f7")
	ColorRed        = lipgloss.Color("#f38ba8")
	ColorYellow     = lipgloss.Color("#f9e2af")

	// --- Styles ---
	StyleMain = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(ColorForeground).
			Background(ColorBackground)

	StyleHeader = lipgloss.NewStyle().
			Foreground(ColorForeground).
			Background(ColorSelection).
			Padding(0, 1).
			Bold(true)

	StyleTitle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true).
			MarginBottom(0)

	StyleSidebar = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(ColorSelection).
			Padding(0, 1).
			MarginRight(1)

	StyleMainPane = lipgloss.NewStyle()

	StyleLogWindow = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSelection).
			Padding(0, 1).
			Height(8).
			MarginTop(1)

	StyleStatus = lipgloss.NewStyle().
			Foreground(ColorComment).
			Italic(true)

	StyleStatusLine = lipgloss.NewStyle().
			Foreground(ColorForeground).
			Background(ColorSelection).
			Padding(0, 1)

	StyleFinding = lipgloss.NewStyle().
			Foreground(ColorYellow)

	StyleCritical = lipgloss.NewStyle().
			Foreground(ColorRed).
			Bold(true)

	StyleHigh = lipgloss.NewStyle().
			Foreground(ColorOrange).
			Bold(true)

	StyleMedium = lipgloss.NewStyle().
			Foreground(ColorYellow)

	StyleLow = lipgloss.NewStyle().
			Foreground(ColorGreen)

	StyleBorder = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(ColorSelection).
			Padding(0, 1)

	StyleTabActive = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(ColorPink).
			Foreground(ColorPink).
			Padding(0, 1).
			Bold(true)

	StyleTabInactive = lipgloss.NewStyle().
				Foreground(ColorComment).
				Padding(0, 1)

	StyleKey = lipgloss.NewStyle().
			Foreground(ColorCyan)

	StyleValue = lipgloss.NewStyle().
			Foreground(ColorForeground)

	StyleGreen = lipgloss.NewStyle().
			Foreground(ColorGreen)

	StyleComment = lipgloss.NewStyle().
			Foreground(ColorComment)

	StyleActivity = lipgloss.NewStyle().
			Foreground(ColorCyan)

	StylePurple = lipgloss.NewStyle().
			Foreground(ColorPurple)

	StylePulse = lipgloss.NewStyle().
			Foreground(ColorPink).
			Bold(true)

	StyleNew = lipgloss.NewStyle().
			Foreground(ColorGreen).
			Background(ColorSelection).
			Bold(true).
			Padding(0, 1)

	StyleFailure = lipgloss.NewStyle().
			Foreground(ColorRed).
			Bold(true)

	// --- ASCII Art ---
	LogoBBPTS = `
  ____  ____  ____ _____ _____ 
 |  _ \| __ )|  _ \_   _/ _ \ 
 | | | |  _ \| |_) || || | | |
 | |_| | |_) |  __/ | || |_| |
 |____/|____/|_|    |_| \___/  v2.0
`
)

// GetPriorityStyle returns a Lip Gloss style based on finding priority.
func GetPriorityStyle(priority string) lipgloss.Style {
	switch priority {
	case "critical":
		return StyleCritical
	case "high":
		return StyleHigh
	case "medium":
		return StyleMedium
	case "low":
		return StyleLow
	default:
		return StyleMain
	}
}
