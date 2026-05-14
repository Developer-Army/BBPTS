// Package tui — styles.go defines the premium visual design system for the BBPTS
// elite dashboard using Charm Lip Gloss. It uses a Dracula-inspired palette
// to create a professional, "elite" look.
package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// --- Colors (Dracula Palette) ---
	ColorBackground = lipgloss.Color("#282a36")
	ColorForeground = lipgloss.Color("#f8f8f2")
	ColorSelection  = lipgloss.Color("#44475a")
	ColorComment    = lipgloss.Color("#6272a4")
	ColorCyan       = lipgloss.Color("#8be9fd")
	ColorGreen      = lipgloss.Color("#50fa7b")
	ColorOrange     = lipgloss.Color("#ffb86c")
	ColorPink       = lipgloss.Color("#ff79c6")
	ColorPurple     = lipgloss.Color("#bd93f9")
	ColorRed        = lipgloss.Color("#ff5555")
	ColorYellow     = lipgloss.Color("#f1fa8c")

	// --- Styles ---
	StyleMain = lipgloss.NewStyle().
			Padding(1, 2).
			Foreground(ColorForeground)

	StyleHeader = lipgloss.NewStyle().
			Foreground(ColorBackground).
			Background(ColorPurple).
			Padding(0, 1).
			Bold(true)

	StyleTitle = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true).
			MarginBottom(1)

	StyleSidebar = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(ColorSelection).
			Padding(0, 1).
			MarginRight(2)

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
			Border(lipgloss.RoundedBorder()).
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
    / __  / __  / /_/ / / /  \__ \             
   / /_/ / /_/ / ____/ / /  ___/ /             
  /_____/_____/_/     /_/  /____/  v2.0-ELITE  
`

	LogoAnalyzer = `      / __ )/ __ )/ __ \/_  __/ ___/  𝓪𝓷𝓪𝓵𝔂𝔃𝓮𝓻`
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
