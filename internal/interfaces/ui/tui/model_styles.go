// Package ui provides user interface components
package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	ColorBackground = lipgloss.Color("#1a1b26")
	ColorForeground = lipgloss.Color("#c0caf5")
	ColorSelection  = lipgloss.Color("#292e42")
	ColorComment    = lipgloss.Color("#565f89")
	ColorCyan       = lipgloss.Color("#7dcfff")
	ColorGreen      = lipgloss.Color("#9ece6a")
	ColorOrange     = lipgloss.Color("#ff9e64")
	ColorPink       = lipgloss.Color("#bb9af7")
	ColorPurple     = lipgloss.Color("#9d7cd8")
	ColorRed        = lipgloss.Color("#f7768e")
	ColorYellow     = lipgloss.Color("#e0af68")
	ColorBorder     = lipgloss.Color("#3b4261")

	StyleMain = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(ColorForeground)

	StyleHeader = lipgloss.NewStyle().
			Foreground(ColorForeground).
			Background(ColorSelection).
			Padding(0, 1).
			Bold(true)

	StyleWhite = lipgloss.NewStyle().
			Foreground(ColorForeground)

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

	StyleRed = lipgloss.NewStyle().
			Foreground(ColorRed)

	StyleCyan = lipgloss.NewStyle().
			Foreground(ColorCyan)

	StyleYellow = lipgloss.NewStyle().
			Foreground(ColorYellow)

	StyleOrange = lipgloss.NewStyle().
			Foreground(ColorOrange)

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

	LogoBBPTS = `    ____  ____  ____  ___________
   / __ )/ __ )/ __ \/_  __/ ___/
  / __  / __  / /_/ / / /  \__ \ 
 / /_/ / /_/ / ____/ / /  ___/ / 
/_____/_____/_/     /_/  /____/  `
)

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
