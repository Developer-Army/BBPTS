package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

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
	b.WriteString(topBorder)
	b.WriteString("\n")

	innerWidth := width - 2

	for i := 0; i < height-2; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}

		truncated := truncateStyledString(line, innerWidth)

		visibleWidth := lipgloss.Width(truncated)
		padded := truncated
		if visibleWidth < innerWidth {
			padded += strings.Repeat(" ", innerWidth-visibleWidth)
		}

		b.WriteString(borderStyle.Render("│"))
		b.WriteString(padded)
		b.WriteString(borderStyle.Render("│"))
		b.WriteString("\n")
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

func truncateString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	if limit <= 3 {
		return s[:limit]
	}
	return s[:limit-3] + "..."
}
