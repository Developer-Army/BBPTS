package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func NewTerminalSummary(targets []string, events []recon.Event, insights []analyze.Insight) *TerminalSummary {
	return &TerminalSummary{Targets: targets, Events: events, Insights: insights}
}

type TerminalSummary struct {
	Targets  []string
	Events   []recon.Event
	Insights []analyze.Insight
}

func (t *TerminalSummary) Write(w io.Writer) {
	fmt.Fprintln(w, "\n\033[1;36m🛡️  BBPTS Reconnaissance Summary\033[0m")
	fmt.Fprintln(w, "\033[1;36m===============================\033[0m")
	fmt.Fprintf(w, "\033[1;34mTargets Analyzed:\033[0m %d\n", len(t.Targets))
	fmt.Fprintf(w, "\033[1;34mTotal Events:\033[0m     %d\n", len(t.Events))
	fmt.Fprintln(w, "")

	highCount := 0
	for _, in := range t.Insights {
		if in.Priority == "high" {
			highCount++
		}
	}

	fmt.Fprintf(w, "\033[1;31m🔥 HIGH PRIORITY TARGETS (%d)\033[0m\n", highCount)
	for i, insight := range t.Insights {
		if insight.Priority != "high" {
			continue
		}
		if i >= 5 { // Show top 5 high priority
			fmt.Fprintf(w, "  ... and %d more high-priority assets\n", highCount-5)
			break
		}
		fmt.Fprintf(w, "\n\033[1;37m• %s\033[0m (\033[1;33mScore: %d\033[0m)\n", insight.Host, insight.Score)
		if len(insight.Reasons) > 0 {
			fmt.Fprintf(w, "  \033[0;90mReason:\033[0m %s\n", strings.Join(insight.Reasons, " | "))
		}
		if len(insight.SuggestedTests) > 0 {
			fmt.Fprintf(w, "  \033[0;90mTests:\033[0m  %d suggestions available in report\n", len(insight.SuggestedTests))
		}
	}

	fmt.Fprintln(w, "\n\033[1;32m🛠️  TOOL STATISTICS\033[0m")
	sources := map[string]int{}
	for _, ev := range t.Events {
		sources[ev.Source]++
	}

	// Sort sources for consistent output
	var keys []string
	for k := range sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, source := range keys {
		fmt.Fprintf(w, "  \033[0;32m%-12s\033[0m: %d items\n", source, sources[source])
	}

	fmt.Fprintln(w, "\n\033[1;35m📄 NEXT STEPS\033[0m")
	fmt.Fprintln(w, "  1. Check the detailed Markdown report for checklists and evidence.")
	fmt.Fprintln(w, "  2. Prioritize testing the 'High' score targets listed above.")
	fmt.Fprintln(w, "  3. Use the suggested tools for each specific finding.")
	fmt.Fprintln(w, "")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
