package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/engine/recon"
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
	fmt.Fprintln(w, "Bug Bounty Target Analysis")
	fmt.Fprintln(w, "==========================")
	fmt.Fprintf(w, "Targets: %d\n", len(t.Targets))
	fmt.Fprintf(w, "Recon events: %d\n", len(t.Events))
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "Targets:")
	for _, target := range t.Targets {
		fmt.Fprintf(w, "- %s\n", target)
	}

	if len(t.Insights) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "HIGH VALUE TARGETS:")
		for _, insight := range t.Insights[:min(3, len(t.Insights))] {
			fmt.Fprintf(w, "- %s (%s, score=%d)\n", insight.Host, insight.Priority, insight.Score)
			if len(insight.Tags) > 0 {
				fmt.Fprintf(w, "  → tags: %s\n", strings.Join(insight.Tags, ", "))
			}
			if len(insight.Reasons) > 0 {
				fmt.Fprintf(w, "  → reasons: %s\n", strings.Join(insight.Reasons, "; "))
			}
			if len(insight.SuggestedTests) > 0 {
				fmt.Fprintf(w, "  → suggested tests: %s\n", strings.Join(insight.SuggestedTests, "; "))
			}
		}
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Top findings:")
	sources := map[string]int{}
	for _, ev := range t.Events {
		sources[ev.Source]++
	}
	for source, count := range sources {
		fmt.Fprintf(w, "- %s: %d items\n", source, count)
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Summary:")
	fmt.Fprintln(w, "- Parsed input and normalized assets.")
	fmt.Fprintln(w, "- Derived prioritized insights from passive recon findings.")
	fmt.Fprintln(w, "- Use the suggested tests to focus manual review.")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
