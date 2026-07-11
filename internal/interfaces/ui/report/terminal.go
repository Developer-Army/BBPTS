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

func (t *TerminalSummary) Write(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "\n\033[1;36m️  BBPTS Reconnaissance Summary\033[0m"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "\033[1;36m===============================\033[0m"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\033[1;34mTargets Analyzed:\033[0m %d\n", len(t.Targets)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\033[1;34mTotal Events:\033[0m     %d\n", len(t.Events)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}

	highCount := 0
	for _, in := range t.Insights {
		if in.Priority == "high" {
			highCount++
		}
	}

	if _, err := fmt.Fprintf(w, "\033[1;31m HIGH PRIORITY TARGETS (%d)\033[0m\n", highCount); err != nil {
		return err
	}
	for i, insight := range t.Insights {
		if insight.Priority != "high" {
			continue
		}
		if i >= 5 {
			if _, err := fmt.Fprintf(w, "  ... and %d more high-priority assets\n", highCount-5); err != nil {
				return err
			}
			break
		}
		if _, err := fmt.Fprintf(w, "\n\033[1;37m• %s\033[0m (\033[1;33mScore: %d\033[0m)\n", insight.Host, insight.Score); err != nil {
			return err
		}
		if len(insight.Reasons) > 0 {
			if _, err := fmt.Fprintf(w, "  \033[0;90mReason:\033[0m %s\n", strings.Join(insight.Reasons, " | ")); err != nil {
				return err
			}
		}
		if len(insight.SuggestedTests) > 0 {
			if _, err := fmt.Fprintf(w, "  \033[0;90mTests:\033[0m  %d suggestions available in report\n", len(insight.SuggestedTests)); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, "\n\033[1;32m🛠️  TOOL STATISTICS\033[0m"); err != nil {
		return err
	}
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
		if _, err := fmt.Fprintf(w, "  \033[0;32m%-12s\033[0m: %d items\n", source, sources[source]); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w, "\n\033[1;35m📄 NEXT STEPS\033[0m"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  1. Check the detailed Markdown report for checklists and evidence."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  2. Prioritize testing the 'High' score targets listed above."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  3. Use the suggested tools for each specific finding."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ""); err != nil {
		return err
	}

	return nil
}
