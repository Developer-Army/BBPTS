package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/engine/recon"
)

func WriteMarkdown(w io.Writer, model *DataModel) error {
	fmt.Fprintln(w, "# Bug Bounty Target Analysis")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Generated: %s\n", nowString())
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Targets")
	for _, target := range model.Targets {
		fmt.Fprintf(w, "- %s\n", target)
	}
	fmt.Fprintln(w)

	if len(model.Insights) > 0 {
		fmt.Fprintln(w, "## High Value Targets")
		for _, insight := range model.Insights {
			fmt.Fprintf(w, "- %s (%s, score=%d)\n", insight.Host, insight.Priority, insight.Score)
			if len(insight.Tags) > 0 {
				fmt.Fprintf(w, "  - tags: %s\n", strings.Join(insight.Tags, ", "))
			}
			if len(insight.Reasons) > 0 {
				fmt.Fprintf(w, "  - reasons: %s\n", strings.Join(insight.Reasons, "; "))
			}
			if len(insight.SuggestedTests) > 0 {
				fmt.Fprintf(w, "  - suggested tests: %s\n", strings.Join(insight.SuggestedTests, "; "))
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## Recon events (%d)\n", len(model.Events))
	grouped := grouping(model.Events)
	for source, events := range grouped {
		fmt.Fprintf(w, "### %s (%d)\n", source, len(events))
		for _, ev := range events {
			fmt.Fprintf(w, "- `%s`\n", ev.Target)
			if len(ev.Properties) > 0 {
				lines := formatProperties(ev.Properties)
				for _, line := range lines {
					fmt.Fprintf(w, "  - %s\n", line)
				}
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "## Review guidance")
	fmt.Fprintln(w, "- Focus on domains with the largest number of passive findings.")
	fmt.Fprintln(w, "- Inspect discovered endpoints for parameter and auth-related behavior.")
	fmt.Fprintln(w, "- Review certificate and subdomain evidence for scope expansion.")
	return nil
}

func grouping(events []recon.Event) map[string][]recon.Event {
	grouped := make(map[string][]recon.Event)
	for _, ev := range events {
		grouped[ev.Source] = append(grouped[ev.Source], ev)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	sorted := make(map[string][]recon.Event, len(grouped))
	for _, key := range keys {
		sorted[key] = grouped[key]
	}
	return sorted
}

func formatProperties(props map[string]string) []string {
	keys := make([]string, 0, len(props))
	for key := range props {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(props))
	for _, key := range keys {
		value := strings.TrimSpace(props[key])
		if value == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("**%s**: %s", key, value))
	}
	return lines
}

func nowString() string {
	return time.Now().UTC().Format(time.RFC3339)
}
