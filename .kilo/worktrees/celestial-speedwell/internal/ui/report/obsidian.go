package report

import (
	"fmt"
	"io"
	"strings"
)

func WriteObsidianNote(w io.Writer, model *DataModel, noteTitle string) error {
	fmt.Fprintf(w, "---\ntitle: %s\n---\n\n", noteTitle)
	fmt.Fprintf(w, "# %s\n\n", noteTitle)
	fmt.Fprintln(w, "## Targets")
	for _, target := range model.Targets {
		fmt.Fprintf(w, "- [[%s]]\n", target)
	}

	if len(model.Insights) > 0 {
		fmt.Fprintln(w, "\n## High Value Targets")
		for _, insight := range model.Insights {
			fmt.Fprintf(w, "- [[%s]] (%s)\n", insight.Host, insight.Priority)
			if len(insight.SuggestedTests) > 0 {
				fmt.Fprintf(w, "  - suggested tests: %s\n", strings.Join(insight.SuggestedTests, "; "))
			}
		}
	}

	fmt.Fprintln(w, "\n## Recon events")
	for _, ev := range model.Events {
		fmt.Fprintf(w, "- [[%s]] (%s)\n", ev.Target, ev.Source)
	}
	return nil
}
