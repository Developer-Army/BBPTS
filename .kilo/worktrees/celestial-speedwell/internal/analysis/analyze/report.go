package analyze

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

const markdownTemplate = `# BBPTS Reconnaissance Report
Generated: {{.Timestamp}}

## Summary
- **Total Hosts Analyzed:** {{.TotalHosts}}
- **High Priority Findings:** {{.HighPriorityCount}}

| Host | Score | Priority | Tags | Suggested Tests |
|------|-------|----------|------|-----------------|
{{- range .Insights}}
| {{.Host}} | {{.Score}} | {{.Priority}} | {{join .Tags ", "}} | {{join .SuggestedTests "; "}} |
{{- end}}

`

// WriteMarkdownReport generates a detailed Markdown report of the insights.
func WriteMarkdownReport(path string, insights []Insight) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	highPriorityCount := 0
	for _, in := range insights {
		if in.Priority == "high" {
			highPriorityCount++
		}
	}

	data := struct {
		Timestamp         string
		TotalHosts        int
		HighPriorityCount int
		Insights          []Insight
	}{
		Timestamp:         time.Now().Format(time.RFC1123),
		TotalHosts:        len(insights),
		HighPriorityCount: highPriorityCount,
		Insights:          insights,
	}

	funcMap := template.FuncMap{
		"join": strings.Join,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(markdownTemplate)
	if err != nil {
		return err
	}

	return tmpl.Execute(f, data)
}

// WriteCSVSummary generates a CSV summary of the insights.
func WriteCSVSummary(path string, insights []Insight) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)

	if err := writer.Write([]string{"host", "severity", "score", "tags", "reasons", "suggested_tests", "evidence_count"}); err != nil {
		return err
	}
	for _, in := range insights {
		if err := writer.Write([]string{
			in.Host,
			in.Priority,
			fmt.Sprintf("%d", in.Score),
			strings.Join(in.Tags, "; "),
			strings.Join(in.Reasons, "; "),
			strings.Join(in.SuggestedTests, "; "),
			fmt.Sprintf("%d", in.EvidenceCount),
		}); err != nil {
			return err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	return nil
}

// ExportToObsidian creates individual notes in an Obsidian vault for each high-priority host.
func ExportToObsidian(dir string, insights []Insight) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	for _, in := range insights {
		if in.Priority != "high" && in.Score < 25 {
			continue
		}

		filename := filepath.Join(dir, in.Host+".md")
		f, err := os.Create(filename)
		if err != nil {
			continue
		}

		fmt.Fprintf(f, "---\n")
		fmt.Fprintf(f, "tags: [bbpts, %s]\n", strings.Join(in.Tags, ", "))
		fmt.Fprintf(f, "priority: %s\n", in.Priority)
		fmt.Fprintf(f, "score: %d\n", in.Score)
		fmt.Fprintf(f, "updated: %s\n", time.Now().Format("2006-01-02"))
		fmt.Fprintf(f, "---\n\n")
		fmt.Fprintf(f, "# %s\n\n", in.Host)
		fmt.Fprintf(f, "## Findings\n")
		for _, r := range in.Reasons {
			fmt.Fprintf(f, "- %s\n", r)
		}
		fmt.Fprintf(f, "\n## Suggested Tests\n")
		for _, t := range in.SuggestedTests {
			fmt.Fprintf(f, "- [ ] %s\n", t)
		}

		f.Close()
	}

	return nil
}
