package cli

import (
	"path/filepath"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func TestDefaultReportPaths_FromCSVInput(t *testing.T) {
	out, summary := defaultReportPaths("targets.example.csv")
	if out != filepath.Join("results", "targets.example_report.md") {
		t.Fatalf("unexpected output path: %s", out)
	}
	if summary != filepath.Join("results", "targets.example_summary.csv") {
		t.Fatalf("unexpected summary path: %s", summary)
	}
}

func TestDefaultReportPaths_EmptyNameFallback(t *testing.T) {
	out, summary := defaultReportPaths("")
	if out != filepath.Join("results", "scan_report.md") {
		t.Fatalf("unexpected output path: %s", out)
	}
	if summary != filepath.Join("results", "scan_summary.csv") {
		t.Fatalf("unexpected summary path: %s", summary)
	}
}

func TestExtractSeedDomainsRejectsSingleLabelJunk(t *testing.T) {
	got := extractSeedDomains([]string{"deposit", "https://app.acme-corp.io/path", "127.0.0.1"})
	if len(got) != 2 {
		t.Fatalf("expected 2 valid seed domains, got %v", got)
	}
	if got[0] != "app.acme-corp.io" || got[1] != "127.0.0.1" {
		t.Fatalf("unexpected seed domains: %v", got)
	}
}

func TestBlockAndElevateRules(t *testing.T) {
	insights := []analyze.Insight{
		{Host: "block-me.com", Priority: "medium", Score: 20},
		{Host: "elevate-me.com", Priority: "low", Score: 10},
		{Host: "keep-me.com", Priority: "medium", Score: 20},
	}

	matches := []recon.Match{
		{
			Rule: recon.Rule{
				Action: recon.Action{Type: "block"},
			},
			Event: recon.Event{Target: "block-me.com"},
		},
		{
			Rule: recon.Rule{
				Description: "Elevate critical targets",
				Action:      recon.Action{Type: "elevate"},
			},
			Event: recon.Event{Target: "elevate-me.com"},
		},
	}

	blockedHosts := make(map[string]bool)
	for _, match := range matches {
		for i := range insights {
			if insights[i].Host == match.Event.Target {
				switch match.Rule.Action.Type {
				case "tag":
					insights[i].Tags = append(insights[i].Tags, match.Rule.Action.Tag)
					insights[i].Reasons = append(insights[i].Reasons, match.Rule.Description)
					insights[i].Score += 10
				case "block":
					blockedHosts[insights[i].Host] = true
				case "elevate":
					insights[i].Priority = "critical"
					insights[i].Score = 100
					insights[i].Reasons = append(insights[i].Reasons, "Elevated: "+match.Rule.Description)
				}
			}
		}
	}

	if len(blockedHosts) > 0 {
		var filtered []analyze.Insight
		for _, in := range insights {
			if !blockedHosts[in.Host] {
				filtered = append(filtered, in)
			}
		}
		insights = filtered
	}

	if len(insights) != 2 {
		t.Fatalf("expected 2 insights after block, got %d", len(insights))
	}

	for _, in := range insights {
		if in.Host == "block-me.com" {
			t.Fatalf("expected block-me.com to be removed")
		}
		if in.Host == "elevate-me.com" {
			if in.Priority != "critical" || in.Score != 100 {
				t.Fatalf("expected elevate-me.com to be critical with score 100, got %s and %d", in.Priority, in.Score)
			}
		}
	}
}
