package cli

import "testing"

func TestDefaultReportPaths_FromCSVInput(t *testing.T) {
	out, summary := defaultReportPaths("targets.example.csv")
	if out != "results/targets.example_report.md" {
		t.Fatalf("unexpected output path: %s", out)
	}
	if summary != "results/targets.example_summary.csv" {
		t.Fatalf("unexpected summary path: %s", summary)
	}
}

func TestDefaultReportPaths_EmptyNameFallback(t *testing.T) {
	out, summary := defaultReportPaths("")
	if out != "results/scan_report.md" {
		t.Fatalf("unexpected output path: %s", out)
	}
	if summary != "results/scan_summary.csv" {
		t.Fatalf("unexpected summary path: %s", summary)
	}
}

func TestExtractSeedDomainsRejectsSingleLabelJunk(t *testing.T) {
	got := extractSeedDomains([]string{"deposit", "https://app.example.com/path", "127.0.0.1"})
	if len(got) != 2 {
		t.Fatalf("expected 2 valid seed domains, got %v", got)
	}
	if got[0] != "app.example.com" || got[1] != "127.0.0.1" {
		t.Fatalf("unexpected seed domains: %v", got)
	}
}
