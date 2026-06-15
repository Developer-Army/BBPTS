package cli

import (
	"path/filepath"
	"testing"
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
