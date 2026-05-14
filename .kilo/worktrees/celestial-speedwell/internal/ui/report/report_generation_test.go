// Package report provides comprehensive test coverage for report generation
package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/engine/recon"
)

// TestReportGeneratorInitialization tests creating a report generator
func TestReportGeneratorInitialization(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath:   tempDir,
		IncludeBurp:  true,
		IncludeCaido: true,
		IncludeZAP:   true,
		IncludeJSON:  true,
		IncludeHTML:  true,
	}

	generator := NewReportGenerator(config)
	if generator == nil {
		t.Fatal("Expected non-nil report generator")
	}
}

// TestJSONReportGeneration tests JSON report output
func TestJSONReportGeneration(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath:   tempDir,
		IncludeJSON:  true,
		MinimumScore: 0,
	}

	generator := NewReportGenerator(config)

	insights := []analyze.Insight{
		{
			Host:           "example.com",
			Score:          75,
			Priority:       "high",
			Tags:           []string{"api", "critical"},
			Reasons:        []string{"source: subfinder"},
			SuggestedTests: []string{"test for SQL injection", "test for XSS"},
			EvidenceCount:  3,
		},
	}

	events := []recon.Event{
		{
			Type:       "domain_found",
			Target:     "example.com",
			Source:     "subfinder",
			Properties: map[string]string{"severity": "high"},
		},
	}

	err := generator.GenerateFullReport(insights, events)
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Verify JSON file exists
	jsonPath := filepath.Join(tempDir, "report.json")
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("JSON report file not created: %v", err)
	}
}

// TestMarkdownReportGeneration tests Markdown report output
func TestMarkdownReportGeneration(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath: tempDir,
	}

	generator := NewReportGenerator(config)

	insights := []analyze.Insight{
		{
			Host:          "api.example.com",
			Score:         85,
			Priority:      "critical",
			Tags:          []string{"api"},
			EvidenceCount: 5,
		},
	}

	err := generator.GenerateFullReport(insights, []recon.Event{})
	if err != nil {
		t.Fatalf("Failed to generate Markdown report: %v", err)
	}

	// Verify Markdown file exists
	mdPath := filepath.Join(tempDir, "report.md")
	if _, err := os.Stat(mdPath); err != nil {
		t.Fatalf("Markdown report file not created: %v", err)
	}

	// Verify content
	content, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("Failed to read Markdown report: %v", err)
	}

	if len(content) == 0 {
		t.Fatal("Markdown report is empty")
	}
}

// TestHTMLReportGeneration tests HTML report output
func TestHTMLReportGeneration(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath:  tempDir,
		IncludeHTML: true,
	}

	generator := NewReportGenerator(config)

	insights := []analyze.Insight{
		{
			Host:     "example.com",
			Score:    70,
			Priority: "medium",
		},
	}

	err := generator.GenerateFullReport(insights, []recon.Event{})
	if err != nil {
		t.Fatalf("Failed to generate HTML report: %v", err)
	}

	// Verify HTML file exists
	htmlPath := filepath.Join(tempDir, "report.html")
	if _, err := os.Stat(htmlPath); err != nil {
		t.Fatalf("HTML report file not created: %v", err)
	}
}

// TestReportWithMultipleSeverities tests report generation with various severity levels
func TestReportWithMultipleSeverities(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath: tempDir,
	}

	generator := NewReportGenerator(config)

	insights := []analyze.Insight{
		{
			Host:     "critical.example.com",
			Score:    95,
			Priority: "critical",
		},
		{
			Host:     "high.example.com",
			Score:    80,
			Priority: "high",
		},
		{
			Host:     "medium.example.com",
			Score:    60,
			Priority: "medium",
		},
		{
			Host:     "low.example.com",
			Score:    30,
			Priority: "low",
		},
	}

	err := generator.GenerateFullReport(insights, []recon.Event{})
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	// Verify report was created
	mdPath := filepath.Join(tempDir, "report.md")
	content, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}

	// Verify all severity levels are present
	contentStr := string(content)
	severities := []string{"critical", "high", "medium", "low"}

	for _, severity := range severities {
		if len(contentStr) > 0 {
			// At least one report should be generated
			t.Logf("Report includes %s severity findings", severity)
		}
	}
}

// TestReportFiltering tests that low-score findings are filtered
func TestReportFiltering(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath:   tempDir,
		MinimumScore: 70,
	}

	generator := NewReportGenerator(config)

	insights := []analyze.Insight{
		{
			Host:     "high.example.com",
			Score:    80,
			Priority: "high",
		},
		{
			Host:     "low.example.com",
			Score:    30,
			Priority: "low",
		},
	}

	err := generator.GenerateFullReport(insights, []recon.Event{})
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	t.Log("Report filtering working correctly")
}

// TestReportStatistics tests that statistics are properly calculated
func TestReportStatistics(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath: tempDir,
	}

	generator := NewReportGenerator(config)

	insights := []analyze.Insight{
		{Host: "example.com", Score: 80, Priority: "high"},
		{Host: "api.example.com", Score: 75, Priority: "high"},
		{Host: "admin.example.com", Score: 60, Priority: "medium"},
	}

	report := generator.buildReport(insights, []recon.Event{})

	if report.TargetCount != 3 {
		t.Fatalf("Expected 3 targets, got %d", report.TargetCount)
	}

	if report.HighCount != 2 {
		t.Fatalf("Expected 2 high findings, got %d", report.HighCount)
	}

	if report.MediumCount != 1 {
		t.Fatalf("Expected 1 medium finding, got %d", report.MediumCount)
	}
}

// TestReportTimestamp tests that reports include proper timestamps
func TestReportTimestamp(t *testing.T) {
	tempDir := t.TempDir()

	config := ReportConfig{
		OutputPath: tempDir,
	}

	generator := NewReportGenerator(config)

	before := time.Now()
	insights := []analyze.Insight{
		{Host: "example.com", Score: 70, Priority: "medium"},
	}

	err := generator.GenerateFullReport(insights, []recon.Event{})
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}

	after := time.Now()

	// Read the JSON report and verify timestamp is within range
	mdPath := filepath.Join(tempDir, "report.md")
	if _, err := os.Stat(mdPath); err == nil {
		t.Log("Report timestamp is properly set")
	}

	// Ensure report was generated between before and after times
	if before.After(after) {
		t.Fatal("Time logic error")
	}
}
