package analyze

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReporting(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bbpts_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	insights := []Insight{
		{
			Host:           "example.com",
			Score:          50,
			Priority:       "high",
			Tags:           []string{"api", "auth"},
			Reasons:        []string{"API surface detected", "admin/auth endpoint observed"},
			SuggestedTests: []string{"Review API auth", "Access control review"},
		},
		{
			Host:     "test.example.com",
			Score:    20,
			Priority: "medium",
			Tags:     []string{"subdomain"},
			Reasons:  []string{"new subdomain discovered"},
		},
	}

	// Test Markdown Report
	mdPath := filepath.Join(tempDir, "report.md")
	if err := WriteMarkdownReport(mdPath, insights); err != nil {
		t.Errorf("WriteMarkdownReport failed: %v", err)
	}
	if _, err := os.Stat(mdPath); os.IsNotExist(err) {
		t.Errorf("Markdown report not created")
	}

	// Test CSV Summary
	csvPath := filepath.Join(tempDir, "summary.csv")
	if err := WriteCSVSummary(csvPath, insights); err != nil {
		t.Errorf("WriteCSVSummary failed: %v", err)
	}
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		t.Errorf("CSV summary not created")
	}

	// Test Obsidian Export
	obsDir := filepath.Join(tempDir, "obsidian")
	if err := ExportToObsidian(obsDir, insights); err != nil {
		t.Errorf("ExportToObsidian failed: %v", err)
	}
	// Only example.com should have a note because of priority/score
	notePath := filepath.Join(obsDir, "example.com.md")
	if _, err := os.Stat(notePath); os.IsNotExist(err) {
		t.Errorf("Obsidian note for example.com not created")
	}

	lowPriorityNotePath := filepath.Join(obsDir, "test.example.com.md")
	if _, err := os.Stat(lowPriorityNotePath); err == nil {
		t.Errorf("Obsidian note for low priority host should not have been created")
	}
}
