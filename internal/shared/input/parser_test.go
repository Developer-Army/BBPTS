package input

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParserCSVBasic tests basic CSV parsing functionality.
func TestParserCSVBasic(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets.csv")

	csvContent := `example.com,api.example.com,admin.example.com
test.io,dev.test.io`

	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("Failed to write test CSV: %v", err)
	}

	parser := NewParser()
	targets, err := parser.ParseFile(csvPath)
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	expectedCount := 5
	if len(targets) != expectedCount {
		t.Fatalf("Expected %d targets, got %d", expectedCount, len(targets))
	}

	expected := []string{"example.com", "api.example.com", "admin.example.com", "test.io", "dev.test.io"}
	for i, exp := range expected {
		if targets[i] != exp {
			t.Fatalf("Expected '%s', got '%s'", exp, targets[i])
		}
	}
}

// TestParserNewlineFormat tests newline-separated targets parsing.
func TestParserNewlineFormat(t *testing.T) {
	tempDir := t.TempDir()
	txtPath := filepath.Join(tempDir, "targets.txt")

	content := `example.com
api.example.com
admin.example.com`

	if err := os.WriteFile(txtPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	parser := NewParser()
	targets, err := parser.ParseFile(txtPath)
	if err != nil {
		t.Fatalf("Failed to parse file: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("Expected 3 targets, got %d", len(targets))
	}
}

// TestParserComments tests that comments are properly ignored.
func TestParserComments(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets_comments.csv")

	csvContent := `# This is a comment
example.com,api.example.com
# Another comment
test.io`

	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("Failed to write test CSV: %v", err)
	}

	parser := NewParser()
	targets, err := parser.ParseFile(csvPath)
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Should be 3: example.com, api.example.com, test.io (comments excluded)
	if len(targets) != 3 {
		t.Fatalf("Expected 3 targets (excluding comments), got %d", len(targets))
	}

	for _, target := range targets {
		if strings.HasPrefix(target, "#") {
			t.Fatalf("Comments should be filtered out, got: %s", target)
		}
	}
}

// TestParserWhitespaceHandling tests that whitespace is properly trimmed.
func TestParserWhitespaceHandling(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets_whitespace.csv")

	csvContent := `  example.com  ,  api.example.com  
	test.io	,	dev.test.io	`

	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("Failed to write test CSV: %v", err)
	}

	parser := NewParser()
	targets, err := parser.ParseFile(csvPath)
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	for _, target := range targets {
		trimmed := strings.TrimSpace(target)
		if target != trimmed {
			t.Fatalf("Expected whitespace to be trimmed, got '%s'", target)
		}
	}
}

// TestParserEmptyFile tests handling of empty files.
func TestParserEmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "empty.csv")

	if err := os.WriteFile(csvPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}

	parser := NewParser()
	targets, err := parser.ParseFile(csvPath)
	if err != nil {
		t.Fatalf("Failed to parse empty file: %v", err)
	}

	if len(targets) != 0 {
		t.Fatalf("Expected 0 targets from empty file, got %d", len(targets))
	}
}

// TestParserNonexistentFile tests handling of missing files.
func TestParserNonexistentFile(t *testing.T) {
	parser := NewParser()
	_, err := parser.ParseFile("/nonexistent/path/targets.csv")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
}

// TestParserQuotedCSVFields tests CSV parsing with quoted fields.
func TestParserQuotedCSVFields(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets_quoted.csv")

	csvContent := `"example.com","api.example.com","admin.example.com"`

	if err := os.WriteFile(csvPath, []byte(csvContent), 0644); err != nil {
		t.Fatalf("Failed to write test CSV: %v", err)
	}

	parser := NewParser()
	targets, err := parser.ParseFile(csvPath)
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("Expected 3 targets, got %d", len(targets))
	}
}
