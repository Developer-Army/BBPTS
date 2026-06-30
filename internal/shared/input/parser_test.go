package input

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParserCSVBasic(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets.csv")

	csvContent := `acme-corp.io,api.acme-corp.io,admin.acme-corp.io
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

	expected := []string{"acme-corp.io", "api.acme-corp.io", "admin.acme-corp.io", "test.io", "dev.test.io"}
	for i, exp := range expected {
		if targets[i] != exp {
			t.Fatalf("Expected '%s', got '%s'", exp, targets[i])
		}
	}
}

func TestParserNewlineFormat(t *testing.T) {
	tempDir := t.TempDir()
	txtPath := filepath.Join(tempDir, "targets.txt")

	content := `acme-corp.io
api.acme-corp.io
admin.acme-corp.io`

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

func TestParserComments(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets_comments.csv")

	csvContent := `# This is a comment
acme-corp.io,api.acme-corp.io
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

	if len(targets) != 3 {
		t.Fatalf("Expected 3 targets (excluding comments), got %d", len(targets))
	}

	for _, target := range targets {
		if strings.HasPrefix(target, "#") {
			t.Fatalf("Comments should be filtered out, got: %s", target)
		}
	}
}

func TestParserWhitespaceHandling(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets_whitespace.csv")

	csvContent := `  acme-corp.io  ,  api.acme-corp.io  
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

func TestParserNonexistentFile(t *testing.T) {
	parser := NewParser()
	_, err := parser.ParseFile("/nonexistent/path/targets.csv")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
}

func TestParserQuotedCSVFields(t *testing.T) {
	tempDir := t.TempDir()
	csvPath := filepath.Join(tempDir, "targets_quoted.csv")

	csvContent := `"acme-corp.io","api.acme-corp.io","admin.acme-corp.io"`

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
