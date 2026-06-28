package services

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

// TestBurpExportIntegration tests the end-to-end Burp Suite export workflow
func TestBurpExportIntegration(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "burp-export.xml")

	hosts := []string{"acme-corp.io", "api.acme-corp.io", "admin.acme-corp.io"}

	err := tools.ExportToBurpXML(outputPath, hosts)
	if err != nil {
		t.Fatalf("Failed to export to Burp config: %v", err)
	}

	t.Logf("Successfully exported Burp config to %s", outputPath)
}

// TestCaidoExportIntegration tests the end-to-end Caido export workflow
func TestCaidoExportIntegration(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "caido-targets.txt")

	hosts := []string{
		"acme-corp.io",
		"api.acme-corp.io",
		"admin.acme-corp.io",
		"staging.acme-corp.io",
	}

	err := tools.ExportToCaidoTarget(outputPath, hosts)
	if err != nil {
		t.Fatalf("Failed to export to Caido targets: %v", err)
	}

	t.Logf("Successfully exported Caido targets to %s", outputPath)
}

// TestMultipleToolExportIntegration tests exporting for multiple tools simultaneously
func TestMultipleToolExportIntegration(t *testing.T) {
	tempDir := t.TempDir()

	hosts := []string{"acme-corp.io", "api.acme-corp.io", "admin.acme-corp.io"}

	// Export for Burp
	burpPath := filepath.Join(tempDir, "burp.json")
	if err := tools.ExportToBurpXML(burpPath, hosts); err != nil {
		t.Fatalf("Burp export failed: %v", err)
	}

	// Export for Caido
	caidoPath := filepath.Join(tempDir, "caido.txt")
	if err := tools.ExportToCaidoTarget(caidoPath, hosts); err != nil {
		t.Fatalf("Caido export failed: %v", err)
	}

	t.Log("Successfully exported to multiple tools")
}

// TestExportWorkflow tests a complete export workflow with timeout
func TestExportWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	hosts := []string{"acme-corp.io", "api.acme-corp.io"}

	// Simulate export workflow
	done := make(chan error, 1)

	go func() {
		err := tools.ExportToBurpXML(filepath.Join(tempDir, "burp.xml"), hosts)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Export workflow failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Export workflow timeout")
	}

	t.Log("Export workflow completed successfully")
}
