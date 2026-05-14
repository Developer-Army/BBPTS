package integration

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestBurpExportIntegration tests the end-to-end Burp Suite export workflow
func TestBurpExportIntegration(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "burp-export.xml")

	hosts := []string{"example.com", "api.example.com", "admin.example.com"}

	err := ExportToBurpConfig(outputPath, hosts)
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
		"example.com",
		"api.example.com",
		"admin.example.com",
		"staging.example.com",
	}

	err := ExportToCaidoTarget(outputPath, hosts)
	if err != nil {
		t.Fatalf("Failed to export to Caido targets: %v", err)
	}

	t.Logf("Successfully exported Caido targets to %s", outputPath)
}

// TestZAPExportIntegration tests the OWASP ZAP export workflow
func TestZAPExportIntegration(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "zap-report.xml")

	findings := map[string]interface{}{
		"alerts": []interface{}{
			map[string]interface{}{
				"name":        "SQL Injection",
				"severity":    "High",
				"description": "Potential SQL injection vulnerability detected",
			},
			map[string]interface{}{
				"name":        "Cross-Site Scripting",
				"severity":    "Medium",
				"description": "Potential XSS vulnerability detected",
			},
		},
	}

	err := ExportToZAP(outputPath, findings)
	if err != nil {
		t.Fatalf("Failed to export to ZAP: %v", err)
	}

	t.Logf("Successfully exported ZAP report to %s", outputPath)
}

// TestProxyFeederRotation tests proxy rotation functionality
func TestProxyFeederRotation(t *testing.T) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"http://proxy3.example.com:8080",
	}

	feeder := NewProxyRotator(proxies)

	// Test rotation
	for i := 0; i < 9; i++ {
		proxy := feeder.GetNextProxy()
		expectedProxy := proxies[i%3]

		if proxy != expectedProxy {
			t.Fatalf("Iteration %d: expected %s, got %s", i, expectedProxy, proxy)
		}
	}

	t.Log("Proxy rotation working correctly")
}

// TestProxyFeederEmpty tests proxy feeder with empty list
func TestProxyFeederEmpty(t *testing.T) {
	feeder := NewProxyRotator([]string{})
	proxy := feeder.GetNextProxy()

	if proxy != "" {
		t.Fatalf("Expected empty string for empty proxy list, got %s", proxy)
	}
}

// TestWebhookNotifier tests webhook notification
func TestWebhookNotifier(t *testing.T) {
	notifier := NewWebhookNotifier("https://hooks.example.com/findings", "token123")

	finding := map[string]interface{}{
		"title":       "Test Finding",
		"severity":    "high",
		"target":      "example.com",
		"description": "This is a test finding",
	}

	err := notifier.NotifyFinding(finding)
	if err != nil {
		t.Fatalf("Failed to notify finding: %v", err)
	}

	t.Log("Webhook notification sent successfully")
}

// TestMultipleToolExportIntegration tests exporting for multiple tools simultaneously
func TestMultipleToolExportIntegration(t *testing.T) {
	tempDir := t.TempDir()

	hosts := []string{"example.com", "api.example.com", "admin.example.com"}

	// Export for Burp
	burpPath := filepath.Join(tempDir, "burp.json")
	if err := ExportToBurpConfig(burpPath, hosts); err != nil {
		t.Fatalf("Burp export failed: %v", err)
	}

	// Export for Caido
	caidoPath := filepath.Join(tempDir, "caido.txt")
	if err := ExportToCaidoTarget(caidoPath, hosts); err != nil {
		t.Fatalf("Caido export failed: %v", err)
	}

	// Export for ZAP
	zapPath := filepath.Join(tempDir, "zap.xml")
	findings := map[string]interface{}{
		"alerts": []interface{}{},
	}
	if err := ExportToZAP(zapPath, findings); err != nil {
		t.Fatalf("ZAP export failed: %v", err)
	}

	t.Log("Successfully exported to multiple tools")
}

// TestExportWorkflow tests a complete export workflow with timeout
func TestExportWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	hosts := []string{"example.com", "api.example.com"}

	// Simulate export workflow
	done := make(chan error, 1)

	go func() {
		err := ExportToBurpConfig(filepath.Join(tempDir, "burp.json"), hosts)
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
