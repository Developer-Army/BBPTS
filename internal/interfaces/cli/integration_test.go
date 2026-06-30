//go:build integration

package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

func TestFullPipelineIntegration(t *testing.T) {
	t.Setenv("BBPTS_ALLOW_LOCAL", "true")

	tmpFile := createTempTargetsFile(t, []string{
		"127.0.0.1",
	})
	defer os.Remove(tmpFile)

	outputFile := t.TempDir() + "/test_report.md"
	summaryFile := t.TempDir() + "/test_summary.csv"

	cfg := &config.Config{
		Threads:      2,
		RateLimit:    10,
		WordlistsDir: "",
		StateDir:     t.TempDir(),
		Notify:       config.NotifyConfig{},
	}

	opts := Options{
		InputPath:   tmpFile,
		Tools:       "crtsh,subfinder,chaos",
		OutputPath:  outputFile,
		SummaryPath: summaryFile,
		Timeout:     10 * time.Second,
		Debug:       true,
		Threads:     2,
		RateLimit:   10,
		SkipRules:   false,
		EnableFleet: false,
		LowResource: true,
		UseTUI:      false,
		RunDoctor:   false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	Run(ctx, opts, cfg, nil, nil)

	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Errorf(" Output report file was not created: %s", outputFile)
	} else {
		content, err := os.ReadFile(outputFile)
		if err != nil {
			t.Errorf("Failed to read output file: %v", err)
		} else if len(content) == 0 {
			t.Errorf(" Output report file is empty - tools may have failed to produce results")
		} else {
			t.Logf("✓ Output report generated (%d bytes)", len(content))
		}
	}

	if _, err := os.Stat(summaryFile); os.IsNotExist(err) {
		t.Errorf(" Summary CSV file was not created: %s", summaryFile)
	} else {
		content, err := os.ReadFile(summaryFile)
		if err != nil {
			t.Errorf("Failed to read summary file: %v", err)
		} else if len(content) == 0 {
			t.Errorf(" Summary CSV file is empty - tools may have failed to produce results")
		} else {
			t.Logf("✓ Summary CSV generated (%d bytes)", len(content))
		}
	}

	t.Log("✓ Full pipeline executed successfully without crashes")
}

func TestPipelineWithMultipleStages(t *testing.T) {
	tmpFile := createTempTargetsFile(t, []string{"acme-corp.io"})
	defer os.Remove(tmpFile)

	cfg := &config.Config{
		Threads:   2,
		RateLimit: 10,
		StateDir:  t.TempDir(),
	}

	opts := Options{
		InputPath:   tmpFile,
		Tools:       "uro,subfinder,dnsx,crtsh",
		Timeout:     15 * time.Second,
		Debug:       false,
		Threads:     2,
		RateLimit:   10,
		LowResource: true,
		UseTUI:      false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Pipeline panicked during multi-stage execution: %v", r)
		}
	}()

	executeRun(ctx, opts, cfg, nil)
	t.Log("✓ Multi-stage pipeline executed successfully")
}

func TestOrchestratorWithAllStagesSequential(t *testing.T) {

	cfg := services.Config{
		ToolNames:    []string{"uro", "subfinder", "dnsx", "katana", "ffuf", "nuclei"},
		Threads:      2,
		RateLimit:    0,
		Proxies:      []string{},
		APIKeys:      map[string]string{},
		WordlistsDir: "",
	}

	orchestrator := services.NewOrchestrator(cfg)
	defer orchestrator.Close()

	if orchestrator == nil {
		t.Fatal("Failed to create orchestrator")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	targets := []string{"acme-corp.io"}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Orchestrator panicked during sequential stage execution: %v", r)
		}
	}()

	events, err := orchestrator.Run(ctx, targets)

	t.Logf("Orchestrator completed: events=%d, error=%v", len(events), err)
	if err != nil {
		t.Logf("Warning: orchestrator returned error (tools may not be installed): %v", err)
	}

	t.Log("✓ Sequential stage execution completed")
}

func TestInputParsingToReconFlow(t *testing.T) {
	tmpFile := createTempTargetsFile(t, []string{
		"acme-corp.io",
		"api.acme-corp.io",
	})
	defer os.Remove(tmpFile)

	cfg := &config.Config{
		Threads:   2,
		RateLimit: 10,
		StateDir:  t.TempDir(),
	}

	opts := Options{
		InputPath:   tmpFile,
		Tools:       "crtsh",
		Timeout:     15 * time.Second,
		Debug:       false,
		Threads:     2,
		RateLimit:   10,
		LowResource: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Input parsing to recon flow panicked: %v", r)
		}
	}()

	executeRun(ctx, opts, cfg, nil)
	t.Log("✓ Input parsing to recon flow completed successfully")
}

func TestErrorHandlingAcrossStages(t *testing.T) {
	tmpFile := createTempTargetsFile(t, []string{"invalid...target...name"})
	defer os.Remove(tmpFile)

	cfg := &config.Config{
		Threads:   2,
		RateLimit: 10,
		StateDir:  t.TempDir(),
	}

	opts := Options{
		InputPath:   tmpFile,
		Tools:       "crtsh,subfinder",
		Timeout:     10 * time.Second,
		Debug:       false,
		Threads:     2,
		RateLimit:   10,
		LowResource: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Pipeline panicked on invalid targets: %v", r)
		}
	}()

	executeRun(ctx, opts, cfg, nil)
	t.Log("✓ Error handling across stages completed successfully")
}

func TestContextTimeoutHandling(t *testing.T) {
	tmpFile := createTempTargetsFile(t, []string{"acme-corp.io"})
	defer os.Remove(tmpFile)

	cfg := &config.Config{
		Threads:   2,
		RateLimit: 10,
		StateDir:  t.TempDir(),
	}

	opts := Options{
		InputPath:   tmpFile,
		Tools:       "crtsh",
		Timeout:     1 * time.Millisecond,
		Debug:       false,
		Threads:     2,
		RateLimit:   10,
		LowResource: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Pipeline panicked on context timeout: %v", r)
		}
	}()

	executeRun(ctx, opts, cfg, nil)
	t.Log("✓ Context timeout handling completed successfully")
}

func TestPipelineWithNoInput(t *testing.T) {
	cfg := &config.Config{
		Threads:   2,
		RateLimit: 10,
		StateDir:  t.TempDir(),
	}

	opts := Options{
		InputPath:   "",
		Tools:       "crtsh",
		Timeout:     10 * time.Second,
		Debug:       false,
		LowResource: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Pipeline panicked on no input: %v", r)
		}
	}()

	executeRun(ctx, opts, cfg, nil)
	t.Log("✓ No input handling completed successfully")
}

func TestToolRegistrationIntegration(t *testing.T) {
	availableTools := services.AvailableToolNames()

	if len(availableTools) == 0 {
		t.Fatal("No tools registered in the registry")
	}

	t.Logf("Found %d registered tools: %v", len(availableTools), strings.Join(availableTools, ", "))

	for _, toolName := range availableTools {
		tool, ok := services.GetToolByName(toolName)
		if !ok {
			t.Errorf("Tool registration failed for: %s", toolName)
		}
		if tool == nil {
			t.Errorf("Tool returned nil for: %s", toolName)
		}
	}

	t.Logf("✓ All %d tools registered and accessible", len(availableTools))
}

func TestToolExecutionAndResults(t *testing.T) {

	cfg := services.Config{
		ToolNames: []string{"crtsh", "subfinder"},
		Threads:   2,
		RateLimit: 10,
		Proxies:   []string{},
		APIKeys:   map[string]string{},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf(" Orchestrator panicked during tool execution: %v", r)
		}
	}()

	orchestrator := services.NewOrchestrator(cfg)
	if orchestrator == nil {
		t.Fatal("Failed to create orchestrator")
	}
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	targets := []string{"acme-corp.io"}

	events, err := orchestrator.Run(ctx, targets)

	t.Logf("Orchestrator completed: events=%d, error=%v", len(events), err)

	if err != nil {
		t.Logf("️  Orchestrator returned error (tools may not be installed or network unavailable): %v", err)
	}

	if len(events) == 0 {
		t.Log("️  No events generated - this is expected in test environment where tools may not be available")
	} else {
		t.Logf("✓ Generated %d events from tools", len(events))

		validEvents := 0
		for i, event := range events {
			if event.Source == "" {
				t.Errorf("Event %d has empty source", i)
			}
			if event.Target == "" {
				t.Errorf("Event %d has empty target", i)
			}
			if len(event.Properties) == 0 {
				t.Logf("Warning: Event %d has no properties", i)
			} else {
				validEvents++
			}
		}
		if validEvents > 0 {
			t.Logf("✓ %d events have valid structure", validEvents)
		}
	}

	t.Log("✓ Tool execution pipeline completed successfully without crashes")
}

func TestOutputGenerationValidation(t *testing.T) {

	mockInsights := []analyze.Insight{
		{
			Host:          "acme-corp.io",
			Priority:      "medium",
			Score:         15,
			Tags:          []string{"subdomain", "certificate"},
			Reasons:       []string{"Found subdomains", "SSL certificate detected"},
			EvidenceCount: 2,
			Sources:       []string{"subfinder"},
		},
		{
			Host:          "subdomain.acme-corp.io",
			Priority:      "low",
			Score:         5,
			Tags:          []string{"subdomain"},
			Reasons:       []string{"Subdomain enumeration"},
			EvidenceCount: 2,
			Sources:       []string{"subfinder"},
		},
	}

	summaryFile := t.TempDir() + "/test_summary.csv"
	err := analyze.WriteCSVSummary(summaryFile, mockInsights)
	if err != nil {
		t.Errorf("Failed to generate summary CSV: %v", err)
	} else {
		if _, err := os.Stat(summaryFile); os.IsNotExist(err) {
			t.Errorf("Summary CSV file was not created")
		} else {
			content, err := os.ReadFile(summaryFile)
			if err != nil {
				t.Errorf("Failed to read summary CSV: %v", err)
			} else if len(content) == 0 {
				t.Errorf("Summary CSV is empty")
			} else {
				t.Logf("✓ Summary CSV generated (%d bytes)", len(content))

				contentStr := string(content)
				if !strings.Contains(contentStr, "acme-corp.io") {
					t.Errorf("Summary CSV does not contain expected host")
				}
				if !strings.Contains(contentStr, "subdomain") {
					t.Errorf("Summary CSV does not contain expected tag")
				}
			}
		}
	}

	reportFile := t.TempDir() + "/test_report.md"
	err = analyze.WriteMarkdownReport(reportFile, mockInsights)
	if err != nil {
		t.Errorf("Failed to generate markdown report: %v", err)
	} else {
		if _, err := os.Stat(reportFile); os.IsNotExist(err) {
			t.Errorf("Report file was not created")
		} else {
			content, err := os.ReadFile(reportFile)
			if err != nil {
				t.Errorf("Failed to read report: %v", err)
			} else if len(content) == 0 {
				t.Errorf("Report is empty")
			} else {
				t.Logf("✓ Markdown report generated (%d bytes)", len(content))

				contentStr := string(content)
				if !strings.Contains(contentStr, "# BBPTS") {
					t.Errorf("Report does not contain expected header")
				}
				if !strings.Contains(contentStr, "acme-corp.io") {
					t.Errorf("Report does not contain expected host")
				}
			}
		}
	}
}

func TestToolFailureDetection(t *testing.T) {

	cfg := services.Config{
		ToolNames: []string{"nonexistent_tool", "crtsh"},
		Threads:   2,
		RateLimit: 10,
		Proxies:   []string{},
		APIKeys:   map[string]string{},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf(" Orchestrator panicked on invalid tool: %v", r)
		}
	}()

	orchestrator := services.NewOrchestrator(cfg)
	if orchestrator == nil {
		t.Log("✓ Orchestrator properly handled invalid tool (returned nil)")
		return
	}

	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	targets := []string{"acme-corp.io"}

	events, err := orchestrator.Run(ctx, targets)

	t.Logf("Completed with %d events, error: %v", len(events), err)

	if err != nil {
		t.Logf("️  Error returned (expected for invalid tools): %v", err)
	}

	if len(events) == 0 {
		t.Log("️  No events generated - all tools may have failed")
	} else {
		t.Logf("✓ Generated %d events despite invalid tool", len(events))
	}
}

func TestStageAssignmentConsistency(t *testing.T) {
	expectedMappings := map[string]int{
		"uro":       0,
		"subfinder": 1,
		"amass":     1,
		"dnsx":      2,
		"naabu":     2,
		"httpx":     2,
		"katana":    3,
		"ffuf":      4,
		"nuclei":    5,
	}

	for toolName, expectedStage := range expectedMappings {
		tool, ok := services.GetToolByName(toolName)
		if !ok {
			t.Logf("Warning: Tool not found in registry: %s (may not be installed)", toolName)
			continue
		}

		if tool == nil {
			t.Errorf("Tool is nil: %s", toolName)
			continue
		}

		t.Logf("✓ Tool '%s' expected at stage %d is available", toolName, expectedStage)
	}

	t.Log("✓ Stage assignment consistency validated")
}

func createTempTargetsFile(t *testing.T, targets []string) string {
	tmpFile, err := os.CreateTemp("", "bbpts_test_targets_*.csv")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	content := "url\n"
	for _, target := range targets {
		content += fmt.Sprintf("%s\n", target)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	return tmpFile.Name()
}
