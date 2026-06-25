package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func TestCleanJSON(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"```json\n{\n  \"confidence\": 80\n}\n```", "{\n  \"confidence\": 80\n}"},
		{"```\n{\n  \"confidence\": 80\n}\n```", "{\n  \"confidence\": 80\n}"},
		{"{\n  \"confidence\": 80\n}", "{\n  \"confidence\": 80\n}"},
	}

	for _, tc := range tests {
		got := cleanJSON(tc.input)
		if got != tc.expected {
			t.Errorf("cleanJSON(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestParseTriageJSON(t *testing.T) {
	text := `Some preamble text
{
  "confidence": 95,
  "explanation": "This is a valid SQL injection finding."
}
Some postamble text`

	result, err := parseTriageJSON(text)
	if err != nil {
		t.Fatalf("parseTriageJSON failed: %v", err)
	}

	if result.Confidence != 95 {
		t.Errorf("expected confidence 95, got %d", result.Confidence)
	}
	if result.Explanation != "This is a valid SQL injection finding." {
		t.Errorf("expected explanation, got %q", result.Explanation)
	}
}

func TestTriageFindingWithLLMLocal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"role":    "assistant",
						"content": `{"confidence": 90, "explanation": "SQL injection detected."}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	finding := &DetailedFinding{
		Title:       "SQL Injection",
		Description: "Parameter id is vulnerable",
		Target:      "http://example.com/api?id=1",
		Request:     "GET /api?id=1 HTTP/1.1",
		Response:    "HTTP/1.1 500 Internal Server Error",
	}

	result, err := TriageFindingWithLLM(context.Background(), finding, "local", "llama3", server.URL, "test-key")
	if err != nil {
		t.Fatalf("local triage failed: %v", err)
	}

	if result.Confidence != 90 {
		t.Errorf("expected 90 confidence, got %d", result.Confidence)
	}
	if result.Explanation != "SQL injection detected." {
		t.Errorf("expected explanation, got %q", result.Explanation)
	}
}

func TestTriageFindingWithLLMFallback(t *testing.T) {
	// Mock target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "test-val")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response-body-content"))
	}))
	defer targetServer.Close()

	// Mock LLM server
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"role":    "assistant",
						"content": `{"confidence": 40, "explanation": "Target is secure."}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer llmServer.Close()

	finding := &DetailedFinding{
		Title:       "Arbitrary finding",
		Description: "Checking target",
		Target:      targetServer.URL,
		Request:     "", // Empty request triggers fallback
		Response:    "", // Empty response triggers fallback
	}

	result, err := TriageFindingWithLLM(context.Background(), finding, "local", "llama3", llmServer.URL, "test-key")
	if err != nil {
		t.Fatalf("fallback triage failed: %v", err)
	}

	if result.Confidence != 40 {
		t.Errorf("expected 40 confidence, got %d", result.Confidence)
	}
	if result.Explanation != "Target is secure." {
		t.Errorf("expected explanation, got %q", result.Explanation)
	}
}

func TestDraftReportWithLLM(t *testing.T) {
	tempDir := t.TempDir()

	// Mock LLM server
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]any{
						"role":    "assistant",
						"content": "# Bug Bounty Draft Report\nThis is a mock draft report.",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer llmServer.Close()

	config := ReportConfig{
		OutputPath:       tempDir,
		DraftReport:      true,
		AITriageProvider: "local",
		AITriageModel:    "llama3",
		AITriageURL:      llmServer.URL,
		AITriageAPIKey:   "test-key",
	}

	generator := NewReportGenerator(config)

	insights := []analyze.Insight{
		{
			Host:     "api.acme-corp.io",
			Score:    85,
			Priority: "critical",
		},
	}

	err := generator.GenerateFullReport(context.Background(), insights, []recon.Event{}, nil)
	if err != nil {
		t.Fatalf("GenerateFullReport with DraftReport failed: %v", err)
	}

	draftPath := filepath.Join(tempDir, "ai_draft_report.md")
	if _, err := os.Stat(draftPath); err != nil {
		t.Fatalf("Draft report file was not created: %v", err)
	}

	data, err := os.ReadFile(draftPath)
	if err != nil {
		t.Fatalf("failed to read draft report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "BBPTS using local (llama3)") {
		t.Errorf("expected header metadata in draft, got: %s", content)
	}
	if !strings.Contains(content, "This is a mock draft report.") {
		t.Errorf("expected LLM content, got: %s", content)
	}
}
