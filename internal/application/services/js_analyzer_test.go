package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func TestJSAnalyzerExposedSecrets(t *testing.T) {
	jsContent := `
// Exposed secrets test JS
const awsKey = "AKIAIOSFODNN7EXAMPLE"; // AWS Key
const slackToken = "` + strings.Replace("xoxb_12345678901_123456789012_123456789012345678901234", "_", "-", -1) + `";
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsContent))
	}))
	defer server.Close()

	analyzer := &JSAnalyzer{}
	ctx := context.Background()

	events, err := analyzer.Run(ctx, []string{server.URL + "/test.js"}, 1)
	if err != nil {
		t.Fatalf("analyzer.Run failed: %v", err)
	}

	foundAWS := false
	foundSlack := false

	for _, ev := range events {
		if ev.Type == "vulnerability" {
			vulnName := ev.Properties["vuln_name"]
			if strings.Contains(strings.ToLower(vulnName), "aws_key") {
				foundAWS = true
			}
			if strings.Contains(strings.ToLower(vulnName), "slack_token") {
				foundSlack = true
			}
		}
	}

	if !foundAWS {
		t.Errorf("expected to find exposed aws_key")
	}
	if !foundSlack {
		t.Errorf("expected to find exposed slack_token")
	}
}

func TestJSAnalyzerChangeDetection(t *testing.T) {
	t.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")

	tempDir := t.TempDir()
	store, err := storage.NewStorage("sqlite", tempDir+"/test.db")
	if err != nil {
		t.Fatalf("failed to create test storage: %v", err)
	}
	defer store.Close()

	jsContentV1 := `// v1 JS
const oldEndpoint = "/api/v1/user";
`
	jsContentV2 := `// v2 JS
const oldEndpoint = "/api/v1/user";
const newEndpoint = "/api/v1/admin/secrets";
const awsKey = "AKIAIOSFODNN7EXAMPLE";
`

	var currentJS string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(currentJS))
	}))
	defer server.Close()

	analyzer := &JSAnalyzer{}
	ctx := storage.WithStorage(context.Background(), store)

	// Run 1: Store initial hash and content
	currentJS = jsContentV1
	_, err = analyzer.Run(ctx, []string{server.URL + "/test.js"}, 1)
	if err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	// Run 2: Verify change detection triggers
	currentJS = jsContentV2
	events, err := analyzer.Run(ctx, []string{server.URL + "/test.js"}, 1)
	if err != nil {
		t.Fatalf("second Run failed: %v", err)
	}

	foundChangeDetection := false
	var diffMsg string
	for _, ev := range events {
		if ev.Type == "vulnerability" && ev.Properties["vuln_name"] == "JavaScript File Changed (New Attack Surface)" {
			foundChangeDetection = true
			diffMsg = ev.Properties["evidence"]
		}
	}

	if !foundChangeDetection {
		t.Errorf("expected to find JS change detection vulnerability event")
	}

	if !strings.Contains(diffMsg, "/api/v1/admin/secrets") {
		t.Errorf("expected diff evidence to contain '/api/v1/admin/secrets', got %q", diffMsg)
	}
	if !strings.Contains(diffMsg, "AWS Access Key ID") {
		t.Errorf("expected diff evidence to contain AWS key warning, got %q", diffMsg)
	}
}
