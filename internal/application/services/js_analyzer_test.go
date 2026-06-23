package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		w.Write([]byte(jsContent))
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
