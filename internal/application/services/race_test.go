package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRaceTool(t *testing.T) {
	// A mock server that simulates a vulnerable endpoint where multiple concurrent requests succeed (returning 200 OK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"applied"}`))
	}))
	defer server.Close()

	tool := &RaceTool{}
	if tool.Name() != "race" {
		t.Errorf("expected tool name race, got %s", tool.Name())
	}

	// Target URL must match state-changing keywords (e.g. "apply") to trigger the test
	targetURL := server.URL + "/api/v1/coupon/apply"

	events, err := tool.Run(context.Background(), []string{targetURL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundRace := false
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		if name == "Race Condition Vulnerability" {
			foundRace = true
		}
	}

	if !foundRace {
		t.Error("expected to detect Race Condition Vulnerability")
	}
}
