package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

func TestOrchestratorSwaggerDiscoveryIntegration(t *testing.T) {

	swaggerServed := `{
		"swagger": "2.0",
		"basePath": "/api/v1",
		"paths": {
			"/users": {
				"get": {
					"parameters": [
						{
							"name": "id",
							"in": "query",
							"required": true,
							"type": "integer"
						}
					]
				}
			}
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(swaggerServed))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)
	swaggerURL := server.URL + "/swagger.json"

	mockFfuf := &tools.MockTool{
		ToolName: "ffuf",
		Events: []Event{
			NewEvent(swaggerURL, "ffuf", "directory", nil),
		},
	}

	mockNuclei := &tools.MockTool{
		ToolName: "nuclei",
		Events: []Event{
			NewEvent(server.URL+"/api/v1/users", "nuclei", "vulnerability", map[string]string{
				"severity": "medium", "vuln_name": "Mock Nuclei Finding",
			}),
		},
	}

	mockDalfox := &tools.MockTool{
		ToolName: "dalfox",
		Events: []Event{
			NewEvent(server.URL+"/api/v1/users?id=1", "dalfox", "vulnerability", map[string]string{
				"severity": "medium", "vuln_name": "Mock Dalfox Finding",
			}),
		},
	}

	config := Config{
		ToolNames:     []string{"ffuf", "nuclei", "dalfox"},
		Threads:       2,
		TmpResultsDir: t.TempDir(),
	}
	orchestrator := NewOrchestrator(config)

	orchestrator.tools = []Tool{mockFfuf, mockNuclei, mockDalfox}

	ctx := context.Background()
	events, err := orchestrator.Run(ctx, []string{server.URL})
	if err != nil {
		t.Fatalf("orchestrator execution failed: %v", err)
	}

	foundAPIEndpoint := false
	foundAuthScheme := false
	for _, ev := range events {
		if ev.Type == "api_endpoint" && strings.Contains(ev.Target, "/api/v1/users") {
			foundAPIEndpoint = true
			if ev.Properties["method"] != "GET" || ev.Properties["path"] != "/users" {
				t.Errorf("incorrect api_endpoint event properties: %v", ev.Properties)
			}
		}
	}
	if !foundAPIEndpoint {
		t.Error("expected api_endpoint event not found in orchestrator output")
	}
	_ = foundAuthScheme

	if mockNuclei.CallCount == 0 {
		t.Error("expected nuclei to be executed on swagger-discovered targets")
	}
	hasBase := false
	hasQuery := false
	for _, tgt := range mockNuclei.LastTargets {
		u, err := url.Parse(tgt)
		if err == nil {
			if u.Path == "/api/v1/users" {
				switch u.RawQuery {
				case "":
					hasBase = true
				case "id=1":
					hasQuery = true
				}
			}
		}
	}
	if !hasBase {
		t.Errorf("expected nuclei to scan base endpoint '/api/v1/users', got targets: %v", mockNuclei.LastTargets)
	}
	if !hasQuery {
		t.Errorf("expected nuclei to scan query-rich endpoint '/api/v1/users?id=1', got targets: %v", mockNuclei.LastTargets)
	}

	if mockDalfox.CallCount == 0 {
		t.Error("expected dalfox to be executed on swagger-discovered targets")
	}
	for _, tgt := range mockDalfox.LastTargets {
		if !strings.Contains(tgt, "?") {
			t.Errorf("dalfox should only receive endpoints with query parameters, got: %s", tgt)
		}
	}

	foundNucleiFinding := false
	foundDalfoxFinding := false
	for _, ev := range events {
		if ev.Source == "nuclei" && ev.Type == "vulnerability" {
			foundNucleiFinding = true
		}
		if ev.Source == "dalfox" && ev.Type == "vulnerability" {
			foundDalfoxFinding = true
		}
	}
	if !foundNucleiFinding {
		t.Error("nuclei vulnerability finding on swagger endpoint not aggregated")
	}
	if !foundDalfoxFinding {
		t.Error("dalfox vulnerability finding on swagger endpoint not aggregated")
	}

	scopeConfig := Config{
		ToolNames:     []string{"ffuf", "nuclei", "dalfox"},
		Threads:       2,
		TmpResultsDir: t.TempDir(),
	}
	scopedOrchestrator := NewOrchestrator(scopeConfig)
	scopedOrchestrator.tools = []Tool{mockFfuf, mockNuclei, mockDalfox}

	mockFfuf.CallCount = 0
	mockNuclei.CallCount = 0
	mockDalfox.CallCount = 0
	mockNuclei.LastTargets = nil
	mockDalfox.LastTargets = nil

	_, _ = scopedOrchestrator.Run(ctx, []string{"https://google.com"})

	for _, tgt := range mockNuclei.LastTargets {
		if strings.Contains(tgt, parsedURL.Host) {
			t.Errorf("Scope Guard failure: out-of-scope target fuzzed by nuclei: %s", tgt)
		}
	}
}
