package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOrchestratorSwaggerDiscoveryIntegration(t *testing.T) {
	// 1. Create a test HTTP server hosting a Swagger specification
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
			w.Write([]byte(swaggerServed))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)
	swaggerURL := server.URL + "/swagger.json"

	// 2. Set up mock tools
	// A directory bruteforcer (ffuf) that discovers the swagger.json spec
	mockFfuf := &MockTool{
		ToolName: "ffuf",
		Events: []Event{
			NewEvent(swaggerURL, "ffuf", "directory", nil),
		},
	}

	// Nuclei tool to assert it receives the parsed endpoints
	mockNuclei := &MockTool{
		ToolName: "nuclei",
		Events: []Event{
			NewEvent(server.URL+"/api/v1/users", "nuclei", "vulnerability", map[string]string{
				"severity": "medium", "vuln_name": "Mock Nuclei Finding",
			}),
		},
	}

	// Dalfox tool to assert it receives the parameter-rich endpoint
	mockDalfox := &MockTool{
		ToolName: "dalfox",
		Events: []Event{
			NewEvent(server.URL+"/api/v1/users?id=1", "dalfox", "vulnerability", map[string]string{
				"severity": "medium", "vuln_name": "Mock Dalfox Finding",
			}),
		},
	}

	// 3. Configure Orchestrator
	config := Config{
		ToolNames:     []string{"ffuf", "nuclei", "dalfox"},
		Threads:       2,
		TmpResultsDir: t.TempDir(),
	}
	orchestrator := NewOrchestrator(config)

	// Overwrite the orchestrator tools with our mock implementations
	orchestrator.tools = []Tool{mockFfuf, mockNuclei, mockDalfox}

	// 4. Run the pipeline stage containing these tools (Stage 4)
	ctx := context.Background()
	events, err := orchestrator.Run(ctx, []string{server.URL})
	if err != nil {
		t.Fatalf("orchestrator execution failed: %v", err)
	}

	// 5. Verify outcomes
	// A. Verify that the api_endpoint was extracted and reported
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
	_ = foundAuthScheme // Swagger spec had no auth scheme, so no discovery event for auth expected

	// B. Verify that Nuclei was executed with the parsed endpoints
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

	// C. Verify that Dalfox was executed with parameter-rich endpoints only
	if mockDalfox.CallCount == 0 {
		t.Error("expected dalfox to be executed on swagger-discovered targets")
	}
	for _, tgt := range mockDalfox.LastTargets {
		if !strings.Contains(tgt, "?") {
			t.Errorf("dalfox should only receive endpoints with query parameters, got: %s", tgt)
		}
	}

	// D. Verify that mock findings from Nuclei/Dalfox on Swagger endpoints are aggregated
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

	// E. Verify that targets generated are scoped to allowed hosts (Scope Guard testing)
	// We'll set a scope guard that blocks the server host and run it again
	scopeConfig := Config{
		ToolNames:     []string{"ffuf", "nuclei", "dalfox"},
		Threads:       2,
		TmpResultsDir: t.TempDir(),
	}
	scopedOrchestrator := NewOrchestrator(scopeConfig)
	scopedOrchestrator.tools = []Tool{mockFfuf, mockNuclei, mockDalfox}

	// Run with initial target as a completely different domain (e.g. google.com) to restrict scope
	mockFfuf.CallCount = 0
	mockNuclei.CallCount = 0
	mockDalfox.CallCount = 0
	mockNuclei.LastTargets = nil
	mockDalfox.LastTargets = nil

	_, _ = scopedOrchestrator.Run(ctx, []string{"https://google.com"})

	// Nuclei and Dalfox should NOT be called on localhost server endpoints since they are out of scope of google.com
	for _, tgt := range mockNuclei.LastTargets {
		if strings.Contains(tgt, parsedURL.Host) {
			t.Errorf("Scope Guard failure: out-of-scope target fuzzed by nuclei: %s", tgt)
		}
	}
}
